package enrich

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/beevik/etree"
	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/enrich/enrichgraph"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/artifactory/services/fspatterns"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type FileContext func(string) parallel.TaskFunc
type indexFileHandlerFunc func(file string)

type EnrichCommand struct {
	serverDetails *config.ServerDetails
	spec          *spec.SpecFiles
	threads       int
	progress      ioUtils.ProgressMgr
}

func (enrichCmd *EnrichCommand) SetProgress(progress ioUtils.ProgressMgr) {
	enrichCmd.progress = progress
}

func (enrichCmd *EnrichCommand) SetThreads(threads int) *EnrichCommand {
	enrichCmd.threads = threads
	return enrichCmd
}

func (enrichCmd *EnrichCommand) SetServerDetails(server *config.ServerDetails) *EnrichCommand {
	enrichCmd.serverDetails = server
	return enrichCmd
}

func (enrichCmd *EnrichCommand) SetSpec(spec *spec.SpecFiles) *EnrichCommand {
	enrichCmd.spec = spec
	return enrichCmd
}

func (enrichCmd *EnrichCommand) ServerDetails() (*config.ServerDetails, error) {
	return enrichCmd.serverDetails, nil
}

func getScaScanFileName(cmdResults *results.SecurityCommandResults) string {
	if len(cmdResults.Targets) > 0 {
		return cmdResults.Targets[0].Target
	}
	return ""
}

func AppendVulnsToJson(cmdResults *results.SecurityCommandResults) error {
	fileName := getScaScanFileName(cmdResults)
	fileContent, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return err
	}
	var data map[string]interface{}
	err = json.Unmarshal(fileContent, &data)
	if err != nil {
		fmt.Println("Error parsing XML:", err)
		return err
	}
	var vulnerabilities []map[string]string
	xrayResults := cmdResults.GetScaScansXrayResults()[0]
	for _, vuln := range xrayResults.Vulnerabilities {
		for component := range vuln.Components {
			vulnerability := map[string]string{"bom-ref": component, "id": vuln.Cves[0].Id}
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}
	data["vulnerabilities"] = vulnerabilities
	return output.PrintJson(data)
}

func AppendVulnsToXML(cmdResults *results.SecurityCommandResults) error {
	fileName := getScaScanFileName(cmdResults)
	result := etree.NewDocument()
	err := result.ReadFromFile(fileName)
	if err != nil {
		return err
	}
	destination := result.FindElements("//bom")[0]
	xrayResults := cmdResults.GetScaScansXrayResults()[0]
	vulns := destination.CreateElement("vulnerabilities")
	for _, vuln := range xrayResults.Vulnerabilities {
		for component := range vuln.Components {
			addVuln := vulns.CreateElement("vulnerability")
			addVuln.CreateAttr("bom-ref", component)
			id := addVuln.CreateElement("id")
			id.CreateText(vuln.Cves[0].Id)
		}
	}
	result.IndentTabs()
	result.Indent(2)
	stringReturn, _ := result.WriteToString()
	log.Output(stringReturn)
	return nil
}

func isXML(scaResults []*results.TargetResults) (bool, error) {
	if len(scaResults) == 0 {
		return false, errors.New("unable to retrieve file")
	}
	fileName := scaResults[0].Target
	var x interface{}
	content, err := os.ReadFile(fileName)
	if err != nil {
		return false, err
	}
	return xml.Unmarshal(content, &x) == nil, nil
}

func (enrichCmd *EnrichCommand) Run() (err error) {
	defer func() {
		if err != nil {
			var e *exec.ExitError
			if errors.As(err, &e) {
				if e.ExitCode() != coreutils.ExitCodeVulnerableBuild.Code {
					err = errors.New("Enrich command failed. " + err.Error())
				}
			}
		}
	}()
	_, xrayVersion, err := xray.CreateXrayServiceManagerAndGetVersion(enrichCmd.serverDetails)
	if err != nil {
		return err
	}

	// Validate Xray minimum version for graph scan command
	err = clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, enrichgraph.EnrichMinimumVersionXray)
	if err != nil {
		return err
	}

	log.Info("JFrog Xray version is:", xrayVersion)

	threads := 1
	if enrichCmd.threads > 1 {
		threads = enrichCmd.threads
	}

	scanResults := results.NewCommandResults(xrayVersion, false)

	fileProducerConsumer := parallel.NewRunner(enrichCmd.threads, 20000, false)
	fileProducerErrors := make([][]formats.SimpleJsonError, threads)
	indexedFileProducerConsumer := parallel.NewRunner(enrichCmd.threads, 20000, false)
	indexedFileProducerErrors := make([][]formats.SimpleJsonError, threads)
	fileCollectingErrorsQueue := clientutils.NewErrorsQueue(1)
	// Start walking on the filesystem to "produce" files that match the given pattern
	// while the consumer uses the indexer to index those files.
	enrichCmd.prepareScanTasks(fileProducerConsumer, indexedFileProducerConsumer, scanResults, indexedFileProducerErrors, fileCollectingErrorsQueue, xrayVersion)
	enrichCmd.performScanTasks(fileProducerConsumer, indexedFileProducerConsumer)

	if enrichCmd.progress != nil {
		if err = enrichCmd.progress.Quit(); err != nil {
			return err
		}

	}

	fileCollectingErr := fileCollectingErrorsQueue.GetError()
	var scanErrors []formats.SimpleJsonError
	if fileCollectingErr != nil {
		scanErrors = append(scanErrors, formats.SimpleJsonError{ErrorMessage: fileCollectingErr.Error()})
	}
	scanErrors = appendErrorSlice(scanErrors, fileProducerErrors)
	scanErrors = appendErrorSlice(scanErrors, indexedFileProducerErrors)

	scanResults.XrayVersion = xrayVersion

	isxml, err := isXML(scanResults.Targets)
	if err != nil {
		return
	}
	if isxml {
		if err = AppendVulnsToXML(scanResults); err != nil {
			return
		}
	} else {
		if err = AppendVulnsToJson(scanResults); err != nil {
			return
		}
	}

	if err != nil {
		return err
	}

	if len(scanErrors) > 0 {
		return errorutils.CheckErrorf(scanErrors[0].ErrorMessage)
	}
	log.Info("Enrich process completed successfully.")
	return nil
}

func NewEnrichCommand() *EnrichCommand {
	return &EnrichCommand{}
}

func (enrichCmd *EnrichCommand) CommandName() string {
	return "xr_enrich"
}

func (enrichCmd *EnrichCommand) prepareScanTasks(fileProducer, indexedFileProducer parallel.Runner, cmdResults *results.SecurityCommandResults, indexedFileErrors [][]formats.SimpleJsonError, fileCollectingErrorsQueue *clientutils.ErrorsQueue, xrayVersion string) {
	go func() {
		defer fileProducer.Done()
		// Iterate over file-spec groups and produce indexing tasks.
		// When encountering an error, log and move to next group.
		specFiles := enrichCmd.spec.Files
		artifactHandlerFunc := enrichCmd.createIndexerHandlerFunc(indexedFileProducer, cmdResults, indexedFileErrors, xrayVersion)
		taskHandler := getAddTaskToProducerFunc(fileProducer, artifactHandlerFunc)

		err := FileForEnriching(specFiles[0], taskHandler)
		if err != nil {
			log.Error(err)
			fileCollectingErrorsQueue.AddError(err)
		}
	}()
}

func (enrichCmd *EnrichCommand) createIndexerHandlerFunc(indexedFileProducer parallel.Runner, cmdResults *results.SecurityCommandResults, indexedFileErrors [][]formats.SimpleJsonError, xrayVersion string) FileContext {
	return func(filePath string) parallel.TaskFunc {
		return func(threadId int) (err error) {
			// Add a new task to the second producer/consumer
			// which will send the indexed binary to Xray and then will store the received result.
			taskFunc := func(threadId int) (err error) {
				// Create a scan target for the file.
				targetResults := cmdResults.NewScanResults(results.ScanTarget{Target: filePath, Name: filepath.Base(filePath)})
				log.Debug(clientutils.GetLogMsgPrefix(threadId, false)+"enrich file:", targetResults.Target)
				fileContent, err := os.ReadFile(targetResults.Target)
				if err != nil {
					targetResults.AddError(err)
					return err
				}
				params := &services.XrayGraphImportParams{
					SBOMInput: fileContent,
					ScanType:  services.Binary,
				}
				importGraphParams := enrichgraph.NewEnrichGraphParams().
					SetServerDetails(enrichCmd.serverDetails).
					SetXrayGraphScanParams(params).
					SetXrayVersion(xrayVersion)
				xrayManager, err := xray.CreateXrayServiceManager(importGraphParams.ServerDetails())
				if err != nil {
					targetResults.AddError(err)
					return err
				}
				scanResults, err := enrichgraph.RunImportGraphAndGetResults(importGraphParams, xrayManager)
				if err != nil {
					targetResults.AddError(err)
					return
				}
				targetResults.NewScaScanResults(*scanResults)
				targetResults.Technology = techutils.Technology(scanResults.ScannedPackageType)
				return
			}

			_, _ = indexedFileProducer.AddTask(taskFunc)
			return
		}
	}
}

func getAddTaskToProducerFunc(producer parallel.Runner, fileHandlerFunc FileContext) indexFileHandlerFunc {
	return func(filePath string) {
		taskFunc := fileHandlerFunc(filePath)
		_, _ = producer.AddTask(taskFunc)
	}
}

func (enrichCmd *EnrichCommand) performScanTasks(fileConsumer parallel.Runner, indexedFileConsumer parallel.Runner) {
	go func() {
		// Blocking until consuming is finished.
		fileConsumer.Run()
		// After all files have been indexed, The second producer notifies that no more tasks will be produced.
		indexedFileConsumer.Done()
	}()
	// Blocking until consuming is finished.
	indexedFileConsumer.Run()
}

func FileForEnriching(fileData spec.File, dataHandlerFunc indexFileHandlerFunc) error {
	fileData.Pattern = clientutils.ReplaceTildeWithUserHome(fileData.Pattern)
	patternType := fileData.GetPatternType()
	rootPath, err := fspatterns.GetRootPath(fileData.Pattern, fileData.Target, "", patternType, false)
	if err != nil {
		return err
	}

	isDir, err := fileutils.IsDirExists(rootPath, false)
	if err != nil {
		return err
	}

	// path should be a single file
	if !isDir {
		dataHandlerFunc(rootPath)
		return nil
	}
	return errors.New("directory instead of a single file")
}

func appendErrorSlice(scanErrors []formats.SimpleJsonError, errorsToAdd [][]formats.SimpleJsonError) []formats.SimpleJsonError {
	for _, errorSlice := range errorsToAdd {
		scanErrors = append(scanErrors, errorSlice...)
	}
	return scanErrors
}