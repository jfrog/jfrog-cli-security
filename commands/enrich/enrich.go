package enrich

import (
	"encoding/xml"
	"errors"
	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/enrichgraph"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils"
	xrutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/artifactory/services/fspatterns"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"os/exec"
)

type FileContext func(string) parallel.TaskFunc
type indexFileHandlerFunc func(file string)

type ScanInfo struct {
	Target string
	Result *services.ScanResponse
}

const (
	BypassArchiveLimitsMinXrayVersion = "3.59.0"
	indexingCommand                   = "graph"
	fileNotSupportedExitCode          = 3
)

type EnrichCommand struct {
	serverDetails *config.ServerDetails
	spec          *spec.SpecFiles
	threads       int
	fail          bool
	// The location of the downloaded Xray indexer binary on the local file system.
	progress ioUtils.ProgressMgr
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

func (enrichCmd *EnrichCommand) SetFail(fail bool) *EnrichCommand {
	enrichCmd.fail = fail
	return enrichCmd
}

func isXML(scaResults []utils.ScaScanResult) (bool, error) {
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
					err = errors.New("Scan command failed. " + err.Error())
				}
			}
		}
	}()
	_, xrayVersion, err := xrutils.CreateXrayServiceManagerAndGetVersion(enrichCmd.serverDetails)
	if err != nil {
		return err
	}

	// Validate Xray minimum version for graph scan command
	err = clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, scangraph.GraphScanMinXrayVersion)
	if err != nil {
		return err
	}

	log.Info("JFrog Xray version is:", xrayVersion)

	threads := 1
	if enrichCmd.threads > 1 {
		threads = enrichCmd.threads
	}

	// resultsArr is a two-dimensional array. Each array in it contains a list of ScanResponses that were requested and collected by a specific thread.
	resultsArr := make([][]*ScanInfo, threads)
	fileProducerConsumer := parallel.NewRunner(enrichCmd.threads, 20000, false)
	fileProducerErrors := make([][]formats.SimpleJsonError, threads)
	indexedFileProducerConsumer := parallel.NewRunner(enrichCmd.threads, 20000, false)
	indexedFileProducerErrors := make([][]formats.SimpleJsonError, threads)
	fileCollectingErrorsQueue := clientutils.NewErrorsQueue(1)
	// Start walking on the filesystem to "produce" files that match the given pattern
	// while the consumer uses the indexer to index those files.
	enrichCmd.prepareScanTasks(fileProducerConsumer, indexedFileProducerConsumer, resultsArr, indexedFileProducerErrors, fileCollectingErrorsQueue, xrayVersion)
	enrichCmd.performScanTasks(fileProducerConsumer, indexedFileProducerConsumer)

	// Handle results
	flatResults := []xrutils.ScaScanResult{}
	for _, arr := range resultsArr {
		for _, res := range arr {
			flatResults = append(flatResults, xrutils.ScaScanResult{Target: res.Target, XrayResults: []services.ScanResponse{*res.Result}})
		}
	}
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

	scanResults := xrutils.NewAuditResults()
	scanResults.XrayVersion = xrayVersion
	scanResults.ScaResults = flatResults

	isxml, err := isXML(scanResults.ScaResults)
	if err != nil {
		return
	}
	if isxml {
		if err = xrutils.NewResultsWriter(scanResults).
			AppendVulnsToXML(); err != nil {
			return
		}
	} else {
		if err = xrutils.NewResultsWriter(scanResults).
			AppendVulnsToJson(); err != nil {
			return
		}
	}

	if err != nil {
		return err
	}

	if err = utils.RecordSecurityCommandOutput(utils.ScanCommandSummaryResult{Results: scanResults.GetSummary(), Section: utils.Binary}); err != nil {
		return err
	}

	// If includeVulnerabilities is false it means that context was provided, so we need to check for build violations.
	// If user provided --fail=false, don't fail the build.
	if enrichCmd.fail {
		if xrutils.CheckIfFailBuild(scanResults.GetScaScansXrayResults()) {
			return xrutils.NewFailBuildError()
		}
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

func (enrichCmd *EnrichCommand) prepareScanTasks(fileProducer, indexedFileProducer parallel.Runner, resultsArr [][]*ScanInfo, indexedFileErrors [][]formats.SimpleJsonError, fileCollectingErrorsQueue *clientutils.ErrorsQueue, xrayVersion string) {
	go func() {
		defer fileProducer.Done()
		// Iterate over file-spec groups and produce indexing tasks.
		// When encountering an error, log and move to next group.
		specFiles := enrichCmd.spec.Files
		artifactHandlerFunc := enrichCmd.createIndexerHandlerFunc(indexedFileProducer, resultsArr, indexedFileErrors, xrayVersion)
		taskHandler := getAddTaskToProducerFunc(fileProducer, artifactHandlerFunc)

		err := FileForIndexing(specFiles[0], taskHandler)
		if err != nil {
			log.Error(err)
			fileCollectingErrorsQueue.AddError(err)
		}
	}()
}

func (enrichCmd *EnrichCommand) createIndexerHandlerFunc(indexedFileProducer parallel.Runner, resultsArr [][]*ScanInfo, indexedFileErrors [][]formats.SimpleJsonError, xrayVersion string) FileContext {
	return func(filePath string) parallel.TaskFunc {
		return func(threadId int) (err error) {
			// Add a new task to the second producer/consumer
			// which will send the indexed binary to Xray and then will store the received result.
			taskFunc := func(threadId int) (err error) {
				fileContent, err := os.ReadFile(filePath)
				if err != nil {
					return err
				}
				params := &services.XrayGraphImportParams{
					SBOMInput: fileContent,
					ScanType:  services.Binary,
				}
				if enrichCmd.progress != nil {
					enrichCmd.progress.SetHeadlineMsg("Scanning 🔍")
				}
				importGraphParams := enrichgraph.NewEnrichGraphParams().
					SetServerDetails(enrichCmd.serverDetails).
					SetXrayGraphScanParams(params).
					SetXrayVersion(xrayVersion)
				xrayManager, err := utils.CreateXrayServiceManager(importGraphParams.ServerDetails())
				if err != nil {
					return err
				}
				scanResults, err := enrichgraph.RunImportGraphAndGetResults(importGraphParams, xrayManager)
				if err != nil {
					indexedFileErrors[threadId] = append(indexedFileErrors[threadId], formats.SimpleJsonError{FilePath: filePath, ErrorMessage: err.Error()})
					return
				}
				resultsArr[threadId] = append(resultsArr[threadId], &ScanInfo{Target: filePath, Result: scanResults})
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

func FileForIndexing(fileData spec.File, dataHandlerFunc indexFileHandlerFunc) error {
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