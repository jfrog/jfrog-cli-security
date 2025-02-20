package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/jas/maliciouscode"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/runner"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"golang.org/x/sync/errgroup"

	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/artifactory/services/fspatterns"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayClient "github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type FileContext func(string) parallel.TaskFunc
type indexFileHandlerFunc func(file string)

const (
	BypassArchiveLimitsMinXrayVersion = "3.59.0"
	indexingCommand                   = "graph"
	fileNotSupportedExitCode          = 3
)

type ScanCommand struct {
	serverDetails *config.ServerDetails
	spec          *spec.SpecFiles
	threads       int
	// The location of the downloaded Xray indexer binary on the local file system.
	indexerPath         string
	indexerTempDir      string
	outputFormat        format.OutputFormat
	minSeverityFilter   severityutils.Severity
	fail                bool
	printExtendedTable  bool
	validateSecrets     bool
	bypassArchiveLimits bool
	fixableOnly         bool
	progress            ioUtils.ProgressMgr
	// JAS is only supported for Docker images.
	commandSupportsJAS bool
	targetNameOverride string

	resultsContext results.ResultContext

	xrayVersion string
	xscVersion  string
	multiScanId string
	startTime   time.Time
}

func (scanCmd *ScanCommand) SetMinSeverityFilter(minSeverityFilter severityutils.Severity) *ScanCommand {
	scanCmd.minSeverityFilter = minSeverityFilter
	return scanCmd
}

func (scanCmd *ScanCommand) SetSecretValidation(validateSecrets bool) *ScanCommand {
	scanCmd.validateSecrets = validateSecrets
	return scanCmd
}

func (scanCmd *ScanCommand) SetFixableOnly(fixable bool) *ScanCommand {
	scanCmd.fixableOnly = fixable
	return scanCmd
}

func (scanCmd *ScanCommand) SetRunJasScans(run bool) *ScanCommand {
	scanCmd.commandSupportsJAS = run
	return scanCmd
}

func (scanCmd *ScanCommand) SetTargetNameOverride(targetName string) *ScanCommand {
	scanCmd.targetNameOverride = targetName
	return scanCmd
}

func (scanCmd *ScanCommand) SetProgress(progress ioUtils.ProgressMgr) {
	scanCmd.progress = progress
}

func (scanCmd *ScanCommand) SetThreads(threads int) *ScanCommand {
	scanCmd.threads = threads
	return scanCmd
}

func (scanCmd *ScanCommand) SetOutputFormat(format format.OutputFormat) *ScanCommand {
	scanCmd.outputFormat = format
	return scanCmd
}

func (scanCmd *ScanCommand) SetServerDetails(server *config.ServerDetails) *ScanCommand {
	scanCmd.serverDetails = server
	return scanCmd
}

func (scanCmd *ScanCommand) SetSpec(spec *spec.SpecFiles) *ScanCommand {
	scanCmd.spec = spec
	return scanCmd
}

func (scanCmd *ScanCommand) SetProject(project string) *ScanCommand {
	scanCmd.resultsContext.ProjectKey = project
	return scanCmd
}

func (scanCmd *ScanCommand) SetWatches(watches []string) *ScanCommand {
	scanCmd.resultsContext.Watches = watches
	return scanCmd
}

func (scanCmd *ScanCommand) SetBaseRepoPath(artifactoryRepoPath string) *ScanCommand {
	scanCmd.resultsContext.RepoPath = artifactoryRepoPath
	return scanCmd
}

func (scanCmd *ScanCommand) SetIncludeVulnerabilities(include bool) *ScanCommand {
	scanCmd.resultsContext.IncludeVulnerabilities = include
	return scanCmd
}

func (scanCmd *ScanCommand) SetIncludeLicenses(include bool) *ScanCommand {
	scanCmd.resultsContext.IncludeLicenses = include
	return scanCmd
}

func (scanCmd *ScanCommand) ServerDetails() (*config.ServerDetails, error) {
	return scanCmd.serverDetails, nil
}

func (scanCmd *ScanCommand) SetFail(fail bool) *ScanCommand {
	scanCmd.fail = fail
	return scanCmd
}

func (scanCmd *ScanCommand) SetPrintExtendedTable(printExtendedTable bool) *ScanCommand {
	scanCmd.printExtendedTable = printExtendedTable
	return scanCmd
}

func (scanCmd *ScanCommand) SetBypassArchiveLimits(bypassArchiveLimits bool) *ScanCommand {
	scanCmd.bypassArchiveLimits = bypassArchiveLimits
	return scanCmd
}

func (scanCmd *ScanCommand) SetXrayVersion(xrayVersion string) *ScanCommand {
	scanCmd.xrayVersion = xrayVersion
	return scanCmd
}

func (scanCmd *ScanCommand) SetXscVersion(xscVersion string) *ScanCommand {
	scanCmd.xscVersion = xscVersion
	return scanCmd
}

func (scanCmd *ScanCommand) indexFile(filePath string) (*xrayUtils.BinaryGraphNode, error) {
	var indexerResults xrayUtils.BinaryGraphNode
	indexerCmd := exec.Command(scanCmd.indexerPath, indexingCommand, filePath, "--temp-dir", scanCmd.indexerTempDir)
	if scanCmd.bypassArchiveLimits {
		indexerCmd.Args = append(indexerCmd.Args, "--bypass-archive-limits")
	}
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	indexerCmd.Stdout = &stdout
	indexerCmd.Stderr = &stderr
	err := indexerCmd.Run()
	if err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			if e.ExitCode() == fileNotSupportedExitCode {
				log.Debug(fmt.Sprintf("File %s is not supported by Xray indexer app.", filePath))
				return &indexerResults, nil
			}
		}
		return nil, errorutils.CheckErrorf("Xray indexer app failed indexing %s with %s: %s", filePath, err, stderr.String())
	}
	if stderr.String() != "" {
		log.Info(stderr.String())
	}
	err = json.Unmarshal(stdout.Bytes(), &indexerResults)
	return &indexerResults, errorutils.CheckError(err)
}

func (scanCmd *ScanCommand) Run() (err error) {
	return scanCmd.RunAndRecordResults(utils.Binary, scanCmd.recordResults)
}

func (scanCmd *ScanCommand) recordResults(scanResults *results.SecurityCommandResults) (err error) {
	hasViolationContext := scanCmd.resultsContext.HasViolationContext()
	if err = output.RecordSarifOutput(scanResults, scanCmd.serverDetails, scanCmd.resultsContext.IncludeVulnerabilities, hasViolationContext); err != nil {
		return
	}
	var summary output.ScanCommandResultSummary
	if summary, err = output.NewBinaryScanSummary(scanResults, scanCmd.serverDetails, scanCmd.resultsContext.IncludeVulnerabilities, hasViolationContext); err != nil {
		return
	}
	return output.RecordSecurityCommandSummary(summary)
}

func (scanCmd *ScanCommand) RunAndRecordResults(cmdType utils.CommandType, recordResFunc func(scanResults *results.SecurityCommandResults) error) (err error) {
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

	cmdResults := scanCmd.RunScan(cmdType)

	if scanCmd.progress != nil {
		if err = scanCmd.progress.Quit(); err != nil {
			return errors.Join(err, cmdResults.GetErrors())
		}
	}

	if err = output.NewResultsWriter(cmdResults).
		SetOutputFormat(scanCmd.outputFormat).
		SetPlatformUrl(scanCmd.serverDetails.Url).
		SetPrintExtendedTable(scanCmd.printExtendedTable).
		SetIsMultipleRootProject(cmdResults.HasMultipleTargets()).
		PrintScanResults(); err != nil {
		return errors.Join(err, cmdResults.GetErrors())
	}

	if err = recordResFunc(cmdResults); err != nil {
		cmdResults.AddGeneralError(fmt.Errorf("failed to record results: %s", err.Error()), false)
	}
	if err = cmdResults.GetErrors(); err != nil {
		return
	}
	// If includeVulnerabilities is false it means that context was provided, so we need to check for build violations.
	// If user provided --fail=false, don't fail the build.
	if scanCmd.fail && !scanCmd.resultsContext.IncludeVulnerabilities {
		if results.CheckIfFailBuild(cmdResults.GetScaScansXrayResults()) {
			return results.NewFailBuildError()
		}
	}
	log.Info("Scan completed successfully.")
	return nil
}

func (scanCmd *ScanCommand) RunScan(cmdType utils.CommandType) (cmdResults *results.SecurityCommandResults) {
	xrayManager, cmdResults := scanCmd.initScanCmdResults(cmdType)
	if cmdResults.GetErrors() != nil {
		return
	}
	// First, Download (if needed) the analyzer manager in a background routine.
	errGroup := new(errgroup.Group)
	if cmdResults.EntitledForJas {
		errGroup.Go(func() error {
			return jas.DownloadAnalyzerManagerIfNeeded(0)
		})
	}
	// Initialize the Xray Indexer
	if indexerPath, indexerTempDir, cleanUp, err := initIndexer(xrayManager, cmdResults.XrayVersion); err != nil {
		return cmdResults.AddGeneralError(err, false)
	} else {
		scanCmd.indexerPath = indexerPath
		scanCmd.indexerTempDir = indexerTempDir
		defer cleanUp()
	}
	threads := 1
	if scanCmd.threads > 1 {
		threads = scanCmd.threads
	}
	// Wait for the Download of the AnalyzerManager to complete.
	if err := errGroup.Wait(); err != nil {
		cmdResults.AddGeneralError(errors.New("failed while trying to get Analyzer Manager: "+err.Error()), false)
	}
	fileProducerConsumer := parallel.NewRunner(threads, 20000, false)
	indexedFileProducerConsumer := parallel.NewRunner(threads, 20000, false)
	// Parallel security runner for JAS scans
	JasScanProducerConsumer := utils.NewSecurityParallelRunner(threads)

	// Start walking on the filesystem to "produce" files that match the given pattern
	// while the consumer uses the indexer to index those files.
	scanCmd.prepareScanTasks(fileProducerConsumer, indexedFileProducerConsumer, &JasScanProducerConsumer, cmdResults)
	scanCmd.performScanTasks(fileProducerConsumer, indexedFileProducerConsumer, &JasScanProducerConsumer)
	return
}

func (scanCmd *ScanCommand) initScanCmdResults(cmdType utils.CommandType) (xrayManager *xrayClient.XrayServicesManager, cmdResults *results.SecurityCommandResults) {
	cmdResults = results.NewCommandResults(cmdType)
	// Validate Xray minimum version for graph scan command
	if err := clientutils.ValidateMinimumVersion(clientutils.Xray, scanCmd.xrayVersion, scangraph.GraphScanMinXrayVersion); err != nil {
		return xrayManager, cmdResults.AddGeneralError(err, false)
	}
	if scanCmd.bypassArchiveLimits {
		// Validate Xray minimum version for BypassArchiveLimits flag for indexer
		if err := clientutils.ValidateMinimumVersion(clientutils.Xray, scanCmd.xrayVersion, BypassArchiveLimitsMinXrayVersion); err != nil {
			return xrayManager, cmdResults.AddGeneralError(err, false)
		}
	}
	xrayManager, err := xray.CreateXrayServiceManager(scanCmd.serverDetails)
	if err != nil {
		return xrayManager, cmdResults.AddGeneralError(err, false)
	}
	// Initialize general information
	cmdResults.SetXrayVersion(scanCmd.xrayVersion)
	cmdResults.SetXscVersion(scanCmd.xscVersion)
	cmdResults.SetMultiScanId(scanCmd.multiScanId)
	cmdResults.SetStartTime(scanCmd.startTime)
	cmdResults.SetResultsContext(scanCmd.resultsContext)
	// Send entitlement request
	if entitledForJas, err := isEntitledForJas(xrayManager, scanCmd.xrayVersion, scanCmd.commandSupportsJAS); err != nil {
		return xrayManager, cmdResults.AddGeneralError(err, false)
	} else {
		cmdResults.SetEntitledForJas(entitledForJas)
		if entitledForJas {
			cmdResults.SetSecretValidation(jas.CheckForSecretValidation(xrayManager, scanCmd.xrayVersion, scanCmd.validateSecrets))
		}
	}
	return
}

func isEntitledForJas(xrayManager *xrayClient.XrayServicesManager, xrayVersion string, useJas bool) (bool, error) {
	if !useJas {
		// No jas scans are needed
		return false, nil
	}
	return jas.IsEntitledForJas(xrayManager, xrayVersion)
}

func initIndexer(xrayManager *xrayClient.XrayServicesManager, xrayVersion string) (indexerPath, indexerTempDir string, cleanUp func(), err error) {
	// Download Xray Indexer if needed
	if indexerPath, err = DownloadIndexerIfNeeded(xrayManager, xrayVersion); err != nil {
		return
	}
	// Create Temp dir for Xray Indexer
	if indexerTempDir, err = fileutils.CreateTempDir(); err != nil {
		return
	}
	cleanUp = func() {
		e := fileutils.RemoveTempDir(indexerTempDir)
		if err == nil {
			err = e
		}
	}
	return
}

func NewScanCommand() *ScanCommand {
	return &ScanCommand{}
}

func (scanCmd *ScanCommand) CommandName() string {
	return "xr_scan"
}

func (scanCmd *ScanCommand) prepareScanTasks(fileProducer, indexedFileProducer parallel.Runner, jasFileProducerConsumer *utils.SecurityParallelRunner, cmdResults *results.SecurityCommandResults) {
	go func() {
		defer fileProducer.Done()
		// Iterate over file-spec groups and produce indexing tasks.
		// When encountering an error, log and move to next group.
		specFiles := scanCmd.spec.Files
		for i := range specFiles {
			artifactHandlerFunc := scanCmd.createIndexerHandlerFunc(&specFiles[i], cmdResults, indexedFileProducer, jasFileProducerConsumer)
			taskHandler := getAddTaskToProducerFunc(fileProducer, artifactHandlerFunc)
			if generalError := collectFilesForIndexing(specFiles[i], taskHandler); generalError != nil {
				log.Error(generalError)
				cmdResults.AddGeneralError(generalError, false)
			}
		}
	}()
}

func (scanCmd *ScanCommand) getBinaryTargetName(binaryPath string) string {
	if scanCmd.targetNameOverride != "" {
		return scanCmd.targetNameOverride
	}
	return filepath.Base(binaryPath)
}

func (scanCmd *ScanCommand) createIndexerHandlerFunc(file *spec.File, cmdResults *results.SecurityCommandResults, indexedFileProducer parallel.Runner, jasFileProducerConsumer *utils.SecurityParallelRunner) FileContext {
	return func(filePath string) parallel.TaskFunc {
		return func(threadId int) (err error) {
			// Create a scan target for the file.
			targetResults := cmdResults.NewScanResults(results.ScanTarget{Target: filePath, Name: scanCmd.getBinaryTargetName(filePath)})
			log.Info(clientutils.GetLogMsgPrefix(threadId, false), "Indexing file:", targetResults.Target)
			if scanCmd.progress != nil {
				scanCmd.progress.SetHeadlineMsg("Indexing file: " + targetResults.Name + " 🗄")
			}
			// Index the file and get the dependencies graph.
			graph, err := scanCmd.indexFile(targetResults.Target)
			if err != nil {
				return targetResults.AddTargetError(err, false)
			}
			// In case of empty graph returned by the indexer,
			// for instance due to unsupported file format, continue without sending a
			// graph request to Xray.
			if graph.Id == "" {
				return
			}
			// Add a new task to the second producer/consumer
			// which will send the indexed binary to Xray and then will store the received result.
			taskFunc := func(scanThreadId int) (err error) {
				scanLogPrefix := clientutils.GetLogMsgPrefix(scanThreadId, false)
				params := &services.XrayGraphScanParams{
					BinaryGraph:            graph,
					RepoPath:               getXrayRepoPathFromTarget(file.Target),
					Watches:                scanCmd.resultsContext.Watches,
					IncludeLicenses:        scanCmd.resultsContext.IncludeLicenses,
					IncludeVulnerabilities: scanCmd.resultsContext.IncludeVulnerabilities,
					ProjectKey:             scanCmd.resultsContext.ProjectKey,
					ScanType:               services.Binary,
					MultiScanId:            cmdResults.MultiScanId,
					XscVersion:             cmdResults.XscVersion,
					XrayVersion:            cmdResults.XrayVersion,
				}
				if scanCmd.progress != nil {
					scanCmd.progress.SetHeadlineMsg("Scanning 🔍")
				}
				scanGraphParams := scangraph.NewScanGraphParams().
					SetServerDetails(scanCmd.serverDetails).
					SetXrayGraphScanParams(params).
					SetFixableOnly(scanCmd.fixableOnly).
					SetSeverityLevel(scanCmd.minSeverityFilter.String())
				xrayManager, err := xray.CreateXrayServiceManager(scanGraphParams.ServerDetails())
				if err != nil {
					return targetResults.AddTargetError(fmt.Errorf("%s failed to create Xray service manager: %s", scanLogPrefix, err.Error()), false)
				}
				graphScanResults, err := scangraph.RunScanGraphAndGetResults(scanGraphParams, xrayManager)
				if err != nil {
					return targetResults.AddTargetError(fmt.Errorf("%s sca scanning '%s' failed with error: %s", scanLogPrefix, graph.Id, err.Error()), false)
				} else {
					targetResults.NewScaScanResults(sca.GetScaScansStatusCode(err, *graphScanResults), *graphScanResults)
					targetResults.Technology = techutils.Technology(graphScanResults.ScannedPackageType)
				}
				if !cmdResults.EntitledForJas {
					return
				}
				module, err := getJasModule(targetResults)
				if err != nil {
					return targetResults.AddTargetError(fmt.Errorf("%s jas scanning failed with error: %s", scanLogPrefix, err.Error()), false)
				}
				// Run Jas scans
				scanner, err := jas.CreateJasScanner(scanCmd.serverDetails,
					cmdResults.SecretValidation,
					scanCmd.minSeverityFilter,
					jas.GetAnalyzerManagerXscEnvVars(
						cmdResults.MultiScanId,
						// Passing but empty since not supported for binary scans
						scanCmd.resultsContext.GitRepoHttpsCloneUrl,
						scanCmd.resultsContext.ProjectKey,
						scanCmd.resultsContext.Watches,
						targetResults.GetTechnologies()...,
					),
				)
				if err != nil {
					return targetResults.AddTargetError(fmt.Errorf("failed to create jas scanner: %s", err.Error()), false)
				} else if scanner == nil {
					log.Debug("Jas scanner was not created, skipping advance security scans...")
					return
				}
				jasParams := runner.JasRunnerParams{
					Runner:             jasFileProducerConsumer,
					ServerDetails:      scanCmd.serverDetails,
					Scanner:            scanner,
					Module:             module,
					ScansToPerform:     utils.GetAllSupportedScans(),
					SecretsScanType:    secrets.SecretsScannerDockerScanType,
					MaliciousScanType:  maliciouscode.MaliciousScannerDockerScanType,
					DirectDependencies: directDepsListFromVulnerabilities(*graphScanResults),
					ApplicableScanType: applicability.ApplicabilityDockerScanScanType,
					ScanResults:        targetResults,
				}
				if generalError := runner.AddJasScannersTasks(jasParams); generalError != nil {
					return targetResults.AddTargetError(fmt.Errorf("%s failed to add Jas scan tasks: %s", scanLogPrefix, generalError.Error()), false)
				}
				return
			}
			_, _ = indexedFileProducer.AddTask(taskFunc)
			return
		}
	}
}

func getJasModule(targetResults *results.TargetResults) (jfrogappsconfig.Module, error) {
	jfrogAppsConfig, err := jas.CreateJFrogAppsConfig([]string{targetResults.Target})
	if err != nil {
		return jfrogappsconfig.Module{}, err
	}
	return jfrogAppsConfig.Modules[0], nil
}

func getAddTaskToProducerFunc(producer parallel.Runner, fileHandlerFunc FileContext) indexFileHandlerFunc {
	return func(filePath string) {
		taskFunc := fileHandlerFunc(filePath)
		_, _ = producer.AddTask(taskFunc)
	}
}

func (scanCmd *ScanCommand) performScanTasks(fileConsumer parallel.Runner, indexedFileConsumer parallel.Runner, jasScanProducerConsumer *utils.SecurityParallelRunner) {
	go func() {
		// Blocking until consuming is finished.
		fileConsumer.Run()
		// After all files have been indexed, The second producer notifies that no more tasks will be produced.
		indexedFileConsumer.Done()
	}()
	go func() {
		// Blocking until consuming is finished.
		indexedFileConsumer.Run()
		// Wait for all jas scans to finish
		jasScanProducerConsumer.Runner.Done()
	}()
	jasScanProducerConsumer.Runner.Run()
}

func collectFilesForIndexing(fileData spec.File, dataHandlerFunc indexFileHandlerFunc) (generalError error) {
	fileData.Pattern = clientutils.ReplaceTildeWithUserHome(fileData.Pattern)
	patternType := fileData.GetPatternType()
	rootPath, generalError := fspatterns.GetRootPath(fileData.Pattern, fileData.Target, "", patternType, false)
	if generalError != nil {
		return generalError
	}
	isDir, generalError := fileutils.IsDirExists(rootPath, false)
	if generalError != nil {
		return generalError
	}
	// If the path is a single file, index it and return
	if !isDir {
		dataHandlerFunc(rootPath)
		return nil
	}
	fileData.Pattern = clientutils.ConvertLocalPatternToRegexp(fileData.Pattern, patternType)
	return collectPatternMatchingFiles(fileData, rootPath, dataHandlerFunc)
}

func collectPatternMatchingFiles(fileData spec.File, rootPath string, dataHandlerFunc indexFileHandlerFunc) (generalError error) {
	fileParams, generalError := fileData.ToCommonParams()
	if generalError != nil {
		return generalError
	}
	excludePathPattern := fspatterns.PrepareExcludePathPattern(fileParams.Exclusions, fileParams.GetPatternType(), fileParams.IsRecursive())
	patternRegex, generalError := regexp.Compile(fileData.Pattern)
	if errorutils.CheckError(generalError) != nil {
		return generalError
	}
	recursive, generalError := fileData.IsRecursive(true)
	if generalError != nil {
		return generalError
	}

	paths, generalError := fspatterns.ListFiles(rootPath, recursive, false, false, false, excludePathPattern)
	if generalError != nil {
		return generalError
	}
	for _, path := range paths {
		matches, isDir, generalError := fspatterns.SearchPatterns(path, false, false, patternRegex)
		if generalError != nil {
			return generalError
		}
		// Because paths should contain all files and directories (walks recursively) we can ignore dirs, as only files relevance for indexing.
		if isDir {
			continue
		}
		if len(matches) > 0 {
			dataHandlerFunc(path)
		}
	}
	return nil
}

// Xray expects a path inside a repo, but does not accept a path to a file.
// Therefore, if the given target path is a path to a file,
// the path to the parent directory will be returned.
// Otherwise, the func will return the path itself.
func getXrayRepoPathFromTarget(target string) (repoPath string) {
	if strings.HasSuffix(target, "/") {
		return target
	}
	return target[:strings.LastIndex(target, "/")+1]
}

func directDepsListFromVulnerabilities(scanResult ...services.ScanResponse) *[]string {
	depsList := []string{}
	for _, result := range scanResult {
		for _, vulnerability := range result.Vulnerabilities {
			dependencies := maps.Keys(vulnerability.Components)
			for _, dependency := range dependencies {
				if !slices.Contains(depsList, dependency) {
					depsList = append(depsList, dependency)
				}
			}
		}
	}
	return &depsList
}

func ConditionalUploadDefaultScanFunc(serverDetails *config.ServerDetails, fileSpec *spec.SpecFiles, threads int, scanOutputFormat format.OutputFormat) error {
	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(serverDetails)
	if err != nil {
		return err
	}
	return NewScanCommand().SetServerDetails(serverDetails).SetXrayVersion(xrayVersion).SetXscVersion(xscVersion).SetSpec(fileSpec).SetThreads(threads).SetOutputFormat(scanOutputFormat).SetFail(true).SetPrintExtendedTable(false).Run()
}
