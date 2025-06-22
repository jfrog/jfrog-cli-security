package scan

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/runner"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/indexer"
	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
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
	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
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
	outputFormat        format.OutputFormat
	minSeverityFilter   severityutils.Severity
	fail                bool
	printExtendedTable  bool
	validateSecrets     bool
	bypassArchiveLimits bool
	fixableOnly         bool
	progress            ioUtils.ProgressMgr
	targetNameOverride  string

	resultsContext results.ResultContext

	xrayVersion string
	xscVersion  string
	multiScanId string
	startTime   time.Time

	// Dynamic logic params
	bomGenerator bom.SbomGenerator
	scanStrategy scan.SbomScanStrategy
}

func (scanCmd *ScanCommand) SetBomGenerator(bomGenerator bom.SbomGenerator) *ScanCommand {
	scanCmd.bomGenerator = bomGenerator
	return scanCmd
}

func (scanCmd *ScanCommand) SetScaScanStrategy(scanStrategy scan.SbomScanStrategy) *ScanCommand {
	scanCmd.scanStrategy = scanStrategy
	return scanCmd
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

func (scanCmd *ScanCommand) SetIncludeSbom(include bool) *ScanCommand {
	scanCmd.resultsContext.IncludeSbom = include
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
	// We consider failing the build only when --fail=true. If a user had provided --fail=false, we don't fail the build even when fail-build rules are applied.
	// If violation context was provided, we need to check all existing violations for fail-build rules.
	if scanCmd.fail && scanCmd.resultsContext.HasViolationContext() {
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
	// Initialize the BOM generator
	if scanCmd.bomGenerator != nil {
		if err := scanCmd.bomGenerator.PrepareGenerator(indexer.WithXray(xrayManager, scanCmd.xrayVersion), indexer.WithBypassArchiveLimits(scanCmd.bypassArchiveLimits)); err != nil {
			return cmdResults.AddGeneralError(fmt.Errorf("failed to prepare indexer generator: %w", err), false)
		}
		defer func() {
			if err := scanCmd.bomGenerator.CleanUp(); err != nil {
				log.Error(fmt.Sprintf("Failed to clean up the BOM generator: %s", err.Error()))
			}
		}()
	}
	// TODO: Use the following code when implementing SCA scan with interface
	// Initialize the scan strategy
	// if scanCmd.scanStrategy != nil {
	// 	if err := scanCmd.scanStrategy.PrepareStrategy(scangraphstrategy.WithParams(*scanCmd.getXrayScanGraphParams(cmdResults.MultiScanId))); err != nil {
	// 		return cmdResults.AddGeneralError(fmt.Errorf("failed to prepare scan strategy: %w", err), false)
	// 	}
	// }

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
	if entitledForJas, err := isEntitledForJas(xrayManager, scanCmd.xrayVersion); err != nil {
		return xrayManager, cmdResults.AddGeneralError(err, false)
	} else {
		cmdResults.SetEntitledForJas(entitledForJas)
		if entitledForJas {
			cmdResults.SetSecretValidation(jas.CheckForSecretValidation(xrayManager, scanCmd.xrayVersion, scanCmd.validateSecrets))
		}
	}
	return
}

func isEntitledForJas(xrayManager *xrayClient.XrayServicesManager, xrayVersion string) (bool, error) {
	return jas.IsEntitledForJas(xrayManager, xrayVersion)
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

func (scanCmd *ScanCommand) getBinaryTargetResults(cmdResults *results.SecurityCommandResults, binaryPath string, threadId int) (targetResults *results.TargetResults) {
	binaryName := filepath.Base(binaryPath)
	if scanCmd.targetNameOverride != "" {
		binaryName = scanCmd.targetNameOverride
	}
	targetResults = cmdResults.NewScanResults(results.ScanTarget{Target: binaryPath, Name: binaryName})
	log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Indexing file:", targetResults.Target)
	if scanCmd.progress != nil {
		scanCmd.progress.SetHeadlineMsg("Indexing file: " + targetResults.Name + " 🗄")
	}
	return
}

func (scanCmd *ScanCommand) createIndexerHandlerFunc(file *spec.File, cmdResults *results.SecurityCommandResults, indexedFileProducer parallel.Runner, jasFileProducerConsumer *utils.SecurityParallelRunner) FileContext {
	return func(filePath string) parallel.TaskFunc {
		return func(threadId int) (err error) {
			// Create a scan target for the file.
			targetResults := scanCmd.getBinaryTargetResults(cmdResults, filePath, threadId)
			// Generate SBOM for the file.
			deprecatedGraph := scanCmd.GenerateBinaryBom(cmdResults.CmdType, targetResults)
			if len(targetResults.Errors) > 0 {
				log.Warn(fmt.Sprintf("Failed to generate SBOM for file %s: %s", targetResults.Target, targetResults.GetErrors()))
				return
			}
			if deprecatedGraph != nil {
				// Deprecated flow
				if deprecatedGraph.Id == "" {
					log.Debug(fmt.Sprintf("file not supported, skipping scans on file %s", targetResults.Target))
					return
				}
			} else if targetResults.ScaResults == nil || targetResults.ScaResults.Sbom == nil || (targetResults.ScaResults.Sbom.Components == nil || len(*targetResults.ScaResults.Sbom.Components) == 0) {
				log.Debug(fmt.Sprintf("file not supported, skipping scans on file %s", targetResults.Target))
				return
			}
			// Add a new task to the second producer/consumer
			// which will scan the indexed file. (SCA + JAS)
			taskFunc := func(scanThreadId int) (err error) {
				if scanCmd.progress != nil {
					scanCmd.progress.SetHeadlineMsg("Scanning 🔍")
				}
				// SCA scan
				targetCompId, graphScanResults, err := scanCmd.RunBinaryScaScan(file.Target, cmdResults, targetResults, deprecatedGraph, scanThreadId)
				if err != nil || !cmdResults.EntitledForJas {
					return
				}
				// Run Jas scans
				return scanCmd.RunBinaryJasScans(cmdResults.CmdType, cmdResults.MultiScanId, cmdResults.SecretValidation, targetResults, targetCompId, graphScanResults, jasFileProducerConsumer, scanThreadId)
			}
			_, _ = indexedFileProducer.AddTask(taskFunc)
			return
		}
	}
}

func (scanCmd *ScanCommand) GenerateBinaryBom(cmdType utils.CommandType, targetResults *results.TargetResults) (deprecatedGraph *xrayClientUtils.BinaryGraphNode) {
	// TODO: For Docker image, scanGraph must binary graph must contains all attributes.
	// Converting the SBOM to a binary graph is not supported for Docker images. since not all attributes are supported.
	// We can't know at this point if the target is a Docker image or not, so we can't use the SBOM as a binary graph.
	// When all attributes are supported, we can use the SBOM as a binary graph and remove the following code.
	// Replacing it with the following code: bom.GenerateSbomForTarget(scanCmd.bomGenerator, bom.SbomGeneratorParams{Target: targetResults})
	if indexerBomGenerator, ok := scanCmd.bomGenerator.(*indexer.IndexerBomGenerator); ok {
		deprecatedGraph, err := indexerBomGenerator.IndexFile(targetResults.Target)
		if err != nil {
			_ = targetResults.AddTargetError(fmt.Errorf("failed to generate SBOM for %s: %s", targetResults.Target, err.Error()), false)
		}
		if deprecatedGraph == nil || deprecatedGraph.Id == "" {
			log.Debug(fmt.Sprintf("No components found in the SBOM for target %s, skipping SCA scan.", targetResults.Target))
			return nil
		}
		sbom := indexer.CreateTargetEmptySbom(targetResults.ScanTarget)
		sbom.Components, sbom.Dependencies = results.CompTreeToSbom(deprecatedGraph)
		targetResults.SetSbom(sbom)
		return deprecatedGraph
	}
	return
}

func (scanCmd *ScanCommand) RunBinaryScaScan(fileTarget string, cmdResults *results.SecurityCommandResults, targetResults *results.TargetResults, deprecatedGraph *xrayClientUtils.BinaryGraphNode, scanThreadId int) (targetCompId string, graphScanResults *services.ScanResponse, err error) {
	// TODO: Use the following code when implementing SCA scan with interface
	// if scanGraphStrategy, ok := scanCmd.scanStrategy.(*scangraphstrategy.ScanGraphStrategy); ok {
	// 	scanGraphStrategy.ScanGraphParams.XrayGraphScanParams().RepoPath = getXrayRepoPathFromTarget(fileTarget)
	// }
	// err = scan.RunScaScan(scanCmd.scanStrategy, scan.ScaScanParams{
	// 	ScanResults:        targetResults,
	// 	ThreadId:           scanThreadId,
	// })
	// return
	scanLogPrefix := clientutils.GetLogMsgPrefix(scanThreadId, false)
	binaryTree := deprecatedGraph
	if deprecatedGraph == nil {
		binaryTrees := results.BomToFullCompTree(targetResults.ScaResults.Sbom, true)
		if len(binaryTrees) == 0 {
			log.Debug(scanLogPrefix + fmt.Sprintf("No components found in the SBOM for target %s, skipping SCA scan.", fileTarget))
			return
		}
		if len(binaryTrees) > 1 {
			log.Warn(scanLogPrefix + fmt.Sprintf("Found multiple root components in the SBOM for target %s, only the first one will be used for SCA scan.", fileTarget))
		}
		binaryTree = binaryTrees[0]
	}
	targetCompId = binaryTree.Id
	// Prepare parameters for the SCA scan
	scanGraphParams := scanCmd.getXrayScanGraphParams(cmdResults.MultiScanId)
	scanGraphParams.XrayGraphScanParams().RepoPath = getXrayRepoPathFromTarget(fileTarget)
	scanGraphParams.XrayGraphScanParams().BinaryGraph = binaryTree
	xrayManager, err := xray.CreateXrayServiceManager(scanGraphParams.ServerDetails(), xray.WithScopedProjectKey(scanCmd.resultsContext.ProjectKey))
	if err != nil {
		err = targetResults.AddTargetError(fmt.Errorf(scanLogPrefix+"failed to create Xray service manager: %s", err.Error()), false)
		return
	}
	// Run SCA scan
	graphScanResults, err = scangraph.RunScanGraphAndGetResults(scanGraphParams, xrayManager)
	if err != nil {
		err = targetResults.AddTargetError(fmt.Errorf(scanLogPrefix+"sca scanning '%s' failed with error: %s", targetCompId, err.Error()), false)
		return
	}
	targetResults.NewScaScanResults(technologies.GetScaScansStatusCode(err, *graphScanResults), *graphScanResults)
	targetResults.Technology = techutils.Technology(graphScanResults.ScannedPackageType)
	return
}

func (scanCmd *ScanCommand) getXrayScanGraphParams(msi string) *scangraph.ScanGraphParams {
	params := &services.XrayGraphScanParams{
		Watches:                scanCmd.resultsContext.Watches,
		IncludeLicenses:        scanCmd.resultsContext.IncludeLicenses,
		IncludeVulnerabilities: scanCmd.resultsContext.IncludeVulnerabilities,
		ProjectKey:             scanCmd.resultsContext.ProjectKey,
		ScanType:               services.Binary,
		MultiScanId:            msi,
		XscVersion:             scanCmd.xscVersion,
		XrayVersion:            scanCmd.xrayVersion,
	}
	return scangraph.NewScanGraphParams().
		SetServerDetails(scanCmd.serverDetails).
		SetXrayGraphScanParams(params).
		SetFixableOnly(scanCmd.fixableOnly).
		SetSeverityLevel(scanCmd.minSeverityFilter.String())
}

func (scanCmd *ScanCommand) RunBinaryJasScans(cmdType utils.CommandType, msi string, secretValidation bool, targetResults *results.TargetResults, targetCompId string, graphScanResults *services.ScanResponse, jasFileProducerConsumer *utils.SecurityParallelRunner, scanThreadId int) (err error) {
	scanLogPrefix := clientutils.GetLogMsgPrefix(scanThreadId, false)
	module, err := getJasModule(targetResults)
	if err != nil {
		return targetResults.AddTargetError(fmt.Errorf(scanLogPrefix+"jas scanning failed with error: %s", err.Error()), false)
	}
	// Prepare Jas scans
	scannerOptions := []jas.JasScannerOption{
		jas.WithEnvVars(
			secretValidation,
			jas.NotDiffScanEnvValue,
			jas.GetAnalyzerManagerXscEnvVars(
				msi,
				// Passing but empty since not supported for binary scans
				scanCmd.resultsContext.GitRepoHttpsCloneUrl,
				scanCmd.resultsContext.ProjectKey,
				scanCmd.resultsContext.Watches,
				targetResults.GetTechnologies()...,
			),
		),
		jas.WithMinSeverity(scanCmd.minSeverityFilter),
	}
	scanner, err := jas.NewJasScanner(scanCmd.serverDetails, scannerOptions...)
	if err != nil {
		return targetResults.AddTargetError(fmt.Errorf(scanLogPrefix+"failed to create jas scanner: %s", err.Error()), false)
	} else if scanner == nil {
		log.Debug("Jas scanner was not created, skipping advance security scans...")
		return
	}
	jasParams := runner.JasRunnerParams{
		Runner:         jasFileProducerConsumer,
		ServerDetails:  scanCmd.serverDetails,
		Scanner:        scanner,
		Module:         module,
		ScansToPerform: utils.GetAllSupportedScans(),
		CvesProvider: func() (directCves []string, indirectCves []string) {
			return results.ExtractCvesFromScanResponse([]services.ScanResponse{*graphScanResults}, *directDepsListFromVulnerabilities(graphScanResults))
		},
		ScanResults: targetResults,
	}
	// Determine the scan types based on the command type and target results.
	jasParams.ApplicableScanType, jasParams.SecretsScanType = getJasScanTypes(cmdType, targetResults, targetCompId, scanThreadId)
	// Run Jas scans
	if generalError := runner.AddJasScannersTasks(jasParams); generalError != nil {
		return targetResults.AddTargetError(fmt.Errorf(scanLogPrefix+"failed to add Jas scan tasks: %s", generalError.Error()), false)
	}
	return
}

func getJasScanTypes(cmdType utils.CommandType, targetResults *results.TargetResults, targetCompId string, scanThreadId int) (applicability.ApplicabilityScanType, secrets.SecretsScanType) {
	scanLogPrefix := clientutils.GetLogMsgPrefix(scanThreadId, false)
	// Default scan types for generic scans
	secretsScanType := secrets.SecretsScannerGenericScanType
	applicabilityScanType := applicability.ApplicabilityGenericScanScanType
	// If the root component is a docker container, we need to use the docker scan types.
	if isDockerBinary(cmdType, targetResults) {
		log.Debug(scanLogPrefix + "Found root component is a docker container")
		secretsScanType = secrets.SecretsScannerDockerScanType
		applicabilityScanType = applicability.ApplicabilityDockerScanScanType
	} else {
		_, _, componentType := techutils.SplitComponentIdRaw(targetCompId)
		log.Debug(scanLogPrefix+"Found root component is not a docker container, type is: ", componentType)
	}
	return applicabilityScanType, secretsScanType
}

func isDockerBinary(cmdType utils.CommandType, targetResults *results.TargetResults) bool {
	return cmdType == utils.DockerImage || targetResults.Technology == techutils.Docker || targetResults.Technology == techutils.Oci
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

func directDepsListFromVulnerabilities(scanResult ...*services.ScanResponse) *[]string {
	depsList := []string{}
	for _, result := range scanResult {
		if result == nil {
			continue
		}
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
