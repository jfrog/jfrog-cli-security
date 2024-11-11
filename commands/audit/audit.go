package audit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jfrog/gofrog/parallel"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/runner"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"golang.org/x/exp/slices"

	xrayutils "github.com/jfrog/jfrog-cli-security/utils/xray"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type AuditCommand struct {
	watches                 []string
	projectKey              string
	targetRepoPath          string
	IncludeVulnerabilities  bool
	IncludeLicenses         bool
	Fail                    bool
	PrintExtendedTable      bool
	analyticsMetricsService *xsc.AnalyticsMetricsService
	Threads                 int
	AuditParams
}

func NewGenericAuditCommand() *AuditCommand {
	return &AuditCommand{AuditParams: *NewAuditParams()}
}

func (auditCmd *AuditCommand) SetWatches(watches []string) *AuditCommand {
	auditCmd.watches = watches
	return auditCmd
}

func (auditCmd *AuditCommand) SetProject(project string) *AuditCommand {
	auditCmd.projectKey = project
	return auditCmd
}

func (auditCmd *AuditCommand) SetTargetRepoPath(repoPath string) *AuditCommand {
	auditCmd.targetRepoPath = repoPath
	return auditCmd
}

func (auditCmd *AuditCommand) SetIncludeVulnerabilities(include bool) *AuditCommand {
	auditCmd.IncludeVulnerabilities = include
	return auditCmd
}

func (auditCmd *AuditCommand) SetIncludeLicenses(include bool) *AuditCommand {
	auditCmd.IncludeLicenses = include
	return auditCmd
}

func (auditCmd *AuditCommand) SetFail(fail bool) *AuditCommand {
	auditCmd.Fail = fail
	return auditCmd
}

func (auditCmd *AuditCommand) SetPrintExtendedTable(printExtendedTable bool) *AuditCommand {
	auditCmd.PrintExtendedTable = printExtendedTable
	return auditCmd
}

func (auditCmd *AuditCommand) SetAnalyticsMetricsService(analyticsMetricsService *xsc.AnalyticsMetricsService) *AuditCommand {
	auditCmd.analyticsMetricsService = analyticsMetricsService
	return auditCmd
}

func (auditCmd *AuditCommand) SetThreads(threads int) *AuditCommand {
	auditCmd.Threads = threads
	return auditCmd
}

func (auditCmd *AuditCommand) CreateCommonGraphScanParams() *scangraph.CommonGraphScanParams {
	commonParams := &scangraph.CommonGraphScanParams{
		RepoPath: auditCmd.targetRepoPath,
		Watches:  auditCmd.watches,
		ScanType: services.Dependency,
	}
	commonParams.ProjectKey = auditCmd.projectKey
	commonParams.IncludeVulnerabilities = auditCmd.IncludeVulnerabilities
	commonParams.IncludeLicenses = auditCmd.IncludeLicenses
	commonParams.MultiScanId, commonParams.XscVersion = xsc.GetXscMsiAndVersion(auditCmd.analyticsMetricsService)
	return commonParams
}

func (auditCmd *AuditCommand) Run() (err error) {
	// If no workingDirs were provided by the user, we apply a recursive scan on the root repository
	isRecursiveScan := len(auditCmd.workingDirs) == 0
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(auditCmd.workingDirs)
	if err != nil {
		return
	}

	// Should be called before creating the audit params, so the params will contain XSC information.
	auditCmd.analyticsMetricsService.AddGeneralEvent(auditCmd.analyticsMetricsService.CreateGeneralEvent(xscservices.CliProduct, xscservices.CliEventType))
	auditParams := NewAuditParams().
		SetWorkingDirs(workingDirs).
		SetMinSeverityFilter(auditCmd.minSeverityFilter).
		SetFixableOnly(auditCmd.fixableOnly).
		SetGraphBasicParams(auditCmd.AuditBasicParams).
		SetCommonGraphScanParams(auditCmd.CreateCommonGraphScanParams()).
		SetThirdPartyApplicabilityScan(auditCmd.thirdPartyApplicabilityScan).
		SetThreads(auditCmd.Threads).
		SetScansResultsOutputDir(auditCmd.scanResultsOutputDir)
	auditParams.SetIsRecursiveScan(isRecursiveScan).SetExclusions(auditCmd.Exclusions())

	auditResults := RunAudit(auditParams)
	auditCmd.analyticsMetricsService.UpdateGeneralEvent(auditCmd.analyticsMetricsService.CreateXscAnalyticsGeneralEventFinalizeFromAuditResults(auditResults))

	if auditCmd.Progress() != nil {
		if err = auditCmd.Progress().Quit(); err != nil {
			return errors.Join(err, auditResults.GetErrors())
		}
	}
	var messages []string
	if !auditResults.EntitledForJas {
		messages = []string{coreutils.PrintTitle("The ‘jf audit’ command also supports JFrog Advanced Security features, such as 'Contextual Analysis', 'Secret Detection', 'IaC Scan' and ‘SAST’.\nThis feature isn't enabled on your system. Read more - ") + coreutils.PrintLink(utils.JasInfoURL)}
	}
	if err = output.NewResultsWriter(auditResults).
		SetHasViolationContext(auditCmd.HasViolationContext()).
		SetIncludeVulnerabilities(auditCmd.IncludeVulnerabilities).
		SetIncludeLicenses(auditCmd.IncludeLicenses).
		SetOutputFormat(auditCmd.OutputFormat()).
		SetPrintExtendedTable(auditCmd.PrintExtendedTable).
		SetExtraMessages(messages).
		SetSubScansPreformed(auditCmd.ScansToPerform()).
		PrintScanResults(); err != nil {
		return errors.Join(err, auditResults.GetErrors())
	}

	if err = auditResults.GetErrors(); err != nil {
		return
	}

	// Only in case Xray's context was given (!auditCmd.IncludeVulnerabilities), and the user asked to fail the build accordingly, do so.
	if auditCmd.Fail && !auditCmd.IncludeVulnerabilities && results.CheckIfFailBuild(auditResults.GetScaScansXrayResults()) {
		err = results.NewFailBuildError()
	}
	return
}

func (auditCmd *AuditCommand) CommandName() string {
	return "generic_audit"
}

func (auditCmd *AuditCommand) HasViolationContext() bool {
	return len(auditCmd.watches) > 0 || auditCmd.projectKey != "" || auditCmd.targetRepoPath != ""
}

// Runs an audit scan based on the provided auditParams.
// Returns an audit Results object containing all the scan results.
// If the current server is entitled for JAS, the advanced security results will be included in the scan results.
func RunAudit(auditParams *AuditParams) (cmdResults *results.SecurityCommandResults) {
	// Initialize Results struct
	if cmdResults = initAuditCmdResults(auditParams); cmdResults.GeneralError != nil {
		return
	}
	jfrogAppsConfig, err := jas.CreateJFrogAppsConfig(cmdResults.GetTargetsPaths())
	if err != nil {
		return cmdResults.AddGeneralError(fmt.Errorf("failed to create JFrogAppsConfig: %s", err.Error()), false)
	}
	// Initialize the parallel runner
	auditParallelRunner := utils.CreateSecurityParallelRunner(auditParams.threads)
	// Add the JAS scans to the parallel runner
	var jasScanner *jas.JasScanner
	var generalJasScanErr error
	if jasScanner, generalJasScanErr = RunJasScans(auditParallelRunner, auditParams, cmdResults, jfrogAppsConfig); generalJasScanErr != nil {
		cmdResults.AddGeneralError(fmt.Errorf("An error has occurred during JAS scan process. JAS scan is skipped for the following directories: %s\n%s", strings.Join(cmdResults.GetTargetsPaths(), ","), generalJasScanErr.Error()), auditParams.AllowPartialResults())
	}
	if auditParams.Progress() != nil {
		auditParams.Progress().SetHeadlineMsg("Scanning for issues")
	}
	// The sca scan doesn't require the analyzer manager, so it can run separately from the analyzer manager download routine.
	if generalScaScanError := buildDepTreeAndRunScaScan(auditParallelRunner, auditParams, cmdResults); generalScaScanError != nil {
		cmdResults.AddGeneralError(fmt.Errorf("An error has occurred during SCA scan process. SCA scan is skipped for the following directories: %s\n%s", strings.Join(cmdResults.GetTargetsPaths(), ","), generalScaScanError.Error()), auditParams.AllowPartialResults())
	}
	go func() {
		auditParallelRunner.ScaScansWg.Wait()
		auditParallelRunner.JasWg.Wait()
		// Wait for all jas scanners to complete before cleaning up scanners temp dir
		auditParallelRunner.JasScannersWg.Wait()
		if jasScanner != nil && jasScanner.ScannerDirCleanupFunc != nil {
			cmdResults.AddGeneralError(jasScanner.ScannerDirCleanupFunc(), false)
		}
		auditParallelRunner.Runner.Done()
	}()
	auditParallelRunner.Runner.Run()
	return
}

func isEntitledForJas(xrayManager *xray.XrayServicesManager, auditParams *AuditParams) (entitled bool, err error) {
	if !auditParams.UseJas() {
		// Dry run without JAS
		return false, nil
	}
	return jas.IsEntitledForJas(xrayManager, auditParams.xrayVersion)
}

func RunJasScans(auditParallelRunner *utils.SecurityParallelRunner, auditParams *AuditParams, scanResults *results.SecurityCommandResults, jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig) (jasScanner *jas.JasScanner, generalError error) {
	if !scanResults.EntitledForJas {
		log.Info("Not entitled for JAS, skipping advance security scans...")
		return
	}
	serverDetails, err := auditParams.ServerDetails()
	if err != nil {
		generalError = fmt.Errorf("failed to get server details: %s", err.Error())
		return
	}
	auditParallelRunner.ResultsMu.Lock()
	jasScanner, err = jas.CreateJasScanner(serverDetails, scanResults.SecretValidation, auditParams.minSeverityFilter, jas.GetAnalyzerManagerXscEnvVars(auditParams.commonGraphScanParams.MultiScanId, scanResults.GetTechnologies()...), auditParams.Exclusions()...)
	auditParallelRunner.ResultsMu.Unlock()
	if err != nil {
		generalError = fmt.Errorf("failed to create jas scanner: %s", err.Error())
		return
	} else if jasScanner == nil {
		log.Debug("Jas scanner was not created, skipping advance security scans...")
		return
	}
	auditParallelRunner.JasWg.Add(1)
	if _, jasErr := auditParallelRunner.Runner.AddTaskWithError(createJasScansTasks(auditParallelRunner, scanResults, serverDetails, auditParams, jasScanner, jfrogAppsConfig), func(taskErr error) {
		scanResults.AddGeneralError(fmt.Errorf("failed while adding JAS scan tasks: %s", taskErr.Error()), auditParams.AllowPartialResults())
	}); jasErr != nil {
		generalError = fmt.Errorf("failed to create JAS task: %s", jasErr.Error())
	}
	return
}

func createJasScansTasks(auditParallelRunner *utils.SecurityParallelRunner, scanResults *results.SecurityCommandResults,
	serverDetails *config.ServerDetails, auditParams *AuditParams, scanner *jas.JasScanner, jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig) parallel.TaskFunc {
	return func(threadId int) (generalError error) {
		defer func() {
			auditParallelRunner.JasWg.Done()
		}()
		logPrefix := clientutils.GetLogMsgPrefix(threadId, false)
		// First download the analyzer manager if needed
		if err := jas.DownloadAnalyzerManagerIfNeeded(threadId); err != nil {
			return fmt.Errorf("%s failed to download analyzer manager: %s", logPrefix, err.Error())
		}
		// Run JAS scanners for each scan target
		for _, targetResult := range scanResults.Targets {
			module := jas.GetModule(targetResult.Target, jfrogAppsConfig)
			if module == nil {
				_ = targetResult.AddTargetError(fmt.Errorf("can't find module for path %s", targetResult.Target), auditParams.AllowPartialResults())
				continue
			}
			params := runner.JasRunnerParams{
				Runner:                      auditParallelRunner,
				ServerDetails:               serverDetails,
				Scanner:                     scanner,
				Module:                      *module,
				ConfigProfile:               auditParams.configProfile,
				ScansToPreform:              auditParams.ScansToPerform(),
				SecretsScanType:             secrets.SecretsScannerType,
				DirectDependencies:          auditParams.DirectDependencies(),
				ThirdPartyApplicabilityScan: auditParams.thirdPartyApplicabilityScan,
				ApplicableScanType:          applicability.ApplicabilityScannerType,
				SignedDescriptions:          auditParams.OutputFormat() == format.Sarif,
				ScanResults:                 targetResult,
				TargetOutputDir:             auditParams.scanResultsOutputDir,
				AllowPartialResults:         auditParams.AllowPartialResults(),
			}
			if generalError = runner.AddJasScannersTasks(params); generalError != nil {
				_ = targetResult.AddTargetError(fmt.Errorf("%s failed to add JAS scan tasks: %s", logPrefix, generalError.Error()), auditParams.AllowPartialResults())
				// We assign nil to 'generalError' after handling it to prevent it to propagate further, so it will not be captured twice - once here, and once in the error handling function of createJasScansTasks
				generalError = nil
			}
		}
		return
	}
}

func initAuditCmdResults(params *AuditParams) (cmdResults *results.SecurityCommandResults) {
	cmdResults = results.NewCommandResults(utils.SourceCode)
	// Initialize general information
	serverDetails, err := params.ServerDetails()
	if err != nil {
		return cmdResults.AddGeneralError(err, false)
	}
	var xrayManager *xray.XrayServicesManager
	if xrayManager, params.xrayVersion, err = xrayutils.CreateXrayServiceManagerAndGetVersion(serverDetails); err != nil {
		return cmdResults.AddGeneralError(err, false)
	} else {
		cmdResults.SetXrayVersion(params.xrayVersion)
	}
	if err = clientutils.ValidateMinimumVersion(clientutils.Xray, params.xrayVersion, scangraph.GraphScanMinXrayVersion); err != nil {
		return cmdResults.AddGeneralError(err, false)
	}
	entitledForJas, err := isEntitledForJas(xrayManager, params)
	if err != nil {
		return cmdResults.AddGeneralError(err, false)
	} else {
		cmdResults.SetEntitledForJas(entitledForJas)
	}
	if entitledForJas {
		cmdResults.SetSecretValidation(jas.CheckForSecretValidation(xrayManager, params.xrayVersion, slices.Contains(params.AuditBasicParams.ScansToPerform(), utils.SecretTokenValidationScan)))
	}
	cmdResults.SetMultiScanId(params.commonGraphScanParams.MultiScanId)
	// Initialize targets
	detectScanTargets(cmdResults, params)
	if params.IsRecursiveScan() && len(params.workingDirs) == 1 && len(cmdResults.Targets) == 0 {
		// No SCA targets were detected, add the root directory as a target for JAS scans.
		cmdResults.NewScanResults(results.ScanTarget{Target: params.workingDirs[0]})
	}
	scanInfo, err := coreutils.GetJsonIndent(cmdResults)
	if err != nil {
		return
	}
	log.Info(fmt.Sprintf("Preforming scans on %d targets:\n%s", len(cmdResults.Targets), scanInfo))
	return
}

func detectScanTargets(cmdResults *results.SecurityCommandResults, params *AuditParams) {
	for _, requestedDirectory := range params.workingDirs {
		if !fileutils.IsPathExists(requestedDirectory, false) {
			log.Warn("The working directory", requestedDirectory, "doesn't exist. Skipping SCA scan...")
			continue
		}
		// Detect descriptors and technologies in the requested directory.
		techToWorkingDirs, err := techutils.DetectTechnologiesDescriptors(requestedDirectory, params.IsRecursiveScan(), params.Technologies(), getRequestedDescriptors(params), sca.GetExcludePattern(params.AuditBasicParams))
		if err != nil {
			log.Warn("Couldn't detect technologies in", requestedDirectory, "directory.", err.Error())
			continue
		}
		// Create scans to preform
		for tech, workingDirs := range techToWorkingDirs {
			if tech == techutils.Dotnet {
				// We detect Dotnet and Nuget the same way, if one detected so does the other.
				// We don't need to scan for both and get duplicate results.
				continue
			}
			// No technology was detected, add scan without descriptors. (so no sca scan will be preformed and set at target level)
			if len(workingDirs) == 0 {
				// Requested technology (from params) descriptors/indicators were not found or recursive scan with NoTech value, add scan without descriptors.
				cmdResults.NewScanResults(results.ScanTarget{Target: requestedDirectory, Technology: tech})
			}
			for workingDir, descriptors := range workingDirs {
				// Add scan for each detected working directory.
				targetResults := cmdResults.NewScanResults(results.ScanTarget{Target: workingDir, Technology: tech})
				if tech != techutils.NoTech {
					targetResults.SetDescriptors(descriptors...)
				}
			}
		}
	}
}
