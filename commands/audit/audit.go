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
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"
)

type AuditCommand struct {
	watches                []string
	gitRepoHttpsCloneUrl   string
	projectKey             string
	targetRepoPath         string
	IncludeVulnerabilities bool
	IncludeLicenses        bool
	Fail                   bool
	PrintExtendedTable     bool
	Threads                int
	AuditParams
}

func NewGenericAuditCommand() *AuditCommand {
	return &AuditCommand{AuditParams: *NewAuditParams()}
}

func (auditCmd *AuditCommand) SetWatches(watches []string) *AuditCommand {
	auditCmd.watches = watches
	return auditCmd
}

func (auditCmd *AuditCommand) SetGitRepoHttpsCloneUrl(gitRepoHttpsCloneUrl string) *AuditCommand {
	auditCmd.gitRepoHttpsCloneUrl = gitRepoHttpsCloneUrl
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

func (auditCmd *AuditCommand) SetThreads(threads int) *AuditCommand {
	auditCmd.Threads = threads
	return auditCmd
}

// Create a results context based on the provided parameters. resolves conflicts between the parameters based on the retrieved platform watches.
func CreateAuditResultsContext(serverDetails *config.ServerDetails, xrayVersion string, watches []string, artifactoryRepoPath, projectKey, gitRepoHttpsCloneUrl string, includeVulnerabilities, includeLicenses bool) (context results.ResultContext) {
	context = results.ResultContext{
		RepoPath:               artifactoryRepoPath,
		Watches:                watches,
		ProjectKey:             projectKey,
		IncludeVulnerabilities: shouldIncludeVulnerabilities(includeVulnerabilities, watches, artifactoryRepoPath, projectKey, ""),
		IncludeLicenses:        includeLicenses,
	}
	if err := clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, services.MinXrayVersionGitRepoKey); err != nil {
		// Git repo key is not supported by the Xray version.
		return
	}
	if gitRepoHttpsCloneUrl == "" {
		// No git repo key was provided, no need to check anything else.
		log.Debug("Git repo key was not provided, jas violations will not be checked for this resource.")
		return
	}
	// Get the defined and active watches from the platform.
	manager, err := xsc.CreateXscService(serverDetails)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to create Xray services manager: %s", err.Error()))
		return
	}
	if context.PlatformWatches, err = manager.GetResourceWatches(xscutils.GetGitRepoUrlKey(gitRepoHttpsCloneUrl), projectKey); err != nil {
		log.Warn(fmt.Sprintf("Failed to get active defined watches: %s", err.Error()))
		return
	}
	// Set git repo key and check if it has any watches defined in the platform.
	context.GitRepoHttpsCloneUrl = gitRepoHttpsCloneUrl
	if len(context.PlatformWatches.GitRepositoryWatches) == 0 && len(watches) == 0 && projectKey == "" {
		log.Debug(fmt.Sprintf("No watches were found in the platform for the given git repo key (%s), and no watches were given by the user (using watches or project flags). Calculating vulnerabilities...", context.GitRepoHttpsCloneUrl))
		context.GitRepoHttpsCloneUrl = ""
	}
	// We calculate again this time also taking into account the final git repo key value.
	// (if there are no watches defined on the git repo and no other context was given, we should include vulnerabilities)
	context.IncludeVulnerabilities = shouldIncludeVulnerabilities(includeVulnerabilities, watches, artifactoryRepoPath, projectKey, context.GitRepoHttpsCloneUrl)
	return
}

// If the user requested to include vulnerabilities, or if the user didn't provide any watches, project key, artifactory repo path or git repo key, we should include vulnerabilities.
func shouldIncludeVulnerabilities(includeVulnerabilities bool, watches []string, artifactoryRepoPath, projectKey, gitRepoHttpsCloneUrl string) bool {
	return includeVulnerabilities || !(len(watches) > 0 || projectKey != "" || artifactoryRepoPath != "" || gitRepoHttpsCloneUrl != "")
}

func (auditCmd *AuditCommand) Run() (err error) {
	// If no workingDirs were provided by the user, we apply a recursive scan on the root repository
	isRecursiveScan := len(auditCmd.workingDirs) == 0
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(auditCmd.workingDirs)
	if err != nil {
		return
	}
	serverDetails, err := auditCmd.ServerDetails()
	if err != nil {
		return
	}

	multiScanId, startTime := xsc.SendNewScanEvent(
		auditCmd.GetXrayVersion(),
		auditCmd.GetXscVersion(),
		serverDetails,
		xsc.CreateAnalyticsEvent(xscservices.CliProduct, xscservices.CliEventType, serverDetails),
	)

	auditParams := NewAuditParams().
		SetWorkingDirs(workingDirs).
		SetMinSeverityFilter(auditCmd.minSeverityFilter).
		SetFixableOnly(auditCmd.fixableOnly).
		SetGraphBasicParams(auditCmd.AuditBasicParams).
		SetResultsContext(CreateAuditResultsContext(
			serverDetails,
			auditCmd.GetXrayVersion(),
			auditCmd.watches,
			auditCmd.targetRepoPath,
			auditCmd.projectKey,
			auditCmd.gitRepoHttpsCloneUrl,
			auditCmd.IncludeVulnerabilities,
			auditCmd.IncludeLicenses,
		)).
		SetThirdPartyApplicabilityScan(auditCmd.thirdPartyApplicabilityScan).
		SetThreads(auditCmd.Threads).
		SetScansResultsOutputDir(auditCmd.scanResultsOutputDir).SetStartTime(startTime).SetMultiScanId(multiScanId)
	auditParams.SetIsRecursiveScan(isRecursiveScan).SetExclusions(auditCmd.Exclusions())

	auditResults := RunAudit(auditParams)

	xsc.SendScanEndedWithResults(serverDetails, auditResults)

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
		SetOutputFormat(auditCmd.OutputFormat()).
		SetPrintExtendedTable(auditCmd.PrintExtendedTable).
		SetExtraMessages(messages).
		SetSubScansPerformed(auditCmd.ScansToPerform()).
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
		cmdResults.AddGeneralError(fmt.Errorf("error has occurred during JAS scan process. JAS scan is skipped for the following directories: %s\n%s", strings.Join(cmdResults.GetTargetsPaths(), ","), generalJasScanErr.Error()), auditParams.AllowPartialResults())
	}
	if auditParams.Progress() != nil {
		auditParams.Progress().SetHeadlineMsg("Scanning for issues")
	}
	// The sca scan doesn't require the analyzer manager, so it can run separately from the analyzer manager download routine.
	if generalScaScanError := buildDepTreeAndRunScaScan(auditParallelRunner, auditParams, cmdResults); generalScaScanError != nil {
		cmdResults.AddGeneralError(fmt.Errorf("error has occurred during SCA scan process. SCA scan is skipped for the following directories: %s\n%s", strings.Join(cmdResults.GetTargetsPaths(), ","), generalScaScanError.Error()), auditParams.AllowPartialResults())
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
	return jas.IsEntitledForJas(xrayManager, auditParams.GetXrayVersion())
}

func RunJasScans(auditParallelRunner *utils.SecurityParallelRunner, auditParams *AuditParams, scanResults *results.SecurityCommandResults, jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig) (jasScanner *jas.JasScanner, generalError error) {
	if !scanResults.EntitledForJas {
		log.Info("Not entitled for JAS, skipping advance security scans...")
		return
	}
	if !utils.IsJASRequested(scanResults.CmdType, auditParams.ScansToPerform()...) {
		log.Debug("JAS scans were not requested, skipping advance security scans...")
		return
	}
	serverDetails, err := auditParams.ServerDetails()
	if err != nil {
		generalError = fmt.Errorf("failed to get server details: %s", err.Error())
		return
	}
	auditParallelRunner.ResultsMu.Lock()
	jasScanner, err = jas.CreateJasScanner(
		serverDetails,
		scanResults.SecretValidation,
		auditParams.minSeverityFilter,
		jas.GetAnalyzerManagerXscEnvVars(
			auditParams.GetMultiScanId(),
			jas.GetGitRepoUrlKey(auditParams.resultsContext.GitRepoHttpsCloneUrl),
			auditParams.resultsContext.ProjectKey,
			auditParams.resultsContext.Watches,
			scanResults.GetTechnologies()...,
		),
		auditParams.Exclusions()...,
	)
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
				ScansToPerform:              auditParams.ScansToPerform(),
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
	if err = clientutils.ValidateMinimumVersion(clientutils.Xray, params.GetXrayVersion(), scangraph.GraphScanMinXrayVersion); err != nil {
		return cmdResults.AddGeneralError(err, false)
	}
	cmdResults.SetXrayVersion(params.GetXrayVersion())
	cmdResults.SetXscVersion(params.GetXscVersion())
	cmdResults.SetMultiScanId(params.GetMultiScanId())
	cmdResults.SetStartTime(params.StartTime())
	cmdResults.SetResultsContext(params.resultsContext)

	xrayManager, err := xrayutils.CreateXrayServiceManager(serverDetails)
	if err != nil {
		return cmdResults.AddGeneralError(err, false)
	}
	// Send entitlement requests
	entitledForJas, err := isEntitledForJas(xrayManager, params)
	if err != nil {
		return cmdResults.AddGeneralError(err, false)
	} else {
		cmdResults.SetEntitledForJas(entitledForJas)
	}
	if entitledForJas {
		cmdResults.SetSecretValidation(jas.CheckForSecretValidation(xrayManager, params.GetXrayVersion(), slices.Contains(params.AuditBasicParams.ScansToPerform(), utils.SecretTokenValidationScan)))
	}
	// Initialize targets
	detectScanTargets(cmdResults, params)
	if params.IsRecursiveScan() && len(params.workingDirs) == 1 && len(cmdResults.Targets) == 0 {
		// No SCA targets were detected, add the root directory as a target for JAS scans.
		cmdResults.NewScanResults(results.ScanTarget{Target: params.workingDirs[0]})
	}
	scanInfo, err := coreutils.GetJsonIndent(cmdResults.GetTargets())
	if err != nil {
		return
	}
	log.Info(fmt.Sprintf("Performing scans on %d targets:\n%s", len(cmdResults.Targets), scanInfo))
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
		// Create scans to perform
		for tech, workingDirs := range techToWorkingDirs {
			if tech == techutils.Dotnet {
				// We detect Dotnet and Nuget the same way, if one detected so does the other.
				// We don't need to scan for both and get duplicate results.
				continue
			}
			// No technology was detected, add scan without descriptors. (so no sca scan will be performed and set at target level)
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
