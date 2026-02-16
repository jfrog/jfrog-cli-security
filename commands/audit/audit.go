package audit

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/runner"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/policy/enforcer"
	"github.com/jfrog/jfrog-cli-security/policy/local"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin"
	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-cli-security/sca/scan/enrich"
	scanGraphStrategy "github.com/jfrog/jfrog-cli-security/sca/scan/scangraph"
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
	watches                 []string
	gitRepoHttpsCloneUrl    string
	projectKey              string
	targetRepoPath          string
	IncludeVulnerabilities  bool
	IncludeLicenses         bool
	IncludeSbom             bool
	IncludeSnippetDetection bool
	Fail                    bool
	PrintExtendedTable      bool
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

func (auditCmd *AuditCommand) SetGitRepoHttpsCloneUrl(gitRepoHttpsCloneUrl string) *AuditCommand {
	auditCmd.gitRepoHttpsCloneUrl = gitRepoHttpsCloneUrl
	return auditCmd
}

func (auditCmd *AuditCommand) SetProject(project string) *AuditCommand {
	auditCmd.projectKey = project
	return auditCmd
}

func (auditCmd *AuditCommand) GetProjectKey() string {
	return auditCmd.projectKey
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

func (auditCmd *AuditCommand) SetIncludeSbom(include bool) *AuditCommand {
	auditCmd.IncludeSbom = include
	return auditCmd
}

func (auditCmd *AuditCommand) SetIncludeSnippetDetection(include bool) *AuditCommand {
	auditCmd.IncludeSnippetDetection = include
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
func CreateAuditResultsContext(serverDetails *config.ServerDetails, xrayVersion string, watches []string, artifactoryRepoPath, projectKey, gitRepoHttpsCloneUrl string, includeVulnerabilities, includeLicenses, includeSbom, includeSnippetDetection bool) (context results.ResultContext) {
	context = results.ResultContext{
		RepoPath:                artifactoryRepoPath,
		Watches:                 watches,
		ProjectKey:              projectKey,
		IncludeVulnerabilities:  shouldIncludeVulnerabilities(includeVulnerabilities, watches, artifactoryRepoPath, projectKey, ""),
		IncludeLicenses:         includeLicenses,
		IncludeSbom:             includeSbom,
		IncludeSnippetDetection: includeSnippetDetection,
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
	manager, err := xsc.CreateXscService(serverDetails, xrayutils.WithScopedProjectKey(projectKey))
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
	return includeVulnerabilities || len(watches) == 0 && projectKey == "" && artifactoryRepoPath == "" && gitRepoHttpsCloneUrl == ""
}

func logScanPaths(workingDirs []string, isRecursiveScan bool) {
	if len(workingDirs) == 0 {
		return
	}
	if len(workingDirs) == 1 {
		if isRecursiveScan {
			log.Info("Detecting recursively targets for scan in path:", workingDirs[0])
		} else {
			log.Info("Scanning path:", workingDirs[0])
		}
		return
	}
	log.Info("Scanning paths:", strings.Join(workingDirs, ", "))
}

func (auditCmd *AuditCommand) Run() (err error) {
	isRecursiveScan := false
	if _, ok := auditCmd.bomGenerator.(*xrayplugin.XrayLibBomGenerator); ok {
		if len(auditCmd.workingDirs) > 1 {
			return errors.New("the 'audit' command with the 'Xray lib' BOM generator supports only one working directory. Please provide a single working directory")
		}
	} else if utils.IsScanRequested(utils.SourceCode, utils.ScaScan, auditCmd.ScansToPerform()...) || auditCmd.IncludeSbom {
		// Only in case of SCA scan / SBOM requested and if no workingDirs were provided by the user
		// We apply a recursive scan on the root repository
		isRecursiveScan = len(auditCmd.workingDirs) == 0
	}
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(auditCmd.workingDirs)
	if err != nil {
		return
	}
	logScanPaths(workingDirs, isRecursiveScan)
	serverDetails, err := auditCmd.ServerDetails()
	if err != nil {
		return
	}

	multiScanId, startTime := xsc.SendNewScanEvent(
		auditCmd.GetXrayVersion(),
		auditCmd.GetXscVersion(),
		serverDetails,
		xsc.CreateAnalyticsEvent(xscservices.CliProduct, xscservices.CliEventType, serverDetails),
		auditCmd.projectKey,
	)

	auditParams := NewAuditParams().
		SetBomGenerator(auditCmd.bomGenerator).
		SetScaScanStrategy(auditCmd.scaScanStrategy).
		SetCustomAnalyzerManagerBinaryPath(auditCmd.customAnalyzerManagerBinaryPath).
		SetCustomBomGenBinaryPath(auditCmd.customBomGenBinaryPath).
		SetViolationGenerator(auditCmd.violationGenerator).
		SetRtResultRepository(auditCmd.rtResultRepository).
		SetUploadCdxResults(auditCmd.uploadCdxResults).
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
			auditCmd.IncludeSbom,
			auditCmd.IncludeSnippetDetection,
		)).
		SetGitContext(auditCmd.GitContext()).
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
	log.Info("####### jf audit Scan Finished #######")
	return OutputResultsAndCmdError(auditResults, auditCmd.getResultWriter(auditResults), auditCmd.Fail)
}

func (auditCmd *AuditCommand) getResultWriter(cmdResults *results.SecurityCommandResults) *output.ResultsWriter {
	var messages []string
	if !cmdResults.EntitledForJas {
		messages = []string{coreutils.PrintTitle("In addition to SCA, the ‘jf audit’ command supports the following Advanced Security scans: 'Contextual Analysis', 'Secrets Detection', 'IaC', and ‘SAST’.\nThese scans are available within Advanced Security license. Read more - ") + coreutils.PrintLink(utils.JasInfoURL)}
	}
	if cmdResults.ResultsPlatformUrl != "" {
		messages = append(messages, output.GetCommandResultsPlatformUrlMessage(cmdResults, true))
	}
	var tableNotes []string
	if cmdResults.EntitledForJas && cmdResults.HasViolationContext() && len(cmdResults.ResultContext.GitRepoHttpsCloneUrl) == 0 {
		tableNotes = []string{"Note: The following vulnerability violations are NOT supported by this audit:\n- Secrets\n- Infrastructure as Code (IaC)\n- Static Application Security Testing (SAST)"}
	}
	return output.NewResultsWriter(cmdResults).
		SetOutputFormat(auditCmd.OutputFormat()).
		SetOutputDir(auditCmd.scanResultsOutputDir).
		SetPrintExtendedTable(auditCmd.PrintExtendedTable).
		SetTableNotes(tableNotes).
		SetExtraMessages(messages).
		SetSubScansPerformed(auditCmd.ScansToPerform())
}

func OutputResultsAndCmdError(auditResults *results.SecurityCommandResults, outputWriter *output.ResultsWriter, failBuild bool) (err error) {
	if err = outputWriter.PrintScanResults(); err != nil {
		// Error printing the results, return the error and the scan results errors.
		return errors.Join(err, auditResults.GetErrors())
	}
	if err = auditResults.GetErrors(); err != nil {
		// Return the scan results errors.
		return
	}
	if failBuild {
		// Only in case the user asked to fail the build accordingly, do so.
		err = policy.CheckPolicyFailBuildError(auditResults)
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
	// Prepare the command for the scan.
	if cmdResults = prepareToScan(auditParams); cmdResults.GeneralError != nil {
		return
	}
	// Run Scanners
	if runParallelAuditScans(cmdResults, auditParams); cmdResults.GeneralError != nil {
		return
	}
	// Process the scan results and run additional steps if needed.
	return processScanResults(auditParams, cmdResults)
}

func prepareToScan(params *AuditParams) (cmdResults *results.SecurityCommandResults) {
	if params.Progress() != nil {
		params.Progress().SetHeadlineMsg("Preparing to scan")
	}
	// Initialize Results struct
	if cmdResults = initAuditCmdResults(params); cmdResults.GeneralError != nil {
		return
	}
	bomGenOptions, scanOptions, err := getScanLogicOptions(params)
	if err != nil {
		return cmdResults.AddGeneralError(fmt.Errorf("failed to get scan logic options: %s", err.Error()), params.AllowPartialResults())
	}
	// Initialize the BOM generator if needed
	if params.resultsContext.IncludeSbom || utils.IsScanRequested(cmdResults.CmdType, utils.ScaScan, params.scansToPerform...) {
		if err = params.bomGenerator.WithOptions(bomGenOptions...).PrepareGenerator(); err != nil {
			return cmdResults.AddGeneralError(fmt.Errorf("failed to prepare the BOM generator: %s", err.Error()), params.AllowPartialResults())
		}
	}
	populateScanTargets(cmdResults, params)
	// Initialize the SCA scan strategy
	if err = params.scaScanStrategy.WithOptions(scanOptions...).PrepareStrategy(); err != nil {
		return cmdResults.AddGeneralError(fmt.Errorf("failed to prepare the SCA scan strategy: %s", err.Error()), params.AllowPartialResults())
	}
	return
}

func getScanLogicOptions(params *AuditParams) (bomGenOptions []bom.SbomGeneratorOption, scanOptions []scan.SbomScanOption, err error) {
	// Bom Generators Options
	buildParams, err := params.ToBuildInfoBomGenParams()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create build info params: %w", err)
	}
	bomGenOptions = []bom.SbomGeneratorOption{
		// Build Info Bom Generator Options
		buildinfo.WithParams(buildParams),
		// Xray-Scan-Plugin Bom Generator Options
		xrayplugin.WithTotalTargets(len(params.workingDirs)),
		xrayplugin.WithBinaryPath(params.CustomBomGenBinaryPath()),
		xrayplugin.WithIgnorePatterns(params.Exclusions()),
		xrayplugin.WithSnippetDetection(params.resultsContext.IncludeSnippetDetection),
	}
	// Scan Strategies Options
	scanGraphParams, err := params.ToXrayScanGraphParams()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create scan graph params: %w", err)
	}
	serverDetails, err := params.ServerDetails()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get server details: %w", err)
	}
	scanOptions = []scan.SbomScanOption{
		// Xray Scan Graph Strategy Options
		scanGraphStrategy.WithParams(scanGraphParams),
		// Catalog Enrich Strategy Options
		enrich.WithParams(serverDetails, params.resultsContext.ProjectKey),
	}
	return bomGenOptions, scanOptions, nil
}

func initAuditCmdResults(params *AuditParams) (cmdResults *results.SecurityCommandResults) {
	cmdResults = results.NewCommandResults(utils.SourceCode)
	// Initialize general information
	cmdResults.SetXrayVersion(params.GetXrayVersion())
	cmdResults.SetXscVersion(params.GetXscVersion())
	cmdResults.SetMultiScanId(params.GetMultiScanId())
	cmdResults.SetStartTime(params.StartTime())
	cmdResults.SetResultsContext(params.resultsContext)
	cmdResults.SetGitContext(params.GitContext())
	serverDetails, err := params.ServerDetails()
	if err != nil {
		return cmdResults.AddGeneralError(err, false)
	}
	// Send entitlement requests
	xrayManager, err := xrayutils.CreateXrayServiceManager(serverDetails, xrayutils.WithScopedProjectKey(params.resultsContext.ProjectKey))
	if err != nil {
		return cmdResults.AddGeneralError(err, false)
	}
	entitledForJas, err := isEntitledForJas(xrayManager, params)
	if err != nil {
		return cmdResults.AddGeneralError(err, false)
	} else {
		cmdResults.SetEntitledForJas(entitledForJas)
	}
	if entitledForJas {
		cmdResults.SetSecretValidation(jas.CheckForSecretValidation(xrayManager, params.GetXrayVersion(), slices.Contains(params.ScansToPerform(), utils.SecretTokenValidationScan)))
	}
	if params.resultsContext.IncludeSnippetDetection {
		if err := clientutils.ValidateMinimumVersion(clientutils.Xray, params.GetXrayVersion(), utils.SnippetDetectionMinVersion); err != nil {
			// Snippet detection is not supported by the Xray version.
			log.Warn(fmt.Sprintf("Snippet detection is not supported by the Xray version (%s). Snippet detection will not be included in the results.", params.GetXrayVersion()))
			params.resultsContext.IncludeSnippetDetection = false
		}
	}
	return
}

func isEntitledForJas(xrayManager *xray.XrayServicesManager, auditParams *AuditParams) (entitled bool, err error) {
	if !auditParams.UseJas() {
		// Dry run without JAS
		return false, nil
	}
	return jas.IsEntitledForJas(xrayManager, auditParams.GetXrayVersion())
}

func populateScanTargets(cmdResults *results.SecurityCommandResults, params *AuditParams) {
	// Populate the scan targets based on the provided parameters.
	detectScanTargets(cmdResults, params)
	// Load apps config information
	jfrogAppsConfig, err := jas.CreateJFrogAppsConfig(cmdResults.GetTargetsPaths())
	if err != nil {
		cmdResults.AddGeneralError(fmt.Errorf("failed to create JFrogAppsConfig: %s", err.Error()), false)
		return
	}
	// Populate target information for the scans
	for _, targetResult := range cmdResults.Targets {
		// Get the apps config module and assign it to the target result for JAS scans.
		targetResult.AppsConfigModule = jas.GetModule(targetResult.Target, jfrogAppsConfig)
		// Generate SBOM for the target if requested or for SCA scans.
		if !params.resultsContext.IncludeSbom && len(params.ScansToPerform()) > 0 && !slices.Contains(params.ScansToPerform(), utils.ScaScan) {
			// No need to generate the SBOM if we are not going to use it.
			continue
		}
		bom.GenerateSbomForTarget(params.BomGenerator().WithOptions(buildinfo.WithDescriptors(targetResult.GetDescriptors())),
			bom.SbomGeneratorParams{
				Target:               targetResult,
				AllowPartialResults:  params.AllowPartialResults(),
				ScanResultsOutputDir: params.scanResultsOutputDir,
				// Diff mode - SCA
				DiffMode:              params.DiffMode(),
				TargetResultToCompare: getTargetResultsToCompare(cmdResults, params.ResultsToCompare(), targetResult),
			},
		)
	}
	logScanTargetsInfo(cmdResults)
}

func logScanTargetsInfo(cmdResults *results.SecurityCommandResults) {
	// Print the scan targets
	if len(cmdResults.Targets) == 1 {
		outLog := "Performing scans on "
		if cmdResults.Targets[0].Technology != techutils.NoTech {
			outLog += fmt.Sprintf("%s ", cmdResults.Targets[0].Technology.String())
		}
		outLog += "project "
		if cmdResults.Targets[0].Name != "" {
			outLog += fmt.Sprintf("'%s' ", cmdResults.Targets[0].Name)
		} else {
			outLog += fmt.Sprintf("'%s' ", cmdResults.Targets[0].Target)
		}
		log.Info(outLog)
		return
	}
	scanInfo, err := coreutils.GetJsonIndent(cmdResults.GetTargets())
	if err != nil {
		return
	}
	log.Info(fmt.Sprintf("Performing scans on %d targets:\n%s", len(cmdResults.Targets), scanInfo))
}

func getTargetResultsToCompare(cmdResults, resultsToCompare *results.SecurityCommandResults, targetResult *results.TargetResults) (targetResultsToCompare *results.TargetResults) {
	if resultsToCompare == nil {
		return
	}
	targetResultsToCompare = results.SearchTargetResultsByRelativePath(
		utils.GetRelativePath(targetResult.Target, cmdResults.GetCommonParentPath()),
		resultsToCompare,
	)
	// Let's check if the target results to compare are valid.
	// If the current target result is a new module, it will not have any previous target results to compare with.
	if targetResultsToCompare == nil || targetResultsToCompare.ScaResults == nil || targetResultsToCompare.ScaResults.Sbom == nil {
		log.Debug(fmt.Sprintf("No previous target results found to compare with for %s", targetResult.Target))
	}
	return
}

func detectScanTargets(cmdResults *results.SecurityCommandResults, params *AuditParams) {
	for _, requestedDirectory := range params.workingDirs {
		if !fileutils.IsPathExists(requestedDirectory, false) {
			log.Warn("The working directory", requestedDirectory, "doesn't exist. Skipping SCA scan...")
			continue
		}
		// Detect descriptors and technologies in the requested directory.
		techToWorkingDirs, err := techutils.DetectTechnologiesDescriptors(requestedDirectory, params.IsRecursiveScan(), params.Technologies(), getRequestedDescriptors(params), technologies.GetExcludePattern(params.GetConfigProfile(), params.IsRecursiveScan(), params.Exclusions()...))
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
	// If no scan targets were detected, we should still proceed with the scans.
	if len(params.workingDirs) == 1 && len(cmdResults.Targets) == 0 {
		cmdResults.NewScanResults(results.ScanTarget{Target: params.workingDirs[0]})
	}
}

func getRequestedDescriptors(params *AuditParams) map[techutils.Technology][]string {
	requestedDescriptors := map[techutils.Technology][]string{}
	if params.PipRequirementsFile() != "" {
		requestedDescriptors[techutils.Pip] = []string{params.PipRequirementsFile()}
	}
	return requestedDescriptors
}

func runParallelAuditScans(cmdResults *results.SecurityCommandResults, auditParams *AuditParams) {
	var jasScanner *jas.JasScanner
	var generalJasScanErr error
	auditParallelRunner := utils.CreateSecurityParallelRunner(auditParams.threads)
	if auditParams.Progress() != nil {
		auditParams.Progress().SetHeadlineMsg("Scanning for issues")
	}
	// TODO: remove "isNewFlow" once the old flow is fully deprecated.
	isNewFlow := true
	if _, ok := auditParams.scaScanStrategy.(*scanGraphStrategy.ScanGraphStrategy); ok {
		isNewFlow = false
	}
	// Add the scans to the parallel runner
	if jasScanner, generalJasScanErr = addJasScansToRunner(auditParallelRunner, auditParams, cmdResults, isNewFlow); generalJasScanErr != nil {
		cmdResults.AddGeneralError(fmt.Errorf("error has occurred during JAS scan process. JAS scan is skipped for the following directories: %s\n%s", strings.Join(cmdResults.GetTargetsPaths(), ","), generalJasScanErr.Error()), auditParams.AllowPartialResults())
	}
	if generalScaScanError := addScaScansToRunner(auditParallelRunner, auditParams, cmdResults, isNewFlow); generalScaScanError != nil {
		cmdResults.AddGeneralError(fmt.Errorf("error has occurred during SCA scan process. SCA scan is skipped for the following directories: %s\n%s", strings.Join(cmdResults.GetTargetsPaths(), ","), generalScaScanError.Error()), auditParams.AllowPartialResults())
	}
	// Start the parallel runner to run the scans.
	auditParallelRunner.OnScanEnd(func() {
		// Wait for all scans to complete before cleaning up
		if jasScanner != nil && jasScanner.ScannerDirCleanupFunc != nil {
			cmdResults.AddGeneralError(jasScanner.ScannerDirCleanupFunc(), false)
		}
		if auditParams.BomGenerator() != nil {
			cmdResults.AddGeneralError(auditParams.BomGenerator().CleanUp(), false)
		}
	}).Start()
}

func addScaScansToRunner(auditParallelRunner *utils.SecurityParallelRunner, auditParams *AuditParams, scanResults *results.SecurityCommandResults, isNewFlow bool) (generalError error) {
	if auditParams.DiffMode() && auditParams.ResultsToCompare() == nil {
		// First call to audit scan on target branch, no diff to compare - no need to run the scan.
		log.Debug("Diff scan - calculated components for target, skipping scan part")
		return
	}

	// Perform SCA scans
	for _, targetResult := range scanResults.Targets {
		if err := scan.RunScaScan(auditParams.scaScanStrategy, scan.ScaScanParams{
			ScanResults:         targetResult,
			TargetCount:         len(scanResults.Targets),
			ScansToPerform:      auditParams.ScansToPerform(),
			ConfigProfile:       auditParams.GetConfigProfile(),
			AllowPartialResults: auditParams.AllowPartialResults(),
			ResultsOutputDir:    auditParams.scanResultsOutputDir,
			Runner:              auditParallelRunner,
			// TODO: remove this field once the new flow is fully implemented.
			IsNewFlow: isNewFlow,
		}); err != nil {
			generalError = errors.Join(generalError, fmt.Errorf("failed to run SCA scan for target %s: %s", targetResult.Target, err.Error()))
		}
	}
	return
}

func addJasScansToRunner(auditParallelRunner *utils.SecurityParallelRunner, auditParams *AuditParams, scanResults *results.SecurityCommandResults, isNewFlow bool) (jasScanner *jas.JasScanner, generalError error) {
	if !scanResults.EntitledForJas {
		log.Info("Advanced Security is not enabled on this system, so Advanced Security scans were skipped...")
		return
	}
	if !utils.IsJASRequested(scanResults.CmdType, auditParams.ScansToPerform()...) {
		log.Debug("Advanced Security scans were not initiated, so Advanced Security scans were skipped...")
		return
	}
	serverDetails, err := auditParams.ServerDetails()
	if err != nil {
		generalError = fmt.Errorf("failed to get server details: %s", err.Error())
		return
	}
	auditParallelRunner.ResultsMu.Lock()
	scannerOptions := []jas.JasScannerOption{
		jas.WithEnvVars(
			scanResults.SecretValidation,
			jas.GetDiffScanTypeValue(auditParams.diffMode, auditParams.resultsToCompare),
			jas.GetAnalyzerManagerXscEnvVars(
				isNewFlow,
				auditParams.GetMultiScanId(),
				utils.GetGitRepoUrlKey(auditParams.resultsContext.GitRepoHttpsCloneUrl),
				auditParams.resultsContext.ProjectKey,
				auditParams.resultsContext.Watches,
				scanResults.GetTechnologies()...,
			),
		),
		jas.WithMinSeverity(auditParams.minSeverityFilter),
		jas.WithExclusions(auditParams.Exclusions()...),
		jas.WithResultsToCompare(auditParams.resultsToCompare),
	}
	jasScanner, err = jas.NewJasScanner(serverDetails, scannerOptions...)
	jas.UpdateJasScannerWithExcludePatternsFromProfile(jasScanner, auditParams.GetConfigProfile())

	auditParallelRunner.ResultsMu.Unlock()
	if err != nil {
		generalError = fmt.Errorf("failed to create jas scanner: %s", err.Error())
		return
	} else if jasScanner == nil {
		log.Debug("Jas scanner was not created, skipping advance security scans...")
		return
	}
	auditParallelRunner.JasWg.Add(1)
	if _, jasErr := auditParallelRunner.Runner.AddTaskWithError(createJasScansTask(auditParallelRunner, scanResults, serverDetails, auditParams, jasScanner), func(taskErr error) {
		scanResults.AddGeneralError(fmt.Errorf("failed while adding JAS scan tasks: %s", taskErr.Error()), auditParams.AllowPartialResults())
	}); jasErr != nil {
		generalError = fmt.Errorf("failed to create JAS task: %s", jasErr.Error())
	}
	return
}

func createJasScansTask(auditParallelRunner *utils.SecurityParallelRunner, scanResults *results.SecurityCommandResults,
	serverDetails *config.ServerDetails, auditParams *AuditParams, scanner *jas.JasScanner) parallel.TaskFunc {
	return func(threadId int) (generalError error) {
		defer func() {
			auditParallelRunner.JasWg.Done()
		}()
		// First download the analyzer manager if needed
		if auditParams.customAnalyzerManagerBinaryPath == "" {
			if generalError = jas.DownloadAnalyzerManagerIfNeeded(threadId); generalError != nil {
				return fmt.Errorf("failed to download analyzer manager: %s", generalError.Error())
			}
			if scanner.AnalyzerManager.AnalyzerManagerFullPath, generalError = jas.GetAnalyzerManagerExecutable(); generalError != nil {
				return fmt.Errorf("failed to set analyzer manager executable path: %s", generalError.Error())
			}
		} else {
			scanner.AnalyzerManager.AnalyzerManagerFullPath = auditParams.customAnalyzerManagerBinaryPath
			log.Debug(clientutils.GetLogMsgPrefix(threadId, false) + "using custom analyzer manager binary path")
		}
		log.Debug(clientutils.GetLogMsgPrefix(threadId, false) + fmt.Sprintf("Using analyzer manager executable at: %s", scanner.AnalyzerManager.AnalyzerManagerFullPath))
		// Run JAS scanners for each scan target
		for _, targetResult := range scanResults.Targets {
			if targetResult.AppsConfigModule == nil {
				_ = targetResult.AddTargetError(fmt.Errorf("can't find module for path %s", targetResult.Target), auditParams.AllowPartialResults())
				continue
			}
			appsConfigModule := *targetResult.AppsConfigModule
			params := runner.JasRunnerParams{
				Runner:                 auditParallelRunner,
				ServerDetails:          serverDetails,
				Scanner:                scanner,
				Module:                 appsConfigModule,
				ConfigProfile:          auditParams.GetConfigProfile(),
				ScansToPerform:         auditParams.ScansToPerform(),
				SourceResultsToCompare: scanner.GetResultsToCompareByRelativePath(utils.GetRelativePath(targetResult.Target, scanResults.GetCommonParentPath())),
				SecretsScanType:        secrets.SecretsScannerType,
				CvesProvider: func() (directCves []string, indirectCves []string) {
					if len(targetResult.GetScaScansXrayResults()) > 0 {
						// TODO: remove this once the new SCA flow with cdx is fully implemented.
						return results.ExtractCvesFromScanResponse(targetResult.GetScaScansXrayResults(), results.GetTargetDirectDependencies(targetResult, auditParams.ShouldGetFlatTreeForApplicableScan(targetResult.Technology), true))
					} else if targetResult.ScaResults != nil && targetResult.ScaResults.Sbom != nil {
						return results.ExtractCdxDependenciesCves(targetResult.ScaResults.Sbom)
					}
					return
				},
				ThirdPartyApplicabilityScan: auditParams.thirdPartyApplicabilityScan,
				ApplicableScanType:          applicability.ApplicabilityScannerType,
				SignedDescriptions:          getSignedDescriptions(auditParams.OutputFormat()),
				SastRules:                   auditParams.SastRules(),
				ScanResults:                 targetResult,
				TargetCount:                 len(scanResults.Targets),
				TargetOutputDir:             auditParams.scanResultsOutputDir,
				AllowPartialResults:         auditParams.AllowPartialResults(),
			}
			if generalError = runner.AddJasScannersTasks(params); generalError != nil {
				_ = targetResult.AddTargetError(fmt.Errorf("failed to add JAS scan tasks: %s", generalError.Error()), auditParams.AllowPartialResults())
				// We assign nil to 'generalError' after handling it to prevent it to propagate further, so it will not be captured twice - once here, and once in the error handling function of createJasScansTasks
				generalError = nil
			}
		}
		return
	}
}

func getSignedDescriptions(currentFormat format.OutputFormat) bool {
	allowEmojis, err := strconv.ParseBool(os.Getenv(utils.IsAllowEmojis))
	if err != nil {
		// default value
		allowEmojis = true
	}
	return currentFormat == format.Sarif && allowEmojis
}

func processScanResults(params *AuditParams, cmdResults *results.SecurityCommandResults) *results.SecurityCommandResults {
	// Upload results to Artifactory (should be the last step not including violations fetching so the uploaded results will include everything else).
	var err error
	uploadPath := ""
	if params.uploadCdxResults {
		log.Info("Finished scanning. Uploading scan results to Artifactory")
		if params.rtResultRepository == "" {
			return cmdResults.AddGeneralError(errors.New("results repository was not provided, can't upload scan results to Artifactory"), false)
		}
		if params.Progress() != nil {
			params.Progress().SetHeadlineMsg("Uploading scan results to platform")
		}
		uploadPath, err = uploadCdxResults(params, cmdResults)
		if err != nil {
			return cmdResults.AddGeneralError(fmt.Errorf("failed to upload scan results to Artifactory: %s", err.Error()), false)
		}
	}
	// Violations fetching
	if cmdResults.HasViolationContext() {
		if params.Progress() != nil {
			params.Progress().SetHeadlineMsg("Fetching violations")
		}
		if err = fetchViolations(uploadPath, cmdResults, params); err != nil {
			cmdResults.AddGeneralError(fmt.Errorf("failed to get violations: %s", err.Error()), params.AllowPartialResults())
		}
	}
	return cmdResults
}

func uploadCdxResults(auditParams *AuditParams, cmdResults *results.SecurityCommandResults) (uploadPath string, err error) {
	serverDetails, err := auditParams.ServerDetails()
	if err != nil {
		err = fmt.Errorf("failed to get server details: %s", err.Error())
		return
	}
	if uploadPath, err = output.UploadCommandResults(serverDetails, auditParams.rtResultRepository, cmdResults); err != nil {
		err = fmt.Errorf("failed to upload scan results to Artifactory: %s", err.Error())
	}
	return
}

func fetchViolations(uploadPath string, cmdResults *results.SecurityCommandResults, auditParams *AuditParams) (err error) {
	serverDetails, err := auditParams.ServerDetails()
	if err != nil {
		return fmt.Errorf("failed to get server details: %s", err.Error())
	}
	generator := auditParams.ViolationGenerator().WithOptions(
		local.WithAllowedLicenses(auditParams.allowedLicenses),
		enforcer.WithServerDetails(serverDetails),
		enforcer.WithProjectKey(auditParams.resultsContext.ProjectKey),
		enforcer.WithArtifactParams(auditParams.rtResultRepository, uploadPath),
		enforcer.WithWatches(auditParams.resultsContext.Watches),
		enforcer.WithResultsOutputDir(auditParams.scanResultsOutputDir),
	)
	// Fetch violations from Xray
	if err = policy.EnrichWithGeneratedViolations(generator, cmdResults); err != nil {
		return fmt.Errorf("failed to enrich with violations: %s", err.Error())
	}
	return
}
