package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/runner"
	"github.com/jfrog/jfrog-cli-security/jas/sast"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/policy/enforcer"
	"github.com/jfrog/jfrog-cli-security/policy/local"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin/plugin"
	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray/artifact"

	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-security/sca/scan/enrich"
	scanGraphStrategy "github.com/jfrog/jfrog-cli-security/sca/scan/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"

	xrayutils "github.com/jfrog/jfrog-cli-security/utils/xray"
)

type AuditCommand struct {
	watches                 []string
	gitRepoHttpsCloneUrl    string
	projectKey              string
	targetRepoPath          string
	IncludeVulnerabilities  bool
	IncludeLicenses         bool
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
func logScanPaths(workingDirs []string, isRecursiveScan bool) {
	switch {
	case len(workingDirs) > 1:
		log.Info("Scanning paths:", strings.Join(workingDirs, ", "))
	case isRecursiveScan && len(workingDirs) == 0:
		log.Info("Detecting recursively targets for scan in current directory")
	case isRecursiveScan:
		log.Info("Detecting recursively targets for scan in path:", workingDirs[0])
	case len(workingDirs) == 0:
		log.Debug("Scanning current directory...")
	default:
		log.Info("Scanning path:", workingDirs[0])
	}
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

func shouldIncludeSnippetDetection(params *AuditParams) bool {
	if profile := params.GetConfigProfile(); profile != nil && len(profile.Modules) > 0 {
		for _, module := range profile.Modules {
			if module.ScanConfig.ScaScannerConfig.EnableSnippetDetection {
				return true
			}
		}
	}
	if params.resultsContext.IncludeSnippetDetection {
		return true
	}
	return strings.ToLower(os.Getenv(plugin.SnippetDetectionEnvVariable)) == "true"
}

func GetTargetsInfo(workingDirs []string, bomGenerator bom.SbomGenerator, scansToPerform []utils.SubScanType, includeSbom bool, rootDir string) (projectPath string, includeDirs []string, isRecursiveScan bool, err error) {
	includeDirs, err = utils.GetFullPathsWorkingDirs(workingDirs)
	if err != nil {
		return
	}
	if !isNewFlow(bomGenerator) && (utils.IsScanRequested(utils.SourceCode, utils.ScaScan, nil, scansToPerform...) || includeSbom) {
		// Only in case of SCA scan / SBOM requested and if no workingDirs were provided by the user
		// We apply a recursive scan on the root repository
		isRecursiveScan = len(workingDirs) == 0
	}
	logScanPaths(includeDirs, isRecursiveScan)
	if rootDir != "" {
		projectPath = rootDir
	} else {
		if currentDir, e := coreutils.GetWorkingDirectory(); e != nil {
			log.Warn(fmt.Sprintf("Failed to get working directory: %s", e.Error()))
			projectPath = utils.GetCommonParentDir(includeDirs...)
		} else {
			projectPath = currentDir
		}
	}
	return
}

func isNewFlow(bomGenerator bom.SbomGenerator) bool {
	if _, ok := bomGenerator.(*xrayplugin.XrayLibBomGenerator); ok {
		return true
	}
	return false
}

func (auditCmd *AuditCommand) Run() (err error) {
	projectPath, includeDirs, isRecursiveScan, err := GetTargetsInfo(auditCmd.workingDirs, auditCmd.bomGenerator, auditCmd.scansToPerform, auditCmd.resultsContext.IncludeSbom, auditCmd.rootDir)
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
		xsc.CreateAnalyticsEvent(xscServices.CliProduct, xscServices.CliEventType, serverDetails, projectPath),
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
		SetWorkingDirs(includeDirs).
		SetMinSeverityFilter(auditCmd.minSeverityFilter).
		SetFixableOnly(auditCmd.fixableOnly).
		SetGraphBasicParams(auditCmd.AuditBasicParams.SetIsRecursiveScan(isRecursiveScan).SetExclusions(auditCmd.Exclusions())).
		SetResultsContext(CreateAuditResultsContext(
			serverDetails,
			auditCmd.GetXrayVersion(),
			auditCmd.watches,
			auditCmd.targetRepoPath,
			auditCmd.projectKey,
			auditCmd.gitRepoHttpsCloneUrl,
			auditCmd.IncludeVulnerabilities,
			auditCmd.IncludeLicenses,
			auditCmd.resultsContext.IncludeSbom,
			auditCmd.IncludeSnippetDetection,
		)).
		SetGitContext(auditCmd.GitContext()).
		SetThirdPartyApplicabilityScan(auditCmd.thirdPartyApplicabilityScan).
		SetThreads(auditCmd.Threads).
		SetScansResultsOutputDir(auditCmd.scanResultsOutputDir).
		SetStartTime(startTime).
		SetMultiScanId(multiScanId).
		SetRootDir(auditCmd.rootDir).SetSastChangedFilesMode(auditCmd.sastChangedFilesMode).SetSastRules(auditCmd.sastRules)

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
	if !cmdResults.Entitlements.Jas {
		messages = []string{coreutils.PrintTitle("In addition to SCA, the ‘jf audit’ command supports the following Advanced Security scans: 'Contextual Analysis', 'Secrets Detection', 'IaC', and ‘SAST’.\nThese scans are available within Advanced Security license. Read more - ") + coreutils.PrintLink(utils.JasInfoURL)}
	}
	if cmdResults.ResultsPlatformUrl != "" && auditCmd.gitContext != nil {
		messages = append(messages, output.GetCommandResultsPlatformUrlMessage(cmdResults, true))
	}
	var tableNotes []string
	if cmdResults.Entitlements.Jas && cmdResults.HasViolationContext() && len(cmdResults.ResultContext.GitRepoHttpsCloneUrl) == 0 {
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
	if cmdResults = prepareToScan(auditParams); cmdResults.GetErrors() != nil {
		return
	}
	// Run Scanners
	if runParallelAuditScans(cmdResults, auditParams); cmdResults.GetErrors() != nil {
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
	if cmdResults = initAuditCmdResults(params); cmdResults.GetErrors() != nil {
		return
	}
	bomGenOptions, scanOptions, err := getScanLogicOptions(params)
	if err != nil {
		return cmdResults.AddGeneralError(fmt.Errorf("failed to get scan logic options: %s", err.Error()), cmdResults.AllowPartialResults)
	}
	// Initialize the BOM generator if needed
	if params.resultsContext.IncludeSbom || utils.IsScanRequested(cmdResults.CmdType, utils.ScaScan, cmdResults.IsScanRequestedByCentralConfig(utils.ScaScan), params.scansToPerform...) {
		if err = params.bomGenerator.WithOptions(bomGenOptions...).PrepareGenerator(); err != nil {
			return cmdResults.AddGeneralError(fmt.Errorf("failed to prepare the BOM generator: %s", err.Error()), cmdResults.AllowPartialResults)
		}
	}
	populateScanTargets(cmdResults, params)
	// Initialize the SCA scan strategy
	if err = params.scaScanStrategy.WithOptions(scanOptions...).PrepareStrategy(); err != nil {
		return cmdResults.AddGeneralError(fmt.Errorf("failed to prepare the SCA scan strategy: %s", err.Error()), cmdResults.AllowPartialResults)
	}
	return
}

func getScanLogicOptions(params *AuditParams) (bomGenOptions []bom.SbomGeneratorOption, scanOptions []scan.SbomScanOption, err error) {
	// Bom Generators Options
	buildParams, err := params.ToBuildInfoBomGenParams()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create build info params: %w", err)
	}
	serverDetails, err := params.ServerDetails()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get server details: %w", err)
	}
	bomGenOptions = []bom.SbomGeneratorOption{
		// Build Info Bom Generator Options
		buildinfo.WithParams(buildParams),
		// Xray-Scan-Plugin Bom Generator Options
		xrayplugin.WithBinaryPath(params.CustomBomGenBinaryPath()),
		xrayplugin.WithSpecificTechnologies(params.Technologies()),
	}
	if params.configProfile != nil && params.configProfile.GeneralConfig.ScannersDownloadPath != "" {
		bomGenOptions = append(bomGenOptions, xrayplugin.WithCentralRemoteReleasesDetails(serverDetails, params.configProfile.GeneralConfig.ScannersDownloadPath))
	}
	// Scan Strategies Options
	scanGraphParams, err := params.ToXrayScanGraphParams()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create scan graph params: %w", err)
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
	cmdResults.SetAllowPartialResults(params.CalculatedAllowPartialResults())
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
	}
	cmdResults.SetEntitledForJas(entitledForJas)
	if entitledForJas {
		// Validate required installed software
		if cmdResults.IsJASRequested(params.ScansToPerform()...) {
			if err = jas.ValidateRequiredInstalledSoftware(); err != nil {
				return cmdResults.AddGeneralError(err, false)
			}
		}
		// Validate secret validation entitlement
		cmdResults.SetSecretValidation(jas.CheckForSecretValidation(xrayManager, params.GetXrayVersion(), slices.Contains(params.ScansToPerform(), utils.SecretTokenValidationScan)))
	}
	// Snippet detection requires JAS entitlement and also the Snippet Detection feature is enabled in Xray.
	if shouldIncludeSnippetDetection(params) {
		entitledForSnippetDetection, err := isEntitledForSnippetDetection(entitledForJas, xrayManager, params)
		if err != nil {
			return cmdResults.AddGeneralError(err, false)
		}
		if !entitledForSnippetDetection {
			return cmdResults.AddGeneralError(fmt.Errorf("snippet detection is requested but the JFrog instance is not entitled for it"), false)
		}
		cmdResults.SetEntitledForSnippetDetection(entitledForSnippetDetection)
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

func isEntitledForSnippetDetection(isEntitledForJas bool, xrayManager *xray.XrayServicesManager, auditParams *AuditParams) (entitled bool, err error) {
	if !isEntitledForJas {
		return false, nil
	}
	// Snippet detection requires JAS entitlement and also the Snippet Detection feature is enabled in Xray.
	return xrayutils.IsEntitled(xrayManager, auditParams.GetXrayVersion(), xrayplugin.SnippetDetectionFeatureId)
}

func populateScanTargets(cmdResults *results.SecurityCommandResults, params *AuditParams) {
	// Populate x scan targets based on the provided parameters.
	detectScanTargets(cmdResults, params)
	// Populate target information for the scans
	for _, targetResult := range cmdResults.Targets {
		// Generate SBOM for the target if requested or for SCA scans.
		if !shouldGenerateSbom(targetResult, params) {
			continue
		}
		bom.GenerateSbomForTarget(params.BomGenerator().WithOptions(
			buildinfo.WithDescriptors(targetResult.GetDescriptors()),
			xrayplugin.WithSnippetDetection(shouldIncludeSnippetDetection(params)),
			xrayplugin.WithServerDetails(params.serverDetails),
		),
			bom.SbomGeneratorParams{
				Target:               targetResult,
				TotalTargets:         len(cmdResults.Targets),
				AllowPartialResults:  cmdResults.AllowPartialResults,
				ScanResultsOutputDir: params.scanResultsOutputDir,
				// Diff mode - SCA
				DiffMode:              params.DiffMode(),
				TargetResultToCompare: getTargetResultsToCompare(cmdResults, params.ResultsToCompare(), targetResult),
			},
		)
	}
	logScanTargetsInfo(cmdResults)
}

func shouldGenerateSbom(targetResult *results.TargetResults, params *AuditParams) bool {
	if params.resultsContext.IncludeSbom {
		log.Verbose("Sbom is requested by input...")
		return true
	}
	scansToPerform := params.ScansToPerform()
	if slices.Contains(scansToPerform, utils.ScaScan) {
		log.Verbose("Sbom is requested for SCA scan...")
		return true
	}
	if targetResult != nil {
		if centralConfiguredToRun := targetResult.IsScanRequestedByCentralConfig(utils.ScaScan); centralConfiguredToRun != nil {
			profileName := ""
			if params.configProfile != nil {
				profileName = params.configProfile.ProfileName
			}
			log.Debug(fmt.Sprintf("Using config profile '%s' to determine if SBOM should be generated...", profileName))
			if !*centralConfiguredToRun {
				log.Debug(fmt.Sprintf("Skipping SBOM generation as SCA scan is not requested by '%s' config profile...", profileName))
				return false
			}
			return true
		}
	}
	if configProfile := params.GetConfigProfile(); configProfile != nil && len(configProfile.Modules) > 0 {
		enableSca := configProfile.Modules[0].ScanConfig.ScaScannerConfig.EnableScaScan
		log.Debug(fmt.Sprintf("Using config profile '%s' to determine if SBOM should be generated...", configProfile.ProfileName))
		return enableSca
	}
	userRequestedSpecificScans := len(scansToPerform) > 0
	if userRequestedSpecificScans {
		if targetResult != nil {
			log.Debug(fmt.Sprintf("Skipping SBOM generation for '%s' as requested by input...", targetResult.String()))
		} else {
			log.Debug("Skipping SBOM generation as requested by input...")
		}
		return false
	}
	// If we got here, we should generate the SBOM (all scans are requested)
	return true
}

func logScanTargetsInfo(cmdResults *results.SecurityCommandResults) {
	if len(cmdResults.Targets) == 0 {
		log.Warn("No scan targets were detected. No scans will be performed.")
		return
	}
	// Print the scan targets
	if len(cmdResults.Targets) == 1 {
		log.Info(fmt.Sprintf("Performing scans on project %s", cmdResults.Targets[0].String()))
		return
	}
	scanInfo, err := coreutils.GetJsonIndent(cmdResults.GetTargets())
	if err != nil {
		return
	}
	log.Info(fmt.Sprintf("Performing scans on %d targets", len(cmdResults.Targets)))
	log.Debug(scanInfo)
}

func getTargetResultsToCompare(cmdResults, resultsToCompare *results.SecurityCommandResults, targetResult *results.TargetResults) (targetResultsToCompare *results.TargetResults) {
	if resultsToCompare == nil {
		return
	}
	targetResultsToCompare = results.SearchTargetResultsByRelativePath(
		utils.GetRelativePath(targetResult.Target, cmdResults.GetCommonParentPath()), resultsToCompare, targetResult.Technologies...,
	)
	// Let's check if the target results to compare are valid.
	// If the current target result is a new module, it will not have any previous target results to compare with.
	if targetResultsToCompare == nil || targetResultsToCompare.ScaResults == nil || targetResultsToCompare.ScaResults.Sbom == nil {
		log.Debug(fmt.Sprintf("No previous target results found to compare with for %s", targetResult.Target))
	}
	return
}

func detectScanTargets(cmdResults *results.SecurityCommandResults, params *AuditParams) {
	cwd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		cmdResults.AddGeneralError(fmt.Errorf("failed to get working directory: %s", err.Error()), false)
		return
	}
	// Create scan targets
	if isNewFlow(params.bomGenerator) {
		createScanTargetsFromConfigs(cmdResults, params, cwd)
	} else {
		// Old flow:
		detectScaTargetsFromTechnologies(cmdResults, params, cwd)
		matchCentralConfigModulesForOldFlow(cmdResults, params.GetConfigProfile())
	}
}

// New flow: creates targets from config profile modules or working dirs input.
func createScanTargetsFromConfigs(cmdResults *results.SecurityCommandResults, params *AuditParams, cwd string) {
	rootDir := params.rootDir
	if rootDir == "" {
		rootDir = cwd
	}
	configProfile := params.GetConfigProfile()
	if configProfile == nil {
		includeDirs := params.WorkingDirs()
		msg := fmt.Sprintf("No config profile found. Creating single scan target from root directory: %s", rootDir)
		if len(includeDirs) > 0 {
			msg += fmt.Sprintf(" and working dirs: %s", strings.Join(includeDirs, ", "))
		}
		log.Debug(msg)
		if scanTarget := createScanTarget(rootDir, params.Exclusions(), includeDirs...); scanTarget != nil {
			scanTarget.Technologies = detectTechnologiesInTarget(*scanTarget, params)
			cmdResults.NewScanResults(*scanTarget)
		}
		return
	}
	log.Debug("Creating scan targets from config profile:", configProfile.ProfileName)
	for _, module := range configProfile.Modules {
		moduleRoot := rootDir
		if module.PathFromRoot != "" && module.PathFromRoot != "." {
			moduleRoot = filepath.Join(rootDir, module.PathFromRoot)
		}
		scanTarget := createScanTarget(moduleRoot, module.ExcludePatterns, module.IncludePatterns...)
		if scanTarget == nil {
			continue
		}
		scanTarget.Technologies = detectTechnologiesInTarget(*scanTarget, params)
		scanTarget.CentralConfigModules = []xscServices.Module{module}
		cmdResults.NewScanResults(*scanTarget)
	}
}

// Create a scan target from the given root directory, exclude patterns and optionally include patterns.
func createScanTarget(root string, exclude []string, includes ...string) *results.ScanTarget {
	dirs := datastructures.MakeSet[string]()
	// Validate include patterns
	for _, includePattern := range includes {
		// Check if the include pattern is a file or a directory.
		if isDir, err := fileutils.IsDirExists(includePattern, false); err != nil {
			log.Warn(fmt.Sprintf("Failed to check if '%s' is a directory: %s", includePattern, err.Error()))
			continue
		} else if isDir && !utils.IsPathExcluded(includePattern, exclude) {
			includePath := includePattern
			if !filepath.IsAbs(includePattern) {
				includePath = filepath.Join(root, includePattern)
			}
			dirs.Add(includePath)
			continue
		}
		// the pattern is not a directory, so we need to list the directories in the pattern.
		log.Debug(fmt.Sprintf("The pattern '%s' is not a directory, listing directories in the pattern...", includePattern))
		includeDirs, err := utils.ListDirs(root, includePattern == root, true, true, utils.GetExcludePattern(exclude, utils.DefaultScaExcludePatterns, includePattern == root), includePattern)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to list directories for '%s': %s", includePattern, err.Error()))
			continue
		}
		dirs.AddElements(includeDirs...)
	}
	include := dirs.ToSlice()
	if utils.IsPathExcluded(root, exclude) {
		if len(include) == 0 {
			log.Warn(fmt.Sprintf("The working directory '%s' matches exclusion patterns %s. Skipping...", root, strings.Join(exclude, ", ")))
			return nil
		}
		log.Debug(fmt.Sprintf("Root directory '%s' is excluded; creating scan target from %d explicit include path(s)", root, len(include)))
	}
	return &results.ScanTarget{Target: root, Include: include, Exclude: exclude}
}

func detectTechnologiesInTarget(target results.ScanTarget, otherParams *AuditParams) (technologies []techutils.Technology) {
	detectedTechnologies := datastructures.MakeSet[techutils.Technology]()
	for _, included := range jas.GetRootsFromTarget(target) {
		techToWorkingDirs, err := techutils.DetectTechnologiesDescriptors(included, included == target.Target, otherParams.Technologies(), nil, utils.GetExcludePattern(target.Exclude, utils.DefaultScaExcludePatterns, included == target.Target))
		if err != nil {
			log.Warn(fmt.Sprintf("Couldn't detect technologies in '%s' directory: %s", included, err.Error()))
			continue
		}
		for tech := range techToWorkingDirs {
			detectedTechnologies.Add(tech)
		}
	}
	return detectedTechnologies.ToSlice()
}

func matchCentralConfigModulesForOldFlow(cmdResults *results.SecurityCommandResults, centralProfile *xscServices.ConfigProfile) {
	if centralProfile == nil {
		return
	}
	if len(centralProfile.Modules) < 1 {
		// Verify Modules are not nil and contain at least one modules
		cmdResults.AddGeneralError(fmt.Errorf("config profile %s has no modules. A config profile must contain at least one modules", centralProfile.ProfileName), false)
		return
	}
	log.Debug(fmt.Sprintf("Assigning all (%d) config profile module(s) from '%s' to each of the %d scan target(s)", len(centralProfile.Modules), centralProfile.ProfileName, len(cmdResults.Targets)))
	for _, targetResult := range cmdResults.Targets {
		// TODO: support matching multiple config modules to the scan targets
		// currently only supported one config module for all targets to configure in the UI
		// PathFromRoot is always '.'
		targetResult.CentralConfigModules = centralProfile.Modules
	}
}

// Old flow: creates targets from technologies detected in the working directories.
func detectScaTargetsFromTechnologies(cmdResults *results.SecurityCommandResults, params *AuditParams, cwd string) {
	exclusions := params.Exclusions()
	if configProfile := params.GetConfigProfile(); configProfile != nil {
		// TODO: support matching multiple config modules to the scan targets
		exclusions = append(exclusions, configProfile.Modules[0].ExcludePatterns...)
		exclusions = append(exclusions, configProfile.Modules[0].ScanConfig.ScaScannerConfig.ExcludePatterns...)
	}
	potentialScanTargets := []string{cwd}
	if len(params.workingDirs) > 0 {
		potentialScanTargets = params.workingDirs
	}
	dirsToDetect := []string{}
	for _, requestedDirectory := range potentialScanTargets {
		if !fileutils.IsPathExists(requestedDirectory, false) {
			log.Warn("The working directory", requestedDirectory, "doesn't exist. Skipping SCA scan...")
			continue
		}
		if isExcluded := utils.IsPathExcluded(requestedDirectory, exclusions); isExcluded {
			log.Warn(fmt.Sprintf("The working directory '%s' matches exclusion patterns %s. Skipping...", requestedDirectory, strings.Join(exclusions, ", ")))
			continue
		}
		dirsToDetect = append(dirsToDetect, requestedDirectory)
	}
	for _, requestedDirectory := range dirsToDetect {
		// Detect descriptors and technologies in the requested directory.
		techToWorkingDirs, err := techutils.DetectTechnologiesDescriptors(requestedDirectory, params.IsRecursiveScan(), params.Technologies(), getRequestedDescriptors(params), utils.GetExcludePattern(exclusions, utils.DefaultScaExcludePatterns, params.IsRecursiveScan()))
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
				scanTarget := createScanTarget(requestedDirectory, exclusions)
				if scanTarget == nil {
					continue
				}
				scanTarget.Technologies = []techutils.Technology{tech}
				cmdResults.NewScanResults(*scanTarget)
			}
			for workingDir, descriptors := range workingDirs {
				// Add scan for each detected working directory.
				scanTarget := createScanTarget(workingDir, exclusions)
				if scanTarget == nil {
					continue
				}
				scanTarget.Technologies = []techutils.Technology{tech}
				targetResults := cmdResults.NewScanResults(*scanTarget)
				if tech != techutils.NoTech {
					targetResults.SetDescriptors(descriptors...)
				}
			}
		}
	}
	// If no scan targets were detected, we should still proceed with the scans.
	if len(dirsToDetect) == 1 && params.IsRecursiveScan() && len(cmdResults.Targets) == 0 {
		if scanTarget := createScanTarget(dirsToDetect[0], exclusions); scanTarget != nil {
			cmdResults.NewScanResults(*scanTarget)
		}
	}
	// Load deprecated apps config information for all targets
	if params.DeprecatedAppsConfig() == nil {
		jfrogAppsConfig, err := jas.CreateJFrogAppsConfig(cmdResults.GetTargetsPaths())
		if err != nil {
			cmdResults.AddGeneralError(fmt.Errorf("failed to create JFrogAppsConfig: %s", err.Error()), false)
			return
		}
		params.SetDeprecatedAppsConfig(jfrogAppsConfig)
	}
	for _, targetResult := range cmdResults.Targets {
		targetResult.DeprecatedAppsConfigModule = jas.GetModule(targetResult.Target, params.DeprecatedAppsConfig())
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
	isNewFlow := isNewFlow(auditParams.bomGenerator)
	// Add the scans to the parallel runner
	if jasScanner, generalJasScanErr = addJasScansToRunner(auditParallelRunner, auditParams, cmdResults, isNewFlow); generalJasScanErr != nil {
		cmdResults.AddGeneralError(fmt.Errorf("error has occurred during JAS scan process. JAS scan is skipped for the following directories: %s\n%s", strings.Join(cmdResults.GetTargetsPaths(), ","), generalJasScanErr.Error()), cmdResults.AllowPartialResults)
	}
	if generalScaScanError := addScaScansToRunner(auditParallelRunner, auditParams, cmdResults, isNewFlow); generalScaScanError != nil {
		cmdResults.AddGeneralError(fmt.Errorf("error has occurred during SCA scan process. SCA scan is skipped for the following directories: %s\n%s", strings.Join(cmdResults.GetTargetsPaths(), ","), generalScaScanError.Error()), cmdResults.AllowPartialResults)
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
		// Merge contextual-analysis evidence into the canonical enriched SBOM.
		if e := cmdResults.FinalizeEnrichedSbomsWithApplicability(); e != nil {
			cmdResults.AddGeneralError(fmt.Errorf("failed to finalize enriched SBOMs with applicability: %s", e.Error()), false)
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
			AllowPartialResults: scanResults.AllowPartialResults,
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
	if !scanResults.Entitlements.Jas {
		log.Info("Advanced Security is not enabled on this system, so Advanced Security scans were skipped...")
		return
	}
	if !scanResults.IsJASRequested(auditParams.ScansToPerform()...) {
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
			jas.GetDiffScanTypeValue(auditParams.diffMode, auditParams.resultsToCompare),
			jas.GetAnalyzerManagerXscEnvVars(
				isNewFlow,
				auditParams.GetMultiScanId(),
				auditParams.GetXrayVersion(),
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

	auditParallelRunner.ResultsMu.Unlock()
	if err != nil {
		generalError = fmt.Errorf("failed to create jas scanner: %s", err.Error())
		return
	} else if jasScanner == nil {
		log.Debug("Jas scanner was not created, skipping advance security scans...")
		return
	}
	auditParallelRunner.JasWg.Add(1)
	if _, jasErr := auditParallelRunner.Runner.AddTaskWithError(createJasScansTask(auditParallelRunner, scanResults, serverDetails, auditParams, jasScanner, isNewFlow), func(taskErr error) {
		scanResults.AddGeneralError(fmt.Errorf("failed while adding JAS scan tasks: %s", taskErr.Error()), scanResults.AllowPartialResults)
	}); jasErr != nil {
		generalError = fmt.Errorf("failed to create JAS task: %s", jasErr.Error())
	}
	return
}

func createJasScansTask(auditParallelRunner *utils.SecurityParallelRunner, scanResults *results.SecurityCommandResults,
	serverDetails *config.ServerDetails, auditParams *AuditParams, scanner *jas.JasScanner, isNewFlow bool) parallel.TaskFunc {
	return func(threadId int) (generalError error) {
		defer func() {
			auditParallelRunner.JasWg.Done()
		}()
		// First download the analyzer manager if needed
		if auditParams.customAnalyzerManagerBinaryPath == "" {
			centralConfigDownloadPath := ""
			if auditParams.configProfile != nil {
				centralConfigDownloadPath = auditParams.configProfile.GeneralConfig.ScannersDownloadPath
			}
			if generalError = jas.DownloadAnalyzerManagerIfNeeded(centralConfigDownloadPath, serverDetails, threadId); generalError != nil {
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
			if !isNewFlow && targetResult.DeprecatedAppsConfigModule == nil {
				_ = targetResult.AddTargetError(fmt.Errorf("can't find module for path %s", targetResult.Target), scanResults.AllowPartialResults)
				continue
			}
			params := runner.JasRunnerParams{
				Runner:                 auditParallelRunner,
				ServerDetails:          serverDetails,
				Scanner:                scanner,
				ConfigProfile:          auditParams.GetConfigProfile(),
				ScansToPerform:         auditParams.ScansToPerform(),
				SourceResultsToCompare: scanner.GetResultsToCompareByRelativePath(utils.GetRelativePath(targetResult.Target, scanResults.GetCommonParentPath()), targetResult.Technologies...),
				SecretsScanType:        secrets.SecretsScannerType,
				SecretValidation:       scanResults.SecretValidation && targetResult.ShouldValidateSecrets(slices.Contains(auditParams.ScansToPerform(), utils.SecretTokenValidationScan)),
				CvesProvider: func() (directCves []string, indirectCves []string) {
					if len(targetResult.GetScaScansXrayResults()) > 0 {
						// TODO: remove this once the new SCA flow with cdx is fully implemented.
						return results.ExtractCvesFromScanResponse(targetResult.GetScaScansXrayResults(), results.GetTargetDirectDependencies(targetResult, auditParams.ShouldGetFlatTreeForApplicableScan(targetResult.ScanTarget), true))
					} else if targetResult.ScaResults != nil && targetResult.ScaResults.Sbom != nil {
						return results.ExtractCdxDependenciesCves(targetResult.ScaResults.Sbom)
					}
					return
				},
				ThirdPartyApplicabilityScan: auditParams.thirdPartyApplicabilityScan,
				ApplicableScanType:          applicability.ApplicabilityScannerType,
				SignedDescriptions:          getSignedDescriptions(auditParams.OutputFormat()),
				SastRules:                   auditParams.SastRules(),
				SastChangedFilesMode:        auditParams.SastChangedFilesMode(),
				ChangedFiles:                sast.SastChangedFilesForTarget(scanResults.GitContext, targetResult.Target, getRootDir(auditParams.rootDir, scanResults)),
				ScanResults:                 targetResult,
				TargetCount:                 len(scanResults.Targets),
				TargetOutputDir:             auditParams.scanResultsOutputDir,
				AllowPartialResults:         scanResults.AllowPartialResults,
			}
			if generalError = runner.AddJasScannersTasks(params); generalError != nil {
				_ = targetResult.AddTargetError(fmt.Errorf("failed to add JAS scan tasks: %s", generalError.Error()), scanResults.AllowPartialResults)
				// We assign nil to 'generalError' after handling it to prevent it to propagate further, so it will not be captured twice - once here, and once in the error handling function of createJasScansTasks
				generalError = nil
			}
		}
		return
	}
}

func getRootDir(rootDir string, scanResults *results.SecurityCommandResults) string {
	if rootDir != "" {
		return rootDir
	}
	return scanResults.GetCommonParentPath()
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
		log.Debug("Finished scanning. Uploading scan results to Artifactory")
		if params.GetRtResultRepositoryWithProjectKey() == "" {
			return cmdResults.AddGeneralError(errors.New("results repository was not provided, can't upload scan results to Artifactory"), false)
		}
		if params.Progress() != nil {
			params.Progress().SetHeadlineMsg("Uploading scan results to platform")
		}
		uploadPath, err = uploadCdxResults(params, cmdResults)
		if err != nil {
			return cmdResults.AddGeneralError(fmt.Errorf("failed to upload scan results to Artifactory: %s", err.Error()), false)
		}
		if uiRoute, err := getScanResultsUiRoute(params, uploadPath); err != nil {
			log.Warn(fmt.Sprintf("failed to get scan results UI route: %s", err.Error()))
		} else if uiRoute != "" {
			cmdResults.SetResultsPlatformUrl(uiRoute)
		}
	}
	// Violations fetching
	if cmdResults.HasViolationContext() {
		if params.Progress() != nil {
			params.Progress().SetHeadlineMsg("Fetching violations")
		}
		if err = fetchViolations(uploadPath, cmdResults, params); err != nil {
			cmdResults.AddGeneralError(fmt.Errorf("failed to get violations: %s", err.Error()), cmdResults.AllowPartialResults)
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
	if uploadPath, err = output.UploadCommandResults(serverDetails, auditParams.GetRtResultRepositoryWithProjectKey(), cmdResults); err != nil {
		err = fmt.Errorf("failed to upload scan results to Artifactory: %s", err.Error())
	}
	return
}

func getScanResultsUiRoute(auditParams *AuditParams, uploadPath string) (string, error) {
	if auditParams.GitContext() == nil {
		return "", nil
	}
	serverDetails, err := auditParams.ServerDetails()
	if err != nil {
		return "", fmt.Errorf("failed to get server details: %s", err.Error())
	}
	xrayManager, err := xrayutils.CreateXrayServiceManager(serverDetails, xrayutils.WithScopedProjectKey(auditParams.resultsContext.ProjectKey))
	if err != nil {
		return "", fmt.Errorf("failed to create Xray service manager: %s", err.Error())
	}
	// first in path is the repository (delimiter '/') rest is the path
	if err = artifact.WaitForArtifactScanStatus(xrayManager, strings.Split(uploadPath, "/")[0], strings.Join(strings.Split(uploadPath, "/")[1:], "/"), artifact.ScanStarted()); err != nil {
		return "", fmt.Errorf("failed to wait for artifact scan status: %s", err.Error())
	}
	return xsc.GetScanResultsUiRoute(&xsc.ScanResultsUiRouteParams{
		XrayVersion:            auditParams.GetXrayVersion(),
		ServerDetails:          serverDetails,
		ProjectKey:             auditParams.resultsContext.ProjectKey,
		GitContext:             auditParams.GitContext(),
		ScanResultArtifactPath: uploadPath,
	})
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
		enforcer.WithArtifactParams(auditParams.GetRtResultRepositoryWithProjectKey(), uploadPath),
		enforcer.WithWatches(auditParams.resultsContext.Watches),
		enforcer.WithResultsOutputDir(auditParams.scanResultsOutputDir),
	)
	// Fetch violations from Xray
	if err = policy.EnrichWithGeneratedViolations(generator, cmdResults); err != nil {
		return fmt.Errorf("failed to enrich with violations: %s", err.Error())
	}
	return
}
