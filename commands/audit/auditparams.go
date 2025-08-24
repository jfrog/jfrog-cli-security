package audit

import (
	"time"

	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/scan"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type AuditParams struct {
	// Common params to all scan routines
	resultsContext    results.ResultContext
	gitContext *xscServices.XscGitInfoContext
	workingDirs       []string
	installFunc       func(tech string) error
	fixableOnly       bool
	minSeverityFilter severityutils.Severity
	*xrayutils.AuditBasicParams
	multiScanId string
	// Include third party dependencies source code in the applicability scan.
	thirdPartyApplicabilityScan bool
	threads                     int
	scanResultsOutputDir        string
	startTime                   time.Time
	// Dynamic logic params
	customAnalyzerManagerBinaryPath string
	bomGenerator                    bom.SbomGenerator
	customBomGenBinaryPath          string
	scaScanStrategy                 scan.SbomScanStrategy
	// Diff mode, scan only the files affected by the diff.
	diffMode         bool
	filesToScan      []string
	resultsToCompare *results.SecurityCommandResults
}

func NewAuditParams() *AuditParams {
	return &AuditParams{
		AuditBasicParams: &xrayutils.AuditBasicParams{},
	}
}

func (params *AuditParams) SetGitContext(gitContext *xscServices.XscGitInfoContext) *AuditParams {
	params.gitContext = gitContext
	return params
}

func (params *AuditParams) GitContext() *xscServices.XscGitInfoContext {
	return params.gitContext
}

func (params *AuditParams) InstallFunc() func(tech string) error {
	return params.installFunc
}

func (params *AuditParams) WorkingDirs() []string {
	return params.workingDirs
}

func (params *AuditParams) SetMultiScanId(msi string) *AuditParams {
	params.multiScanId = msi
	return params
}

func (params *AuditParams) GetMultiScanId() string {
	return params.multiScanId
}

func (params *AuditParams) SetBomGenerator(bomGenerator bom.SbomGenerator) *AuditParams {
	params.bomGenerator = bomGenerator
	return params
}

func (params *AuditParams) BomGenerator() bom.SbomGenerator {
	return params.bomGenerator
}

func (params *AuditParams) SetCustomBomGenBinaryPath(customBomGenBinaryPath string) *AuditParams {
	params.customBomGenBinaryPath = customBomGenBinaryPath
	return params
}

func (params *AuditParams) CustomBomGenBinaryPath() string {
	return params.customBomGenBinaryPath
}

func (params *AuditParams) SetCustomAnalyzerManagerBinaryPath(customAnalyzerManagerBinaryPath string) *AuditParams {
	params.customAnalyzerManagerBinaryPath = customAnalyzerManagerBinaryPath
	return params
}

func (params *AuditParams) CustomAnalyzerManagerBinaryPath() string {
	return params.customAnalyzerManagerBinaryPath
}

func (params *AuditParams) SetScaScanStrategy(scaScanStrategy scan.SbomScanStrategy) *AuditParams {
	params.scaScanStrategy = scaScanStrategy
	return params
}

func (params *AuditParams) ScaScanStrategy() scan.SbomScanStrategy {
	return params.scaScanStrategy
}

func (params *AuditParams) SetStartTime(startTime time.Time) *AuditParams {
	params.startTime = startTime
	return params
}

func (params *AuditParams) StartTime() time.Time {
	return params.startTime
}

func (params *AuditParams) SetGraphBasicParams(gbp *xrayutils.AuditBasicParams) *AuditParams {
	params.AuditBasicParams = gbp
	return params
}

func (params *AuditParams) SetWorkingDirs(workingDirs []string) *AuditParams {
	params.workingDirs = workingDirs
	return params
}

func (params *AuditParams) SetInstallFunc(installFunc func(tech string) error) *AuditParams {
	params.installFunc = installFunc
	return params
}

func (params *AuditParams) FixableOnly() bool {
	return params.fixableOnly
}

func (params *AuditParams) SetFixableOnly(fixable bool) *AuditParams {
	params.fixableOnly = fixable
	return params
}

func (params *AuditParams) MinSeverityFilter() severityutils.Severity {
	return params.minSeverityFilter
}

func (params *AuditParams) SetMinSeverityFilter(minSeverityFilter severityutils.Severity) *AuditParams {
	params.minSeverityFilter = minSeverityFilter
	return params
}

func (params *AuditParams) SetThirdPartyApplicabilityScan(includeThirdPartyDeps bool) *AuditParams {
	params.thirdPartyApplicabilityScan = includeThirdPartyDeps
	return params
}

func (params *AuditParams) SetDepsRepo(depsRepo string) *AuditParams {
	params.AuditBasicParams.SetDepsRepo(depsRepo)
	return params
}

func (params *AuditParams) SetThreads(threads int) *AuditParams {
	params.threads = threads
	return params
}

func (params *AuditParams) SetResultsContext(resultsContext results.ResultContext) *AuditParams {
	params.resultsContext = resultsContext
	return params
}

func (params *AuditParams) SetScansResultsOutputDir(outputDir string) *AuditParams {
	params.scanResultsOutputDir = outputDir
	return params
}

func (params *AuditParams) createXrayGraphScanParams() *services.XrayGraphScanParams {
	return &services.XrayGraphScanParams{
		RepoPath:               params.resultsContext.RepoPath,
		Watches:                params.resultsContext.Watches,
		ProjectKey:             params.resultsContext.ProjectKey,
		GitRepoHttpsCloneUrl:   params.resultsContext.GitRepoHttpsCloneUrl,
		IncludeVulnerabilities: params.resultsContext.IncludeVulnerabilities,
		IncludeLicenses:        params.resultsContext.IncludeLicenses,
		ScanType:               services.Dependency,
	}
}

func (params *AuditParams) ToBuildInfoBomGenParams() (bomParams technologies.BuildInfoBomGeneratorParams, err error) {
	serverDetails, err := params.AuditBasicParams.ServerDetails()
	if err != nil {
		return
	}
	bomParams = technologies.BuildInfoBomGeneratorParams{
		XrayVersion:         params.GetXrayVersion(),
		Progress:            params.Progress(),
		ExclusionPattern:    technologies.GetExcludePattern(params.GetConfigProfile(), params.IsRecursiveScan(), params.Exclusions()...),
		AllowPartialResults: params.AllowPartialResults(),
		// Artifactory repository info
		ServerDetails:          serverDetails,
		DependenciesRepository: params.DepsRepo(),
		IgnoreConfigFile:       params.IgnoreConfigFile(),
		InsecureTls:            params.InsecureTls(),
		// Install params
		SkipAutoInstall:    params.SkipAutoInstall(),
		InstallCommandName: params.InstallCommandName(),
		Args:               params.Args(),
		InstallCommandArgs: params.InstallCommandArgs(),
		// Curation params
		IsCurationCmd: params.IsCurationCmd(),
		// Java params
		IsMavenDepTreeInstalled: params.IsMavenDepTreeInstalled(),
		UseWrapper:              params.UseWrapper(),
		// Python params
		PipRequirementsFile: params.PipRequirementsFile(),
		// Pnpm params
		MaxTreeDepth: params.MaxTreeDepth(),
	}
	return
}

func (params *AuditParams) ToXrayScanGraphParams() (scanGraphParams scangraph.ScanGraphParams, err error) {
	serverDetails, err := params.ServerDetails()
	if err != nil {
		return
	}
	// Create the scan graph parameters.
	xrayScanGraphParams := params.createXrayGraphScanParams()
	xrayScanGraphParams.MultiScanId = params.GetMultiScanId()
	xrayScanGraphParams.XrayVersion = params.GetXrayVersion()
	xrayScanGraphParams.XscVersion = params.GetXscVersion()
	xrayScanGraphParams.IncludeLicenses = params.resultsContext.IncludeLicenses

	scanGraphParams = *scangraph.NewScanGraphParams().
		SetServerDetails(serverDetails).
		SetXrayGraphScanParams(xrayScanGraphParams).
		SetFixableOnly(params.fixableOnly).
		SetSeverityLevel(params.minSeverityFilter.String())
	return
}

func (params *AuditParams) SetFilesToScan(filesToScan []string) *AuditParams {
	params.filesToScan = filesToScan
	return params
}

func (params *AuditParams) FilesToScan() []string {
	return params.filesToScan
}

func (params *AuditParams) SetResultsToCompare(resultsToCompare *results.SecurityCommandResults) *AuditParams {
	params.resultsToCompare = resultsToCompare
	return params
}

func (params *AuditParams) ResultsToCompare() *results.SecurityCommandResults {
	return params.resultsToCompare
}

func (params *AuditParams) SetDiffMode(diffMode bool) *AuditParams {
	params.diffMode = diffMode
	return params
}

func (params *AuditParams) DiffMode() bool {
	return params.diffMode
}

// When building pip dependency tree using pipdeptree, some of the direct dependencies are recognized as transitive and missed by the CA scanner.
// Our solution for this case is to send all dependencies to the CA scanner.
// When thirdPartyApplicabilityScan is true, use flatten graph to include all the dependencies in applicability scanning.
// Only npm is supported for this flag.
func (params *AuditParams) ShouldGetFlatTreeForApplicableScan(tech techutils.Technology) bool {
	if params.bomGenerator == nil {
		return false
	}
	// Check if bomGenerator is BuildInfo type, if not, return false
	if _, success := params.bomGenerator.(*buildinfo.BuildInfoBomGenerator); !success {
		return false
	}
	return tech == techutils.Pip || (params.thirdPartyApplicabilityScan && tech == techutils.Npm)
}
