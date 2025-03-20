package audit

import (
	"time"

	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type AuditParams struct {
	// Common params to all scan routines
	resultsContext    results.ResultContext
	workingDirs       []string
	installFunc       func(tech string) error
	fixableOnly       bool
	minSeverityFilter severityutils.Severity
	*xrayutils.AuditBasicParams
	multiScanId string
	// Include third party dependencies source code in the applicability scan.
	thirdPartyApplicabilityScan bool
	threads                     int
	configProfile               *xscservices.ConfigProfile
	scanResultsOutputDir        string
	startTime                   time.Time
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

func (params *AuditParams) SetConfigProfile(configProfile *xscservices.ConfigProfile) *AuditParams {
	params.configProfile = configProfile
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
