package audit

import (
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-client-go/xray/services"
	clientservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type AuditParams struct {
	// Common params to all scan routines
	commonGraphScanParams *scangraph.CommonGraphScanParams
	workingDirs           []string
	installFunc           func(tech string) error
	fixableOnly           bool
	minSeverityFilter     severityutils.Severity
	*xrayutils.AuditBasicParams
	xrayVersion string
	// Include third party dependencies source code in the applicability scan.
	thirdPartyApplicabilityScan bool
	threads                     int
	configProfile               *clientservices.ConfigProfile
	scanResultsOutputDir        string
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

func (params *AuditParams) XrayVersion() string {
	return params.xrayVersion
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

func (params *AuditParams) SetCommonGraphScanParams(commonParams *scangraph.CommonGraphScanParams) *AuditParams {
	params.commonGraphScanParams = commonParams
	return params
}

func (params *AuditParams) SetConfigProfile(configProfile *clientservices.ConfigProfile) *AuditParams {
	params.configProfile = configProfile
	return params
}

func (params *AuditParams) SetScansResultsOutputDir(outputDir string) *AuditParams {
	params.scanResultsOutputDir = outputDir
	return params
}

func (params *AuditParams) createXrayGraphScanParams() *services.XrayGraphScanParams {
	return &services.XrayGraphScanParams{
		RepoPath:               params.commonGraphScanParams.RepoPath,
		Watches:                params.commonGraphScanParams.Watches,
		ScanType:               params.commonGraphScanParams.ScanType,
		ProjectKey:             params.commonGraphScanParams.ProjectKey,
		IncludeVulnerabilities: params.commonGraphScanParams.IncludeVulnerabilities,
		IncludeLicenses:        params.commonGraphScanParams.IncludeLicenses,
		XscVersion:             params.commonGraphScanParams.XscVersion,
		MultiScanId:            params.commonGraphScanParams.MultiScanId,
	}
}
