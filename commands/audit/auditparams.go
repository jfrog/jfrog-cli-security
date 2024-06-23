package audit

import (
	"github.com/jfrog/jfrog-cli-security/scangraph"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type AuditParams struct {
	// Common params to all scan routines
	commonGraphScanParams *scangraph.CommonGraphScanParams
	workingDirs           []string
	installFunc           func(tech string) error
	fixableOnly           bool
	minSeverityFilter     string
	*xrayutils.AuditBasicParams
	xrayVersion string
	// Include third party dependencies source code in the applicability scan.
	thirdPartyApplicabilityScan bool
	threads                     int
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

func (params *AuditParams) MinSeverityFilter() string {
	return params.minSeverityFilter
}

func (params *AuditParams) SetMinSeverityFilter(minSeverityFilter string) *AuditParams {
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
