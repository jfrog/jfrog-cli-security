package audit

import (
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

type GitAuditParams struct {
	// Git Params
	gitContext services.XscGitInfoContext
	// Connection params
	serverDetails *config.ServerDetails
	// Violations params
	resultsContext results.ResultContext
	failBuild      bool
	// Scan params
	scansToPerform []utils.SubScanType
	threads        int
	exclusions     []string
	// Output params
	outputFormat  format.OutputFormat
	extendedTable bool
	outputDir     string
	// Cmd information (not params, set by the cmd)
	xrayVersion         string
	xscVersion          string
	repositoryLocalPath string
	multiScanId         string
	startTime           time.Time
	// Dynamic logic params
	bomGenerator       bom.SbomGenerator
	scaScanStrategy    scan.SbomScanStrategy
	violationGenerator policy.PolicyHandler
	uploadResults      bool
	rtResultRepository string
	remediationService bool
}

func NewGitAuditParams() *GitAuditParams {
	return &GitAuditParams{}
}

func (gap *GitAuditParams) SetServerDetails(serverDetails *config.ServerDetails) *GitAuditParams {
	gap.serverDetails = serverDetails
	return gap
}

func (gap *GitAuditParams) SetWatches(watches []string) *GitAuditParams {
	gap.resultsContext.Watches = watches
	return gap
}

func (gap *GitAuditParams) SetProjectKey(project string) *GitAuditParams {
	gap.resultsContext.ProjectKey = project
	return gap
}

func (gap *GitAuditParams) SetFailBuild(failBuild bool) *GitAuditParams {
	gap.failBuild = failBuild
	return gap
}

func (gap *GitAuditParams) SetIncludeLicenses(includeLicenses bool) *GitAuditParams {
	gap.resultsContext.IncludeLicenses = includeLicenses
	return gap
}

func (gap *GitAuditParams) SetIncludeVulnerabilities(includeVulnerabilities bool) *GitAuditParams {
	gap.resultsContext.IncludeVulnerabilities = includeVulnerabilities
	return gap
}

func (gap *GitAuditParams) SetScansToPerform(scansToPerform []utils.SubScanType) *GitAuditParams {
	gap.scansToPerform = scansToPerform
	return gap
}

func (gap *GitAuditParams) SetOutputFormat(outputFormat format.OutputFormat) *GitAuditParams {
	gap.outputFormat = outputFormat
	return gap
}

func (gap *GitAuditParams) SetExtendedTable(extendedTable bool) *GitAuditParams {
	gap.extendedTable = extendedTable
	return gap
}

func (gap *GitAuditParams) SetXrayVersion(xrayVersion string) *GitAuditParams {
	gap.xrayVersion = xrayVersion
	return gap
}

func (gap *GitAuditParams) SetXscVersion(xscVersion string) *GitAuditParams {
	gap.xscVersion = xscVersion
	return gap
}

func (gap *GitAuditParams) SetMultiScanId(multiScanId string) *GitAuditParams {
	gap.multiScanId = multiScanId
	return gap
}

func (gap *GitAuditParams) SetStartTime(startTime time.Time) *GitAuditParams {
	gap.startTime = startTime
	return gap
}

func (gap *GitAuditParams) SetThreads(threads int) *GitAuditParams {
	gap.threads = threads
	return gap
}

func (gap *GitAuditParams) SetExclusions(exclusions []string) *GitAuditParams {
	gap.exclusions = exclusions
	return gap
}

func (gap *GitAuditParams) SetSbomGenerator(generator bom.SbomGenerator) *GitAuditParams {
	gap.bomGenerator = generator
	return gap
}

func (gap *GitAuditParams) SetScaScanStrategy(scaScanStrategy scan.SbomScanStrategy) *GitAuditParams {
	gap.scaScanStrategy = scaScanStrategy
	return gap
}

func (gap *GitAuditParams) SetOutputDir(outputDir string) *GitAuditParams {
	gap.outputDir = outputDir
	return gap
}

func (gap *GitAuditParams) SetViolationGenerator(violationGenerator policy.PolicyHandler) *GitAuditParams {
	gap.violationGenerator = violationGenerator
	return gap
}

func (gap *GitAuditParams) ViolationGenerator() policy.PolicyHandler {
	return gap.violationGenerator
}

func (gap *GitAuditParams) SetUploadCdxResults(uploadCdxResults bool) *GitAuditParams {
	gap.uploadResults = uploadCdxResults
	return gap
}

func (gap *GitAuditParams) UploadCdxResults() bool {
	return gap.uploadResults
}

func (gap *GitAuditParams) SetRtResultRepository(rtResultRepository string) *GitAuditParams {
	gap.rtResultRepository = rtResultRepository
	return gap
}

func (gap *GitAuditParams) RtResultRepository() string {
	return gap.rtResultRepository
}

func (gap *GitAuditParams) SetRemediationService(remediationService bool) *GitAuditParams {
	gap.remediationService = remediationService
	return gap
}

func (gap *GitAuditParams) RemediationService() bool {
	return gap.remediationService
}
