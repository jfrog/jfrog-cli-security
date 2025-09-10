package audit

import (
	"errors"
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"

	sourceAudit "github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/scm"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
)

type GitAuditCommand struct {
	GitAuditParams
	progress ioUtils.ProgressMgr
}

func NewGitAuditCommand() *GitAuditCommand {
	return &GitAuditCommand{}
}

func (gaCmd *GitAuditCommand) CommandName() string {
	return "git_audit"
}

func (gaCmd *GitAuditCommand) SetProgress(progress ioUtils.ProgressMgr) {
	gaCmd.progress = progress
}

func (gaCmd *GitAuditCommand) ServerDetails() (*config.ServerDetails, error) {
	return gaCmd.serverDetails, nil
}

func (gaCmd *GitAuditCommand) Run() (err error) {
	if gaCmd.repositoryLocalPath, err = coreutils.GetWorkingDirectory(); err != nil {
		return
	}
	// Detect git info
	gitInfo, err := DetectGitInfo(gaCmd.repositoryLocalPath)
	if err != nil {
		return fmt.Errorf("failed to get source control context: %v", err)
	}
	if gitInfo == nil {
		// No Error but no git info = project working tree is dirty
		return fmt.Errorf("detected uncommitted changes in '%s'. Please commit your changes and try again", gaCmd.repositoryLocalPath)
	}
	gaCmd.gitContext = *gitInfo
	// Run the scan
	auditResults := RunGitAudit(gaCmd.GitAuditParams)
	// Process the results and output
	if gaCmd.progress != nil {
		if err = gaCmd.progress.Quit(); err != nil {
			return errors.Join(err, auditResults.GetErrors())
		}
	}
	return sourceAudit.OutputResultsAndCmdError(auditResults, gaCmd.getResultWriter(auditResults), gaCmd.failBuild)
}

func DetectGitInfo(wd string) (gitInfo *services.XscGitInfoContext, err error) {
	scmManager, err := scm.DetectScmInProject(wd)
	if err != nil {
		return
	}
	return scmManager.GetSourceControlContext()
}

func toAuditParams(params GitAuditParams) *sourceAudit.AuditParams {
	auditParams := sourceAudit.NewAuditParams()
	// Connection params
	auditParams.SetServerDetails(params.serverDetails).SetInsecureTls(params.serverDetails.InsecureTls).SetXrayVersion(params.xrayVersion).SetXscVersion(params.xscVersion)
	// Violations params
	resultContext := sourceAudit.CreateAuditResultsContext(
		params.serverDetails,
		params.xrayVersion,
		params.resultsContext.Watches,
		params.resultsContext.RepoPath,
		params.resultsContext.ProjectKey,
		params.gitContext.Source.GitRepoHttpsCloneUrl,
		params.resultsContext.IncludeVulnerabilities,
		params.resultsContext.IncludeLicenses,
		false,
	)
	auditParams.SetResultsContext(resultContext)
	log.Debug(fmt.Sprintf("Results context: %+v", resultContext))
	// Source control params
	auditParams.SetGitContext(&params.gitContext).SetMultiScanId(params.multiScanId).SetStartTime(params.startTime)
	// Scan params
	auditParams.SetThreads(params.threads).SetWorkingDirs([]string{params.repositoryLocalPath}).SetExclusions(params.exclusions).SetScansToPerform(params.scansToPerform)
	// Output params
	auditParams.SetScansResultsOutputDir(params.outputDir).SetOutputFormat(params.outputFormat)
	auditParams.SetUploadCdxResults(params.uploadResults).SetRtResultRepository(params.rtResultRepository)
	// Cmd information
	auditParams.SetBomGenerator(params.bomGenerator).SetScaScanStrategy(params.scaScanStrategy).SetViolationGenerator(params.violationGenerator).SetRemediationService(params.remediationService)
	// Basic params
	isRecursiveScan := true
	if _, ok := params.bomGenerator.(*xrayplugin.XrayLibBomGenerator); ok {
		// 'Xray lib' BOM generator supports only one working directory, no recursive scan (single target)
		isRecursiveScan = false
	}
	auditParams.SetUseJas(true).SetIsRecursiveScan(isRecursiveScan)
	return auditParams
}

func RunGitAudit(params GitAuditParams) (scanResults *results.SecurityCommandResults) {
	// Send scan started event
	event := xsc.CreateAnalyticsEvent(services.CliProduct, services.CliEventType, params.serverDetails)
	event.GitInfo = &params.gitContext
	event.IsGitInfoFlow = true
	multiScanId, startTime := xsc.SendNewScanEvent(
		params.xrayVersion,
		params.xscVersion,
		params.serverDetails,
		event,
	)
	params.multiScanId = multiScanId
	params.startTime = startTime
	// Run the scan
	scanResults = sourceAudit.RunAudit(toAuditParams(params))
	// Send scan ended event
	xsc.SendScanEndedWithResults(params.serverDetails, scanResults)
	return scanResults
}

func (gaCmd *GitAuditCommand) getResultWriter(cmdResults *results.SecurityCommandResults) *output.ResultsWriter {
	var messages []string
	if !cmdResults.EntitledForJas {
		messages = []string{coreutils.PrintTitle("The ‘jf git audit’ command also supports JFrog Advanced Security features, such as 'Contextual Analysis', 'Secrets Detection', 'IaC Scan' and ‘SAST’.\nThis feature isn't enabled on your system. Read more - ") + coreutils.PrintLink(utils.JasInfoURL)}
	}
	return output.NewResultsWriter(cmdResults).
		SetOutputFormat(gaCmd.outputFormat).
		SetOutputDir(gaCmd.outputDir).
		SetPrintExtendedTable(gaCmd.extendedTable).
		SetExtraMessages(messages).
		SetSubScansPerformed(gaCmd.scansToPerform)
}
