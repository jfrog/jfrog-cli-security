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
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/gitutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
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
	// Detect git info
	_, gitInfo, err := DetectGitInfo()
	if err != nil {
		return
	}
	if gitInfo == nil {
		// No Error but no git info = project is dirty
		return fmt.Errorf("failed to get git context from dirty project")
	}
	gaCmd.source = *gitInfo
	// Run the scan
	auditResults := RunGitAudit(gaCmd.GitAuditParams)
	// Process the results and output
	if gaCmd.progress != nil {
		if err = gaCmd.progress.Quit(); err != nil {
			return errors.Join(err, auditResults.GetErrors())
		}
	}
	return sourceAudit.ProcessResultsAndOutput(auditResults, gaCmd.getResultWriter(auditResults), gaCmd.failBuild)
}

func DetectGitInfo() (gitManager *gitutils.GitManager, gitInfo *services.XscGitInfoContext, err error) {
	gitManager, err = gitutils.NewGitManager(".")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to found local git repository at the current directory: %v", err)
	}
	gitInfo, err = gitManager.GetGitContext()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get git context: %v", err)
	}
	if gitInfo == nil {
		log.Warn("Failed to get git context: defaulting to audit command.")
		return nil, nil, nil
	}
	return
}

func toAuditParams(params GitAuditParams) *sourceAudit.AuditParams {
	auditParams := sourceAudit.NewAuditParams()
	// Connection params
	auditParams.SetServerDetails(params.serverDetails).SetInsecureTls(params.serverDetails.InsecureTls).SetXrayVersion(params.xrayVersion).SetXscVersion(params.xscVersion)
	// Violations params
	auditParams.SetResultsContext(params.resultsContext)
	// Scan params
	auditParams.SetThreads(params.threads).SetExclusions(params.exclusions).SetScansToPerform(params.scansToPerform)
	// Output params
	auditParams.SetOutputFormat(params.outputFormat)
	// Cmd information
	auditParams.SetMultiScanId(params.multiScanId).SetStartTime(params.startTime)
	// Basic params
	auditParams.SetIsRecursiveScan(true)
	return auditParams
}

func RunGitAudit(params GitAuditParams) (scanResults *results.SecurityCommandResults) {
	// Send scan started event
	multiScanId, startTime := xsc.SendNewScanEvent(
		params.xrayVersion,
		params.xscVersion,
		params.serverDetails,
		xsc.CreateAnalyticsEvent(services.CliProduct, services.CliEventType, params.serverDetails),
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
		messages = []string{coreutils.PrintTitle("The ‘jf git audit’ command also supports JFrog Advanced Security features, such as 'Contextual Analysis', 'Secret Detection', 'IaC Scan' and ‘SAST’.\nThis feature isn't enabled on your system. Read more - ") + coreutils.PrintLink(utils.JasInfoURL)}
	}
	return output.NewResultsWriter(cmdResults).
		SetOutputFormat(gaCmd.outputFormat).
		SetPrintExtendedTable(gaCmd.extendedTable).
		SetExtraMessages(messages).
		SetSubScansPerformed(gaCmd.scansToPerform)
}
