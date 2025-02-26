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

func DetectGitInfo(wd string) (gitInfo *services.XscGitInfoContext, err error) {
	scmManager, err := scm.DetectScmInProject(wd)
	if err != nil {
		return
	}
	return scmManager.GetSourceControlContext()
}

func toAuditParams(params GitAuditParams, changes *scm.DiffContent) *sourceAudit.AuditParams {
	auditParams := sourceAudit.NewAuditParams()
	// Connection params
	auditParams.SetServerDetails(params.serverDetails).SetInsecureTls(params.serverDetails.InsecureTls).SetXrayVersion(params.xrayVersion).SetXscVersion(params.xscVersion)
	// Violations params
	auditParams.SetResultsContext(sourceAudit.CreateAuditResultsContext(
		params.serverDetails,
		params.xrayVersion,
		params.resultsContext.Watches,
		params.resultsContext.RepoPath,
		params.resultsContext.ProjectKey,
		params.source.GitRepoHttpsCloneUrl,
		params.resultsContext.IncludeVulnerabilities,
		params.resultsContext.IncludeLicenses,
		false,
	))
	// Scan params
	auditParams.SetThreads(params.threads).SetWorkingDirs([]string{params.repositoryLocalPath}).SetExclusions(params.exclusions).SetScansToPerform(params.scansToPerform)
	if changes != nil && changes.HasChanges() {
		if changedPaths := changes.GetChangedFilesPaths(); len(changedPaths) > 0 {
			log.Debug(fmt.Sprintf("Diff targets: %v", changedPaths))
			auditParams.SetFilesToScan(changedPaths)
		}
	}
	// Output params
	auditParams.SetOutputFormat(params.outputFormat)
	// Cmd information
	auditParams.SetMultiScanId(params.multiScanId).SetStartTime(params.startTime)
	// Basic params
	auditParams.SetUseJas(true).SetIsRecursiveScan(true)
	return auditParams
}

func RunGitAudit(params GitAuditParams) (scanResults *results.SecurityCommandResults) {
	// Get diff targets to scan if needed
	diffTargets, err := getDiffTargets(params)
	if err != nil {
		return results.NewCommandResults(utils.SourceCode).AddGeneralError(err, false)
	}
	if diffTargets != nil && !diffTargets.HasChanges() {
		log.Warn("No relevant changes detected in the diff, nothing to scan")
		// Set entitled to avoid printing extra messages
		return results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true)
	}
	log.Debug(fmt.Sprintf("Diff targets: %v", diffTargets))
	return results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true)
	// Send scan started event
	event := xsc.CreateAnalyticsEvent(services.CliProduct, services.CliEventType, params.serverDetails)
	event.GitInfo = &params.source
	event.IsGitInfoFlow = true
	multiScanId, startTime := xsc.SendNewScanEvent(
		params.xrayVersion,
		params.xscVersion,
		params.serverDetails,
		event,
	)
	params.multiScanId = multiScanId
	params.startTime = startTime
	// Run the scan and filter results not in diff
	scanResults = filterResultsNotInDiff(sourceAudit.RunAudit(toAuditParams(params, diffTargets)), diffTargets)
	// Send scan ended event
	xsc.SendScanEndedWithResults(params.serverDetails, scanResults)
	return scanResults
}

func getDiffTargets(params GitAuditParams) (diffTargets *scm.DiffContent, err error) {
	if params.diffTarget == "" {
		return
	}
	gitManager, err := scm.NewGitManager(params.repositoryLocalPath)
	if err != nil {
		return
	}
	if params.commonAncestor, err = gitManager.GetCommonAncestor(params.diffTarget); err != nil {
		return
	}
	if params.source.LastCommitHash == params.commonAncestor {
		// TODO: talk with technical writer about this error message
		err = fmt.Errorf("the target commit must share a common ancestor with the source commit, but the common ancestor cannot be the source commit itself")
		return
	}
	log.Info(fmt.Sprintf("Diff mode: comparing '%s' against target '%s' (common ancestor '%s')", params.source.LastCommitHash, params.diffTarget, params.commonAncestor))
	if changes, err := gitManager.DiffGetRemovedContent(params.commonAncestor); err == nil {
		diffTargets = &changes
	}
	return
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
