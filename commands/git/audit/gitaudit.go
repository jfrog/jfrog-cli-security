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
	gaCmd.SetGitContext(gitInfo)
	// Get the config profile if applicable
	configProfile, err := getJPDConfigProfile(gaCmd.GitAuditParams)
	if err != nil {
		return fmt.Errorf("failed to get config profile: %v", err)
	}
	gaCmd.SetConfigProfile(configProfile)
	// Run the scan
	auditResults := RunGitAudit(gaCmd.GitAuditParams)
	// Process the results and output
	if gaCmd.progress != nil {
		if err = gaCmd.progress.Quit(); err != nil {
			return errors.Join(err, auditResults.GetErrors())
		}
	}
	log.Info("####### jf git audit Scan Finished #######")
	return sourceAudit.OutputResultsAndCmdError(auditResults, gaCmd.getResultWriter(auditResults), gaCmd.failBuild)
}

func getJPDConfigProfile(params GitAuditParams) (*services.ConfigProfile, error) {
	if !params.useConfigProfile {
		// Not using config profile, return nil
		log.Debug("Not using config profile for git audit as requested by the user")
		return nil, nil
	}
	if params.configProfile != nil {
		// Already set, use it
		return params.configProfile, nil
	}
	log.Debug(fmt.Sprintf("Fetching config profile for git repo URL: %s", params.gitContext.Source.GitRepoHttpsCloneUrl))
	configProfile, err := xsc.GetConfigProfileByUrl(params.xrayVersion, params.serverDetails, params.gitContext.Source.GitRepoHttpsCloneUrl, params.resultsContext.ProjectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get config profile for git audit: %v", err)
	}
	return configProfile, verifyConfigProfile(configProfile)
}

func verifyConfigProfile(configProfile *services.ConfigProfile) error {
	if len(configProfile.Modules) != 1 {
		return fmt.Errorf("more than one module was found '%s' profile. Frogbot currently supports only one module per config profile", configProfile.ProfileName)
	}
	if configProfile.Modules[0].PathFromRoot != "." {
		return fmt.Errorf("module '%s' in profile '%s' contains the following path from root: '%s'. Frogbot currently supports only a single module with a '.' path from root", configProfile.Modules[0].ModuleName, configProfile.ProfileName, configProfile.Modules[0].PathFromRoot)
	}
	if profileString, err := utils.GetAsJsonString(configProfile, false, true); err != nil {
		log.Verbose(fmt.Sprintf("Failed to get Config Profile as JSON string: %v", err))
		return nil
	} else {
		log.Verbose(fmt.Sprintf("Utilized Config Profile:\n%s", profileString))
	}
	return nil
}

func DetectGitInfo(wd string) (gitInfo *services.XscGitInfoContext, err error) {
	scmManager, err := scm.DetectScmInProject(wd)
	if err != nil {
		return
	}
	return scmManager.GetSourceControlContext()
}

func toAuditParams(params GitAuditParams) (*sourceAudit.AuditParams, error) {
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
		params.includeSbom,
		params.resultsContext.IncludeSnippetDetection,
	)
	auditParams.SetResultsContext(resultContext)
	log.Debug(fmt.Sprintf("Results context: %+v", resultContext))
	// Source control params
	auditParams.SetGitContext(&params.gitContext).SetMultiScanId(params.multiScanId).SetStartTime(params.startTime)
	// Scan params
	auditParams.SetThreads(params.threads).SetWorkingDirs([]string{params.repositoryLocalPath}).SetExclusions(params.exclusions).SetScansToPerform(params.scansToPerform)
	if params.useConfigProfile {
		auditParams.SetConfigProfile(params.configProfile)
	}
	// Output params
	auditParams.SetScansResultsOutputDir(params.outputDir).SetOutputFormat(params.outputFormat)
	auditParams.SetUploadCdxResults(params.uploadResults).SetRtResultRepository(params.rtResultRepository)
	// Cmd information
	auditParams.SetBomGenerator(params.bomGenerator).SetScaScanStrategy(params.scaScanStrategy).SetViolationGenerator(params.violationGenerator)
	auditParams.SetCustomBomGenBinaryPath(params.customBomGenBinaryPath).SetCustomAnalyzerManagerBinaryPath(params.customAnalyzerManagerBinaryPath)
	// Basic params
	_, includeDirs, isRecursiveScan, err := sourceAudit.GetTargetsInfo(params.workingDirs, params.bomGenerator, params.scansToPerform, params.includeSbom, params.repositoryLocalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get targets info: %v", err)
	}
	auditParams.SetWorkingDirs(includeDirs).SetUseJas(true).SetIsRecursiveScan(isRecursiveScan)
	return auditParams, nil
}

func RunGitAudit(params GitAuditParams) (scanResults *results.SecurityCommandResults) {
	// Send scan started event
	event := xsc.CreateAnalyticsEvent(services.CliProduct, services.CliEventType, params.serverDetails, params.repositoryLocalPath)
	event.GitInfo = &params.gitContext
	event.IsGitInfoFlow = true
	multiScanId, startTime := xsc.SendNewScanEvent(
		params.xrayVersion,
		params.xscVersion,
		params.serverDetails,
		event,
		params.GetProjectKey(),
	)
	params.multiScanId = multiScanId
	params.startTime = startTime
	// Run the scan
	auditParams, err := toAuditParams(params)
	if err != nil {
		return scanResults.AddGeneralError(err, false)
	}
	scanResults = sourceAudit.RunAudit(auditParams)
	// Send scan ended event
	xsc.SendScanEndedWithResults(params.serverDetails, scanResults)
	return scanResults
}

func (gaCmd *GitAuditCommand) getResultWriter(cmdResults *results.SecurityCommandResults) *output.ResultsWriter {
	var messages []string
	if !cmdResults.Entitlements.Jas {
		messages = []string{coreutils.PrintTitle("In addition to SCA, the ‘jf git audit’ command supports the following Advanced Security scans: 'Contextual Analysis', 'Secrets Detection', 'IaC', and ‘SAST’.\nThese scans are available within Advanced Security license. Read more - ") + coreutils.PrintLink(utils.JasInfoURL)}
	}
	if cmdResults.ResultsPlatformUrl != "" {
		messages = append(messages, output.GetCommandResultsPlatformUrlMessage(cmdResults, true))
	}
	return output.NewResultsWriter(cmdResults).
		SetOutputFormat(gaCmd.outputFormat).
		SetOutputDir(gaCmd.outputDir).
		SetPrintExtendedTable(gaCmd.extendedTable).
		SetExtraMessages(messages).
		SetSubScansPerformed(gaCmd.scansToPerform)
}
