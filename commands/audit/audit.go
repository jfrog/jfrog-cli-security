package audit

import (
	"errors"
	"fmt"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas"
	"github.com/jfrog/jfrog-cli-security/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type AuditCommand struct {
	watches                []string
	projectKey             string
	targetRepoPath         string
	IncludeVulnerabilities bool
	IncludeLicenses        bool
	Fail                   bool
	PrintExtendedTable     bool
	ParallelScans          int
	AuditParams
}

type CommonCommandParams struct {
	watches                []string
	projectKey             string
	targetRepoPath         string
	IncludeVulnerabilities bool
	IncludeLicenses        bool
}

func NewGenericAuditCommand() *AuditCommand {
	return &AuditCommand{AuditParams: *NewAuditParams()}
}

func (auditCmd *AuditCommand) SetWatches(watches []string) *AuditCommand {
	auditCmd.watches = watches
	return auditCmd
}

func (auditCmd *AuditCommand) SetProject(project string) *AuditCommand {
	auditCmd.projectKey = project
	return auditCmd
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

func (auditCmd *AuditCommand) SetFail(fail bool) *AuditCommand {
	auditCmd.Fail = fail
	return auditCmd
}

func (auditCmd *AuditCommand) SetPrintExtendedTable(printExtendedTable bool) *AuditCommand {
	auditCmd.PrintExtendedTable = printExtendedTable
	return auditCmd
}

func (auditCmd *AuditCommand) SetParallelScans(threads int) *AuditCommand {
	auditCmd.ParallelScans = threads
	return auditCmd
}

func (auditCmd *AuditCommand) CreateCommonCommandParams() *CommonCommandParams {
	commonParams := &CommonCommandParams{
		watches:                auditCmd.watches,
		projectKey:             auditCmd.projectKey,
		targetRepoPath:         auditCmd.targetRepoPath,
		IncludeVulnerabilities: auditCmd.IncludeVulnerabilities,
		IncludeLicenses:        auditCmd.IncludeLicenses,
	}
	return commonParams
}

func (auditCmd *AuditCommand) Run() (err error) {
	// If no workingDirs were provided by the user, we apply a recursive scan on the root repository
	isRecursiveScan := len(auditCmd.workingDirs) == 0
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(auditCmd.workingDirs)
	if err != nil {
		return
	}

	auditParams := NewAuditParams().
		SetWorkingDirs(workingDirs).
		SetMinSeverityFilter(auditCmd.minSeverityFilter).
		SetFixableOnly(auditCmd.fixableOnly).
		SetGraphBasicParams(auditCmd.AuditBasicParams).
		SetCommonCommandParams(auditCmd.CreateCommonCommandParams()).
		SetThirdPartyApplicabilityScan(auditCmd.thirdPartyApplicabilityScan).
		SetParallelScans(auditCmd.ParallelScans)
	auditParams.SetIsRecursiveScan(isRecursiveScan).SetExclusions(auditCmd.Exclusions())
	auditResults, err := RunAudit(auditParams)
	if err != nil {
		return
	}
	if auditCmd.Progress() != nil {
		if err = auditCmd.Progress().Quit(); err != nil {
			return
		}
	}
	var messages []string
	if !auditResults.ExtendedScanResults.EntitledForJas {
		messages = []string{coreutils.PrintTitle("The ‘jf audit’ command also supports JFrog Advanced Security features, such as 'Contextual Analysis', 'Secret Detection', 'IaC Scan' and ‘SAST’.\nThis feature isn't enabled on your system. Read more - ") + coreutils.PrintLink("https://jfrog.com/xray/")}
	}
	if err = xrayutils.NewResultsWriter(auditResults).
		SetIsMultipleRootProject(auditResults.IsMultipleProject()).
		SetIncludeVulnerabilities(auditCmd.IncludeVulnerabilities).
		SetIncludeLicenses(auditCmd.IncludeLicenses).
		SetOutputFormat(auditCmd.OutputFormat()).
		SetPrintExtendedTable(auditCmd.PrintExtendedTable).
		SetExtraMessages(messages).
		SetScanType(services.Dependency).
		PrintScanResults(); err != nil {
		return
	}

	if auditResults.ScansErr != nil {
		return auditResults.ScansErr
	}

	// Only in case Xray's context was given (!auditCmd.IncludeVulnerabilities), and the user asked to fail the build accordingly, do so.
	if auditCmd.Fail && !auditCmd.IncludeVulnerabilities && xrayutils.CheckIfFailBuild(auditResults.GetScaScansXrayResults()) {
		err = xrayutils.NewFailBuildError()
	}
	return
}

func (auditCmd *AuditCommand) CommandName() string {
	return "generic_audit"
}

// Runs an audit scan based on the provided auditParams.
// Returns an audit Results object containing all the scan results.
// If the current server is entitled for JAS, the advanced security results will be included in the scan results.
func RunAudit(auditParams *AuditParams) (results *xrayutils.Results, err error) {
	// Initialize Results struct
	results = xrayutils.NewAuditResults()
	serverDetails, err := auditParams.ServerDetails()
	if err != nil {
		return
	}
	var xrayManager *xray.XrayServicesManager
	if xrayManager, auditParams.xrayVersion, err = xrayutils.CreateXrayServiceManagerAndGetVersion(serverDetails); err != nil {
		return
	}
	if err = clientutils.ValidateMinimumVersion(clientutils.Xray, auditParams.xrayVersion, scangraph.GraphScanMinXrayVersion); err != nil {
		return
	}
	results.XrayVersion = auditParams.xrayVersion
	results.ExtendedScanResults.EntitledForJas, err = isEntitledForJas(xrayManager, auditParams.xrayVersion)
	if err != nil {
		return
	}

	if auditParams.xrayGraphScanParams.XscGitInfoContext != nil {
		if err = xrayutils.SendXscGitInfoRequestIfEnabled(auditParams.xrayGraphScanParams, xrayManager); err != nil {
			return nil, err
		}
		results.MultiScanId = auditParams.xrayGraphScanParams.MultiScanId
	}

	auditParallelRunner := utils.CreateAuditParallelRunner(auditParams.numOfParallelScans)
	JFrogAppsConfig, err := jas.CreateJFrogAppsConfig(auditParams.workingDirs)
	if err != nil {
		return results, fmt.Errorf("failed to create JFrogAppsConfig: %s", err.Error())
	}
	if results.ExtendedScanResults.EntitledForJas {
		// Download (if needed) the analyzer manager and run scanners.
		auditParallelRunner.JasWg.Add(1)
		_, jasErr := auditParallelRunner.Runner.AddTaskWithError(func(threadId int) error {
			return downloadAnalyzerManagerAndRunScanners(auditParallelRunner, results, serverDetails, auditParams, JFrogAppsConfig, threadId)
		}, auditParallelRunner.AddErrorToChan)
		if jasErr != nil {
			auditParallelRunner.AddErrorToChan(fmt.Errorf("failed to creat AM and jas scanners task: %s", err.Error()))
		}
	}

	// The sca scan doesn't require the analyzer manager, so it can run separately from the analyzer manager download routine.
	scaScanErr := runScaScan(auditParallelRunner, auditParams, results)
	if scaScanErr != nil {
		auditParallelRunner.AddErrorToChan(scaScanErr)
	}
	go func() {
		auditParallelRunner.JasWg.Wait()
		auditParallelRunner.ScaScansWg.Wait()
		auditParallelRunner.Runner.Done()
	}()
	go func() {
		for e := range auditParallelRunner.ErrorsQueue {
			results.ScansErr = errors.Join(results.ScansErr, e)
		}
	}()
	if auditParams.Progress() != nil {
		auditParams.Progress().SetHeadlineMsg("Scanning for issues")
	}
	auditParallelRunner.Runner.Run()
	return
}

func isEntitledForJas(xrayManager *xray.XrayServicesManager, xrayVersion string) (entitled bool, err error) {
	if e := clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, xrayutils.EntitlementsMinVersion); e != nil {
		log.Debug(e)
		return
	}
	entitled, err = xrayManager.IsEntitled(xrayutils.ApplicabilityFeatureId)
	return
}

func downloadAnalyzerManagerAndRunScanners(auditParallelRunner *utils.AuditParallelRunner, scanResults *utils.Results,
	serverDetails *config.ServerDetails, auditParams *AuditParams, jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig, threadId int) (err error) {
	defer func() {
		auditParallelRunner.JasWg.Done()
	}()
	err = utils.DownloadAnalyzerManagerIfNeeded(threadId)
	if err != nil {
		return
	}
	err = RunJasScannersAndSetResults(auditParallelRunner, scanResults, serverDetails, auditParams, jfrogAppsConfig)
	return
}
