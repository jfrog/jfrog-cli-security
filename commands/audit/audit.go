package audit

import (
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/runner"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"os"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/scangraph"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"

	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type AuditCommand struct {
	watches                 []string
	projectKey              string
	targetRepoPath          string
	IncludeVulnerabilities  bool
	IncludeLicenses         bool
	Fail                    bool
	PrintExtendedTable      bool
	analyticsMetricsService *xrayutils.AnalyticsMetricsService
	Threads                 int
	AuditParams
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

func (auditCmd *AuditCommand) SetAnalyticsMetricsService(analyticsMetricsService *xrayutils.AnalyticsMetricsService) *AuditCommand {
	auditCmd.analyticsMetricsService = analyticsMetricsService
	return auditCmd
}

func (auditCmd *AuditCommand) SetThreads(threads int) *AuditCommand {
	auditCmd.Threads = threads
	return auditCmd
}

func (auditCmd *AuditCommand) CreateCommonGraphScanParams() *scangraph.CommonGraphScanParams {
	commonParams := &scangraph.CommonGraphScanParams{
		RepoPath: auditCmd.targetRepoPath,
		Watches:  auditCmd.watches,
		ScanType: services.Dependency,
	}
	if auditCmd.projectKey == "" {
		commonParams.ProjectKey = os.Getenv(coreutils.Project)
	} else {
		commonParams.ProjectKey = auditCmd.projectKey
	}
	commonParams.IncludeVulnerabilities = auditCmd.IncludeVulnerabilities
	commonParams.IncludeLicenses = auditCmd.IncludeLicenses
	commonParams.MultiScanId = auditCmd.analyticsMetricsService.GetMsi()
	if commonParams.MultiScanId != "" {
		xscManager := auditCmd.analyticsMetricsService.XscManager()
		if xscManager != nil {
			version, err := xscManager.GetVersion()
			if err != nil {
				log.Debug(fmt.Sprintf("Can't get XSC version for xray graph scan params. Cause: %s", err.Error()))
			}
			commonParams.XscVersion = version
		}
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

	// Should be called before creating the audit params, so the params will contain XSC information.
	auditCmd.analyticsMetricsService.AddGeneralEvent(auditCmd.analyticsMetricsService.CreateGeneralEvent(xscservices.CliProduct, xscservices.CliEventType))
	auditParams := NewAuditParams().
		SetWorkingDirs(workingDirs).
		SetMinSeverityFilter(auditCmd.minSeverityFilter).
		SetFixableOnly(auditCmd.fixableOnly).
		SetGraphBasicParams(auditCmd.AuditBasicParams).
		SetCommonGraphScanParams(auditCmd.CreateCommonGraphScanParams()).
		SetThirdPartyApplicabilityScan(auditCmd.thirdPartyApplicabilityScan).
		SetThreads(auditCmd.Threads)
	auditParams.SetIsRecursiveScan(isRecursiveScan).SetExclusions(auditCmd.Exclusions())

	auditResults, err := RunAudit(auditParams)
	if err != nil {
		return
	}
	auditCmd.analyticsMetricsService.UpdateGeneralEvent(auditCmd.analyticsMetricsService.CreateXscAnalyticsGeneralEventFinalizeFromAuditResults(auditResults))
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
	results.ExtendedScanResults.EntitledForJas, err = jas.IsEntitledForJas(xrayManager, auditParams.xrayVersion)
	if err != nil {
		return
	}

	results.MultiScanId = auditParams.commonGraphScanParams.MultiScanId

	auditParallelRunner := utils.CreateSecurityParallelRunner(auditParams.threads)
	if results.ExtendedScanResults.EntitledForJas {
		// Download (if needed) the analyzer manager and run scanners.
		auditParallelRunner.JasWg.Add(1)
		if _, jasErr := auditParallelRunner.Runner.AddTaskWithError(func(threadId int) error {
			return downloadAnalyzerManagerAndRunScanners(auditParallelRunner, results, serverDetails, auditParams, threadId)
		}, auditParallelRunner.AddErrorToChan); jasErr != nil {
			auditParallelRunner.AddErrorToChan(fmt.Errorf("failed to create AM downloading task, skipping JAS scans...: %s", jasErr.Error()))
		}
	}

	// The sca scan doesn't require the analyzer manager, so it can run separately from the analyzer manager download routine.
	if _, scaErr := auditParallelRunner.Runner.AddTaskWithError(func(threadId int) error {
		return buildDepTreeAndRunScaScan(auditParallelRunner, auditParams, results, threadId)
	}, auditParallelRunner.AddErrorToChan); scaErr != nil {
		auditParallelRunner.AddErrorToChan(fmt.Errorf("failed to create sca scan task %s", scaErr.Error()))
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

func downloadAnalyzerManagerAndRunScanners(auditParallelRunner *utils.SecurityParallelRunner, scanResults *utils.Results,
	serverDetails *config.ServerDetails, auditParams *AuditParams, threadId int) error {
	defer func() {
		auditParallelRunner.JasWg.Done()
	}()
	if err := xrayutils.DownloadAnalyzerManagerIfNeeded(threadId); err != nil {
		return fmt.Errorf("error from thread_id %d: %s", threadId, err.Error())
	}
	if err := runner.RunJasScannersAndSetResults(auditParallelRunner, scanResults, scanResults.GetScaScannedTechnologies(), auditParams.DirectDependencies(), serverDetails, auditParams.workingDirs, auditParams.thirdPartyApplicabilityScan, auditParams.commonGraphScanParams.MultiScanId, applicability.ApplicabilityScannerType, secrets.SecretsScannerType, auditParallelRunner.AddErrorToChan); err != nil {
		return fmt.Errorf("error from thread_id %d: %s", threadId, err.Error())
	}
	return nil
}
