package audit

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
)

type AuditCommand struct {
	watches                []string
	projectKey             string
	targetRepoPath         string
	IncludeVulnerabilities bool
	IncludeLicenses        bool
	Fail                   bool
	PrintExtendedTable     bool
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

func (auditCmd *AuditCommand) CreateXrayGraphScanParams() *services.XrayGraphScanParams {
	params := &services.XrayGraphScanParams{
		RepoPath: auditCmd.targetRepoPath,
		Watches:  auditCmd.watches,
		ScanType: services.Dependency,
	}
	if auditCmd.projectKey == "" {
		params.ProjectKey = os.Getenv(coreutils.Project)
	} else {
		params.ProjectKey = auditCmd.projectKey
	}
	params.IncludeVulnerabilities = auditCmd.IncludeVulnerabilities
	params.IncludeLicenses = auditCmd.IncludeLicenses
	return params
}

func (auditCmd *AuditCommand) Run() (err error) {
	// If no workingDirs were provided by the user, we apply a recursive scan on the root repository
	isRecursiveScan := len(auditCmd.workingDirs) == 0
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(auditCmd.workingDirs)
	if err != nil {
		return
	}

	auditParams := NewAuditParams().
		SetXrayGraphScanParams(auditCmd.CreateXrayGraphScanParams()).
		SetWorkingDirs(workingDirs).
		SetMinSeverityFilter(auditCmd.minSeverityFilter).
		SetFixableOnly(auditCmd.fixableOnly).
		SetGraphBasicParams(auditCmd.AuditBasicParams).
		SetThirdPartyApplicabilityScan(auditCmd.thirdPartyApplicabilityScan).
		SetExclusions(auditCmd.exclusions).
		SetIsRecursiveScan(isRecursiveScan)
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
	// Print Scan results on all cases except if errors accrued on SCA scan and no security/license issues found.
	printScanResults := !(auditResults.ScaError != nil && !auditResults.IsScaIssuesFound())
	if printScanResults {
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
	}
	if err = errors.Join(auditResults.ScaError, auditResults.JasError); err != nil {
		return
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

	auditParallelRunner := utils.CreateAuditParallelRunner()
	if results.ExtendedScanResults.EntitledForJas {
		// Download (if needed) the analyzer manager and run scanners.
		auditParallelRunner.JasWg.Add(1)
		log.Debug("added 1 am task")
		_, err = auditParallelRunner.Runner.AddTaskWithError(func(_ int) error {
			return downloadAnalyzerManagerAndRunScanners(auditParallelRunner, results, auditParams.DirectDependencies(), serverDetails,
				auditParams.workingDirs, auditParams.Progress(), auditParams.thirdPartyApplicabilityScan, auditParams)
		}, auditParallelRunner.ErrorsQueue.AddError)
	}

	// The sca scan doesn't require the analyzer manager, so it can run separately from the analyzer manager download routine.
	err = runScaScan(auditParallelRunner, auditParams, results)
	if err != nil {
		return
	}
	go func() {
		auditParallelRunner.JasWg.Wait()
		log.Debug("finishing am and scanners")
		auditParallelRunner.ScaScansWg.Wait()
		log.Debug("finishing sca")
		auditParallelRunner.Runner.Done()
		log.Debug("done total run")
	}()
	auditParallelRunner.Runner.Run()
	log.Debug("finish running")
	//auditParallelRunner.ErrorsQueue.GetError()
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

func downloadAnalyzerManagerAndRunScanners(auditParallelRunner *utils.AuditParallelRunner, scanResults *utils.Results, directDependencies []string,
	serverDetails *config.ServerDetails, workingDirs []string, progress io.ProgressMgr, thirdPartyApplicabilityScan bool, auditParams *AuditParams) (err error) {
	defer func() {
		log.Debug("remove 1 am task")
		auditParallelRunner.JasWg.Done()
	}()
	err = utils.DownloadAnalyzerManagerIfNeeded()
	if err != nil {
		return
	}
	err = RunJasScannersAndSetResults(auditParallelRunner, scanResults, directDependencies, serverDetails, workingDirs, progress, thirdPartyApplicabilityScan, auditParams)
	return
}
