package maliciousscan

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/maliciouscode"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type MaliciousScanCommand struct {
	serverDetails             *config.ServerDetails
	workingDirs               []string
	threads                   int
	outputFormat              format.OutputFormat
	minSeverityFilter         severityutils.Severity
	progress                  ioUtils.ProgressMgr
	customAnalyzerManagerPath string
	project                   string
}

func (cmd *MaliciousScanCommand) SetProgress(progress ioUtils.ProgressMgr) {
	cmd.progress = progress
}

func (cmd *MaliciousScanCommand) SetThreads(threads int) *MaliciousScanCommand {
	cmd.threads = threads
	return cmd
}

func (cmd *MaliciousScanCommand) SetServerDetails(server *config.ServerDetails) *MaliciousScanCommand {
	cmd.serverDetails = server
	return cmd
}

func (cmd *MaliciousScanCommand) SetWorkingDirs(workingDirs []string) *MaliciousScanCommand {
	cmd.workingDirs = workingDirs
	return cmd
}

func (cmd *MaliciousScanCommand) SetOutputFormat(format format.OutputFormat) *MaliciousScanCommand {
	cmd.outputFormat = format
	return cmd
}

func (cmd *MaliciousScanCommand) SetMinSeverityFilter(minSeverity severityutils.Severity) *MaliciousScanCommand {
	cmd.minSeverityFilter = minSeverity
	return cmd
}

func (cmd *MaliciousScanCommand) SetCustomAnalyzerManagerPath(path string) *MaliciousScanCommand {
	cmd.customAnalyzerManagerPath = path
	return cmd
}

func (cmd *MaliciousScanCommand) SetProject(project string) *MaliciousScanCommand {
	cmd.project = project
	return cmd
}

func (cmd *MaliciousScanCommand) ServerDetails() (*config.ServerDetails, error) {
	return cmd.serverDetails, nil
}

func (cmd *MaliciousScanCommand) CommandName() string {
	return "malicious_scan"
}

func NewMaliciousScanCommand() *MaliciousScanCommand {
	return &MaliciousScanCommand{}
}

func (cmd *MaliciousScanCommand) Run() (err error) {
	xrayVersion, entitledForJas, workingDirs, err := cmd.validateAndPrepare()
	if err != nil {
		return err
	}

	cmdResults := cmd.initializeCommandResults(xrayVersion, entitledForJas)
	populateScanTargets(cmdResults, workingDirs)

	scanner, err := cmd.createJasScanner()
	if err != nil {
		return err
	}

	if err = cmd.runMaliciousScans(cmdResults, scanner); err != nil {
		return err
	}

	return cmd.outputResults(cmdResults)
}

func (cmd *MaliciousScanCommand) validateAndPrepare() (xrayVersion string, entitledForJas bool, workingDirs []string, err error) {
	xrayManager, xrayVersion, err := xray.CreateXrayServiceManagerAndGetVersion(cmd.serverDetails, xray.WithScopedProjectKey(cmd.project))
	if err != nil {
		return "", false, nil, err
	}

	entitledForJas, err = jas.IsEntitledForJas(xrayManager, xrayVersion)
	if err != nil {
		return "", false, nil, err
	}
	if !entitledForJas {
		return "", false, nil, errors.New("JAS (Advanced Security) feature is not entitled")
	}

	log.Info("JFrog Xray version is:", xrayVersion)

	workingDirs, err = coreutils.GetFullPathsWorkingDirs(cmd.workingDirs)
	if err != nil {
		return "", false, nil, err
	}
	logScanPaths(workingDirs)

	return xrayVersion, entitledForJas, workingDirs, nil
}

func (cmd *MaliciousScanCommand) initializeCommandResults(xrayVersion string, entitledForJas bool) *results.SecurityCommandResults {
	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.SetXrayVersion(xrayVersion)
	cmdResults.SetEntitledForJas(entitledForJas)
	cmdResults.SetResultsContext(results.ResultContext{
		IncludeVulnerabilities: true,
	})
	return cmdResults
}

func (cmd *MaliciousScanCommand) createJasScanner() (*jas.JasScanner, error) {
	scannerOptions := []jas.JasScannerOption{
		jas.WithEnvVars(
			false,
			jas.NotDiffScanEnvValue,
			jas.GetAnalyzerManagerXscEnvVars(
				"",
				"",
				cmd.project,
				nil,
			),
		),
		jas.WithMinSeverity(cmd.minSeverityFilter),
	}

	scanner, err := jas.NewJasScanner(cmd.serverDetails, scannerOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create JAS scanner: %w", err)
	}
	if scanner == nil {
		return nil, errors.New("JAS scanner was not created")
	}

	if err = cmd.setAnalyzerManagerPath(scanner); err != nil {
		return nil, err
	}

	log.Debug(fmt.Sprintf("Using analyzer manager executable at: %s", scanner.AnalyzerManager.AnalyzerManagerFullPath))
	return scanner, nil
}

func (cmd *MaliciousScanCommand) setAnalyzerManagerPath(scanner *jas.JasScanner) error {
	if cmd.customAnalyzerManagerPath == "" {
		if err := jas.DownloadAnalyzerManagerIfNeeded(0); err != nil {
			return fmt.Errorf("failed to download analyzer manager: %s", err.Error())
		}
		var err error
		if scanner.AnalyzerManager.AnalyzerManagerFullPath, err = jas.GetAnalyzerManagerExecutable(); err != nil {
			return fmt.Errorf("failed to set analyzer manager executable path: %s", err.Error())
		}
	} else {
		scanner.AnalyzerManager.AnalyzerManagerFullPath = cmd.customAnalyzerManagerPath
		log.Debug("using custom analyzer manager binary path")
	}
	return nil
}

func (cmd *MaliciousScanCommand) runMaliciousScans(cmdResults *results.SecurityCommandResults, scanner *jas.JasScanner) error {
	jasScanProducerConsumer := utils.NewSecurityParallelRunner(cmd.threads)
	jasScanProducerConsumer.JasWg.Add(1)
	createMaliciousScansTask := func(threadId int) (generalError error) {
		defer func() {
			jasScanProducerConsumer.JasWg.Done()
		}()
		for _, targetResult := range cmdResults.Targets {
			vulnerabilitiesResults, err := maliciouscode.RunMaliciousScan(
				scanner,
				maliciouscode.MaliciousScannerType,
				targetResult.Target,
				len(cmdResults.Targets),
				threadId,
			)
			jasScanProducerConsumer.ResultsMu.Lock()
			// Malicious code scans only return vulnerabilities, not violations
			targetResult.AddJasScanResults(jasutils.MaliciousCode, vulnerabilitiesResults, nil, jas.GetAnalyzerManagerExitCode(err))
			jasScanProducerConsumer.ResultsMu.Unlock()
			if err = jas.ParseAnalyzerManagerError(jasutils.MaliciousCode, err); err != nil {
				_ = targetResult.AddTargetError(fmt.Errorf("failed to run malicious scan: %w", err), false)
			}
		}
		return
	}

	if _, addTaskErr := jasScanProducerConsumer.Runner.AddTaskWithError(createMaliciousScansTask, func(taskErr error) {
		cmdResults.AddGeneralError(fmt.Errorf("failed while adding malicious scan tasks: %s", taskErr.Error()), false)
	}); addTaskErr != nil {
		return fmt.Errorf("failed to create malicious scan task: %w", addTaskErr)
	}

	jasScanProducerConsumer.Start()
	return nil
}

func (cmd *MaliciousScanCommand) outputResults(cmdResults *results.SecurityCommandResults) error {
	if err := output.NewResultsWriter(cmdResults).
		SetOutputFormat(cmd.outputFormat).
		SetPlatformUrl(cmd.serverDetails.Url).
		SetPrintExtendedTable(false).
		SetIsMultipleRootProject(cmdResults.HasMultipleTargets()).
		SetSubScansPerformed([]utils.SubScanType{utils.MaliciousCodeScan}).
		PrintScanResults(); err != nil {
		return errors.Join(err, cmdResults.GetErrors())
	}

	if err := cmdResults.GetErrors(); err != nil {
		return err
	}

	log.Info("Malicious scan completed successfully.")
	return nil
}

func logScanPaths(workingDirs []string) {
	if len(workingDirs) == 0 {
		return
	}
	if len(workingDirs) == 1 {
		log.Debug("Scanning path:", workingDirs[0])
		return
	}
	log.Debug("Scanning paths:", strings.Join(workingDirs, ", "))
}

func populateScanTargets(cmdResults *results.SecurityCommandResults, workingDirs []string) {
	for _, requestedDirectory := range workingDirs {
		if !fileutils.IsPathExists(requestedDirectory, false) {
			log.Warn("The working directory", requestedDirectory, "doesn't exist. Skipping scan...")
			continue
		}
		cmdResults.NewScanResults(results.ScanTarget{Target: requestedDirectory, Name: filepath.Base(requestedDirectory)})
	}

	if len(cmdResults.Targets) == 0 {
		log.Warn("No scan targets were detected.")
		return
	}

	logScanTargetsInfo(cmdResults)
}

func logScanTargetsInfo(cmdResults *results.SecurityCommandResults) {
	if len(cmdResults.Targets) == 0 {
		return
	}
	log.Info("Scanning", len(cmdResults.Targets), "target(s)...")
	for _, targetResult := range cmdResults.Targets {
		log.Info("Scanning target:", targetResult.Target)
	}
}
