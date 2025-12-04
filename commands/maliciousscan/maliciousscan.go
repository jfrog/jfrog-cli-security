package maliciousscan

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/runner"
	"github.com/jfrog/jfrog-cli-security/utils"
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
	defer func() {
		if err != nil {
			var e *exec.ExitError
			if errors.As(err, &e) {
				if e.ExitCode() != coreutils.ExitCodeVulnerableBuild.Code {
					err = errors.New("Malicious scan command failed. " + err.Error())
				}
			}
		}
	}()

	xrayManager, xrayVersion, err := xray.CreateXrayServiceManagerAndGetVersion(cmd.serverDetails)
	if err != nil {
		return err
	}

	entitledForJas, err := jas.IsEntitledForJas(xrayManager, xrayVersion)
	if err != nil {
		return err
	}
	if !entitledForJas {
		return errors.New("JAS (Advanced Security) feature is not entitled")
	}

	log.Info("JFrog Xray version is:", xrayVersion)

	if err = jas.DownloadAnalyzerManagerIfNeeded(0); err != nil {
		return fmt.Errorf("failed to download Analyzer Manager: %w", err)
	}

	isRecursiveScan := len(cmd.workingDirs) == 0
	workingDirs, err := coreutils.GetFullPathsWorkingDirs(cmd.workingDirs)
	if err != nil {
		return err
	}
	logScanPaths(workingDirs, isRecursiveScan)

	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.SetXrayVersion(xrayVersion)
	cmdResults.SetEntitledForJas(entitledForJas)
	cmdResults.SetResultsContext(results.ResultContext{
		IncludeVulnerabilities: true,
	})

	populateScanTargets(cmdResults, workingDirs, isRecursiveScan)

	scannerOptions := []jas.JasScannerOption{
		jas.WithEnvVars(
			false, // validateSecrets not relevant for malicious scan
			jas.NotDiffScanEnvValue,
			jas.GetAnalyzerManagerXscEnvVars(
				"",  // msi
				"",  // gitRepoUrl
				"",  // projectKey
				nil, // watches
			),
		),
		jas.WithMinSeverity(cmd.minSeverityFilter),
	}

	scanner, err := jas.NewJasScanner(cmd.serverDetails, scannerOptions...)
	if err != nil {
		return fmt.Errorf("failed to create JAS scanner: %w", err)
	}
	if scanner == nil {
		return errors.New("JAS scanner was not created")
	}

	if cmd.customAnalyzerManagerPath != "" {
		scanner.AnalyzerManager.AnalyzerManagerFullPath = cmd.customAnalyzerManagerPath
	} else {
		if scanner.AnalyzerManager.AnalyzerManagerFullPath, err = jas.GetAnalyzerManagerExecutable(); err != nil {
			return fmt.Errorf("failed to set analyzer manager executable path: %w", err)
		}
	}

	log.Debug(fmt.Sprintf("Using analyzer manager executable at: %s", scanner.AnalyzerManager.AnalyzerManagerFullPath))

	jasScanProducerConsumer := utils.NewSecurityParallelRunner(cmd.threads)

	serverDetails, err := cmd.ServerDetails()
	if err != nil {
		return err
	}

	jasScanProducerConsumer.JasWg.Add(1)
	createMaliciousScansTask := func(threadId int) (generalError error) {
		defer func() {
			jasScanProducerConsumer.JasWg.Done()
		}()
		for _, targetResult := range cmdResults.Targets {
			if targetResult.AppsConfigModule == nil {
				_ = targetResult.AddTargetError(fmt.Errorf("can't find module for path %s", targetResult.Target), false)
				continue
			}
			appsConfigModule := *targetResult.AppsConfigModule
			jasParams := runner.JasRunnerParams{
				Runner:         &jasScanProducerConsumer,
				ServerDetails:  serverDetails,
				Scanner:        scanner,
				Module:         appsConfigModule,
				ScansToPerform: []utils.SubScanType{utils.MaliciousCodeScan},
				ScanResults:    targetResult,
				TargetCount:    len(cmdResults.Targets),
			}

			if generalError = runner.AddJasScannersTasks(jasParams); generalError != nil {
				_ = targetResult.AddTargetError(fmt.Errorf("failed to add malicious scan task: %w", generalError), false)
				generalError = nil
			}
		}
		return
	}

	if _, addTaskErr := jasScanProducerConsumer.Runner.AddTaskWithError(createMaliciousScansTask, func(taskErr error) {
		cmdResults.AddGeneralError(fmt.Errorf("failed while adding JAS scan tasks: %s", taskErr.Error()), false)
	}); addTaskErr != nil {
		return fmt.Errorf("failed to create JAS task: %w", addTaskErr)
	}

	jasScanProducerConsumer.Start()

	if cmd.progress != nil {
		if err = cmd.progress.Quit(); err != nil {
			return err
		}
	}

	if err = output.NewResultsWriter(cmdResults).
		SetOutputFormat(cmd.outputFormat).
		SetPlatformUrl(cmd.serverDetails.Url).
		SetPrintExtendedTable(false).
		SetIsMultipleRootProject(cmdResults.HasMultipleTargets()).
		SetSubScansPerformed([]utils.SubScanType{utils.MaliciousCodeScan}).
		PrintScanResults(); err != nil {
		return errors.Join(err, cmdResults.GetErrors())
	}

	if err = cmdResults.GetErrors(); err != nil {
		return err
	}

	log.Info("Malicious scan completed successfully.")
	return nil
}

func logScanPaths(workingDirs []string, isRecursiveScan bool) {
	if len(workingDirs) == 0 {
		return
	}
	if len(workingDirs) == 1 {
		if isRecursiveScan {
			log.Info("Detecting recursively targets for scan in path:", workingDirs[0])
		} else {
			log.Info("Scanning path:", workingDirs[0])
		}
		return
	}
	log.Info("Scanning paths:", strings.Join(workingDirs, ", "))
}

func populateScanTargets(cmdResults *results.SecurityCommandResults, workingDirs []string, isRecursiveScan bool) {
	for _, requestedDirectory := range workingDirs {
		if !fileutils.IsPathExists(requestedDirectory, false) {
			log.Warn("The working directory", requestedDirectory, "doesn't exist. Skipping scan...")
			continue
		}
		cmdResults.NewScanResults(results.ScanTarget{Target: requestedDirectory, Name: filepath.Base(requestedDirectory)})
	}

	if len(workingDirs) == 0 {
		currentDir, err := coreutils.GetWorkingDirectory()
		if err != nil {
			cmdResults.AddGeneralError(fmt.Errorf("failed to get current working directory: %w", err), false)
			return
		}
		cmdResults.NewScanResults(results.ScanTarget{Target: currentDir, Name: filepath.Base(currentDir)})
	}

	if len(cmdResults.Targets) == 0 {
		log.Warn("No scan targets were detected. Proceeding with empty scan...")
		return
	}

	jfrogAppsConfig, err := jas.CreateJFrogAppsConfig(cmdResults.GetTargetsPaths())
	if err != nil {
		cmdResults.AddGeneralError(fmt.Errorf("failed to create JFrogAppsConfig: %w", err), false)
		return
	}

	for _, targetResult := range cmdResults.Targets {
		targetResult.AppsConfigModule = jas.GetModule(targetResult.Target, jfrogAppsConfig)
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
