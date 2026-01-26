package jas

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	ApplicabilityFeatureId                    = "contextual_analysis"
	AnalyzerManagerZipName                    = "analyzerManager.zip"
	defaultAnalyzerManagerVersion             = "1.30.1"
	analyzerManagerDownloadPath               = "xsc-gen-exe-analyzer-manager-local/v1"
	analyzerManagerDirName                    = "analyzerManager"
	analyzerManagerExecutableName             = "analyzerManager"
	analyzerManagerLogDirName                 = "analyzerManagerLogs"
	jfUserEnvVariable                         = "JF_USER"
	jfPasswordEnvVariable                     = "JF_PASS"
	jfTokenEnvVariable                        = "JF_TOKEN"
	jfPlatformUrlEnvVariable                  = "JF_PLATFORM_URL"
	jfPlatformXrayUrlEnvVariable              = "JF_PLATFORM_XRAY_URL"
	logDirEnvVariable                         = "AM_LOG_DIRECTORY"
	watchesEnvVariable                        = "AM_WATCHES"
	projectEnvVariable                        = "AM_PROJECT_KEY"
	gitRepoEnvVariable                        = "AM_GIT_REPO_VIOLATIONS"
	newFlowEnvVariable                        = "AM_DUMMY_MODE"
	notEntitledExitCode                       = 31
	unsupportedCommandExitCode                = 13
	unsupportedOsExitCode                     = 55
	ErrFailedScannerRun                       = "failed to run %s scan. Exit code received: %s"
	jfrogCliAnalyzerManagerVersionEnvVariable = "JFROG_CLI_ANALYZER_MANAGER_VERSION"
	JfPackageManagerEnvVariable               = "AM_PACKAGE_MANAGER"
	JfLanguageEnvVariable                     = "AM_LANGUAGE"
	DiffScanEnvVariable                       = "AM_DIFF_SCAN"
	// #nosec G101 -- Not credentials.
	JfSecretValidationEnvVariable = "JF_VALIDATE_SECRETS"
)

const (
	NotDiffScanEnvValue        JasDiffScanEnvValue = ""
	FirstScanDiffScanEnvValue  JasDiffScanEnvValue = "first_scan"
	SecondScanDiffScanEnvValue JasDiffScanEnvValue = "second_scan"
)

type JasDiffScanEnvValue string

var exitCodeErrorsMap = map[int]string{
	notEntitledExitCode:        "got not entitled error from analyzer manager",
	unsupportedCommandExitCode: "got unsupported scan command error from analyzer manager",
	unsupportedOsExitCode:      "got unsupported operating system error from analyzer manager",
}

type AnalyzerManager struct {
	AnalyzerManagerFullPath string
	MultiScanId             string
}

func (am *AnalyzerManager) Exec(configFile, scanCommand, workingDir string, serverDetails *config.ServerDetails, envVars map[string]string) (err error) {
	return am.ExecWithOutputFile(configFile, scanCommand, workingDir, "", serverDetails, envVars)
}

func (am *AnalyzerManager) ExecWithOutputFile(configFile, scanCommand, workingDir, outputFile string, serverDetails *config.ServerDetails, envVars map[string]string) (err error) {
	var cmd *exec.Cmd
	multiScanId := envVars[utils.JfMsiEnvVariable]
	if len(outputFile) > 0 {
		log.Debug("Executing", am.AnalyzerManagerFullPath, scanCommand, configFile, outputFile, multiScanId)
		cmd = exec.Command(am.AnalyzerManagerFullPath, scanCommand, configFile, outputFile)
	} else {
		log.Debug("Executing", am.AnalyzerManagerFullPath, scanCommand, configFile, multiScanId)
		cmd = exec.Command(am.AnalyzerManagerFullPath, scanCommand, configFile)
	}
	defer func() {
		if cmd.ProcessState != nil && !cmd.ProcessState.Exited() {
			if killProcessError := cmd.Process.Kill(); errorutils.CheckError(killProcessError) != nil {
				err = errors.Join(err, killProcessError)
			}
		}
	}()
	cmd.Env = utils.ToCommandEnvVars(envVars)
	cmd.Dir = workingDir
	output, err := cmd.CombinedOutput()
	if utils.IsCI() || err != nil {
		if len(output) > 0 {
			log.Debug(fmt.Sprintf("%s %q output: %s", workingDir, strings.Join(cmd.Args, " "), string(output)))
		}
		err = errorutils.CheckError(err)
	}
	return
}

func GetDiffScanTypeValue(diffScan bool, resultsToCompare *results.SecurityCommandResults) JasDiffScanEnvValue {
	if !diffScan {
		return NotDiffScanEnvValue
	}
	if resultsToCompare == nil {
		return FirstScanDiffScanEnvValue
	}
	return SecondScanDiffScanEnvValue
}

func GetAnalyzerManagerDownloadPath() (string, error) {
	osAndArc, err := coreutils.GetOSAndArc()
	if err != nil {
		return "", err
	}
	return path.Join(analyzerManagerDownloadPath, GetAnalyzerManagerVersion(), osAndArc, AnalyzerManagerZipName), nil
}

func GetAnalyzerManagerVersion() string {
	if analyzerManagerVersion := os.Getenv(jfrogCliAnalyzerManagerVersionEnvVariable); analyzerManagerVersion != "" {
		return analyzerManagerVersion
	}
	return defaultAnalyzerManagerVersion
}

func GetAnalyzerManagerDirAbsolutePath() (string, error) {
	jfrogDir, err := config.GetJfrogDependenciesPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(jfrogDir, analyzerManagerDirName), nil
}

func GetAnalyzerManagerExecutable() (analyzerManagerPath string, err error) {
	analyzerManagerDir, err := GetAnalyzerManagerDirAbsolutePath()
	if err != nil {
		return "", err
	}
	analyzerManagerPath = filepath.Join(analyzerManagerDir, GetAnalyzerManagerExecutableName())
	var exists bool
	if exists, err = fileutils.IsFileExists(analyzerManagerPath, false); err != nil {
		return
	}
	if !exists {
		err = fmt.Errorf("unable to locate the analyzer manager package at %s. Advanced security scans cannot be performed without this package", analyzerManagerPath)
	}
	return analyzerManagerPath, err
}

func GetAnalyzerManagerExecutableName() string {
	analyzerManager := analyzerManagerExecutableName
	if coreutils.IsWindows() {
		return analyzerManager + ".exe"
	}
	return analyzerManager
}

func GetAnalyzerManagerEnvVariables(serverDetails *config.ServerDetails) (envVars map[string]string, err error) {
	envVars = map[string]string{
		jfUserEnvVariable:            serverDetails.User,
		jfPasswordEnvVariable:        serverDetails.Password,
		jfPlatformUrlEnvVariable:     serverDetails.Url,
		jfPlatformXrayUrlEnvVariable: serverDetails.XrayUrl,
		jfTokenEnvVariable:           serverDetails.AccessToken,
	}
	if !utils.IsCI() {
		analyzerManagerLogFolder, err := coreutils.CreateDirInJfrogHome(filepath.Join(coreutils.JfrogLogsDirName, analyzerManagerLogDirName))
		if err != nil {
			return nil, err
		}
		envVars[logDirEnvVariable] = analyzerManagerLogFolder
	}
	return
}

func ParseAnalyzerManagerError(scanner jasutils.JasScanType, err error) (formatErr error) {
	if err == nil {
		return
	}
	if exitCodeDescription, exitCodeExists := exitCodeErrorsMap[GetAnalyzerManagerExitCode(err)]; exitCodeExists {
		log.Warn(exitCodeDescription)
		return nil
	}
	return fmt.Errorf(ErrFailedScannerRun, scanner, err.Error())
}

func GetAnalyzerManagerExitCode(err error) int {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	if err != nil {
		// An exit code of -1 is used to indicate that an error occurred before the command was executed or that the exit code could not be determined.
		return -1
	}
	return 0
}

// Download the latest AnalyzerManager executable if not cached locally.
// By default, the zip is downloaded directly from jfrog releases.
func DownloadAnalyzerManagerIfNeeded(threadId int) error {
	downloadPath, err := GetAnalyzerManagerDownloadPath()
	if err != nil {
		return err
	}
	analyzerManagerDir, err := GetAnalyzerManagerDirAbsolutePath()
	if err != nil {
		return err
	}
	return utils.DownloadResourceFromPlatformIfNeeded("Analyzer Manager", downloadPath, analyzerManagerDir, AnalyzerManagerZipName, true, threadId)
}

func establishPipeToFile(dst io.WriteCloser, src io.Reader) {
	defer func() {
		if err := dst.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing pipe: %v", err))
		}
	}()
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Error("Error establishing pipe")
	}
}

func establishPipeFromFile(dst io.Writer, src io.ReadCloser) {
	defer func() {
		if err := src.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing pipe: %v", err))
		}
	}()
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Error("Error establishing pipe")
	}
}

// RunAnalyzerManagerWithPipes runs the analyzer manager with the given command and pipes for stdin, stdout, and stderr.
// timeout is in seconds; if 0 or negative, the command runs until completion.
func RunAnalyzerManagerWithPipes(env map[string]string, cmd string, inputPipe io.Reader, outputPipe io.Writer, errorPipe io.Writer, timeout int, args ...string) error {
	amPath, err := GetAnalyzerManagerExecutable()
	if err != nil {
		return err
	}

	allArgs := append([]string{cmd}, args...)
	log.Info(fmt.Sprintf("Launching: %s; command %s; arguments %v", amPath, cmd, args))
	command := exec.Command(amPath, allArgs...)
	command.Env = utils.ToCommandEnvVars(env)

	stdin, pipeErr := command.StdinPipe()
	if pipeErr != nil {
		log.Error(fmt.Sprintf("Error creating stdin pipe: %v", pipeErr))
		return pipeErr
	}
	defer func() {
		if err := stdin.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing stdin pipe: %v", err))
		}
	}()

	stdout, pipeErr := command.StdoutPipe()
	if pipeErr != nil {
		log.Error(fmt.Sprintf("Error creating stdout pipe: %v", pipeErr))
		return pipeErr
	}
	defer func() {
		if err := stdout.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing stdout pipe: %v", err))
		}
	}()

	stderr, pipeErr := command.StderrPipe()
	if pipeErr != nil {
		log.Error(fmt.Sprintf("Error creating stderr pipe: %v", pipeErr))
		return pipeErr
	}
	defer func() {
		if err := stderr.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing stderr pipe: %v", err))
		}
	}()

	go establishPipeToFile(stdin, inputPipe)
	go establishPipeFromFile(errorPipe, stderr)
	go establishPipeFromFile(outputPipe, stdout)

	if startErr := command.Start(); startErr != nil {
		log.Error(fmt.Sprintf("Error starting subprocess: %v", startErr))
		return startErr
	}

	var waitErr error
	if timeout > 0 {
		waitCh := make(chan error, 1)
		go func() {
			waitCh <- command.Wait()
		}()
		select {
		case waitErr = <-waitCh:
		case <-time.After(time.Duration(timeout) * time.Second):
			log.Warn("Timeout reached")
			return nil
		}
	} else {
		waitErr = command.Wait()
	}

	if waitErr != nil {
		log.Error(fmt.Sprintf("Error waiting for subprocess: %v", waitErr))
		return waitErr
	}
	return nil
}

// RunAnalyzerManagerWithPipesAndDownload downloads the analyzer manager if needed and runs the command with pipes.
func RunAnalyzerManagerWithPipesAndDownload(envVars map[string]string, cmd string, inputPipe io.Reader, outputPipe io.Writer, errorPipe io.Writer, timeout int, args ...string) error {
	err := DownloadAnalyzerManagerIfNeeded(0)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to download Analyzer Manager: %v", err))
	}
	return RunAnalyzerManagerWithPipes(envVars, cmd, inputPipe, outputPipe, errorPipe, timeout, args...)
}
