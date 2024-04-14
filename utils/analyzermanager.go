package utils

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/dependencies"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	EntitlementsMinVersion                    = "3.66.5"
	ApplicabilityFeatureId                    = "contextual_analysis"
	AnalyzerManagerZipName                    = "analyzerManager.zip"
	defaultAnalyzerManagerVersion             = "[RELEASE]"
	analyzerManagerDownloadPath               = "xsc-gen-exe-analyzer-manager-local/v1"
	analyzerManagerDirName                    = "analyzerManager"
	analyzerManagerExecutableName             = "analyzerManager"
	analyzerManagerLogDirName                 = "analyzerManagerLogs"
	jfUserEnvVariable                         = "JF_USER"
	jfPasswordEnvVariable                     = "JF_PASS"
	jfTokenEnvVariable                        = "JF_TOKEN"
	jfPlatformUrlEnvVariable                  = "JF_PLATFORM_URL"
	logDirEnvVariable                         = "AM_LOG_DIRECTORY"
	notEntitledExitCode                       = 31
	unsupportedCommandExitCode                = 13
	unsupportedOsExitCode                     = 55
	ErrFailedScannerRun                       = "failed to run %s scan. Exit code received: %s"
	jfrogCliAnalyzerManagerVersionEnvVariable = "JFROG_CLI_ANALYZER_MANAGER_VERSION"
	JfMsiEnvVariable                          = "JF_MSI"
	JfPackageManagerEnvVariable               = "AM_PACKAGE_MANAGER"
	JfLanguageEnvVariable                     = "AM_LANGUAGE"
)

type ApplicabilityStatus string

const (
	Applicable                ApplicabilityStatus = "Applicable"
	NotApplicable             ApplicabilityStatus = "Not Applicable"
	ApplicabilityUndetermined ApplicabilityStatus = "Undetermined"
	NotScanned                ApplicabilityStatus = ""
)

func (as ApplicabilityStatus) String() string {
	return string(as)
}

type JasScanType string

const (
	Applicability JasScanType = "Applicability"
	Secrets       JasScanType = "Secrets"
	IaC           JasScanType = "IaC"
	Sast          JasScanType = "Sast"
)

func (jst JasScanType) String() string {
	return string(jst)
}

func (jst JasScanType) FormattedError(err error) error {
	if err != nil {
		return fmt.Errorf(ErrFailedScannerRun, jst, err.Error())
	}
	return nil
}

var exitCodeErrorsMap = map[int]string{
	notEntitledExitCode:        "got not entitled error from analyzer manager",
	unsupportedCommandExitCode: "got unsupported scan command error from analyzer manager",
	unsupportedOsExitCode:      "got unsupported operating system error from analyzer manager",
}

type AnalyzerManager struct {
	AnalyzerManagerFullPath string
	MultiScanId             string
}

func (am *AnalyzerManager) Exec(configFile, scanCommand, workingDir string, serverDetails *config.ServerDetails) (err error) {
	return am.ExecWithOutputFile(configFile, scanCommand, workingDir, "", serverDetails)
}

func (am *AnalyzerManager) ExecWithOutputFile(configFile, scanCommand, workingDir, outputFile string, serverDetails *config.ServerDetails) (err error) {
	if err = SetAnalyzerManagerEnvVariables(serverDetails); err != nil {
		return
	}
	var cmd *exec.Cmd
	multiScanId := os.Getenv(JfMsiEnvVariable)
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
	cmd.Dir = workingDir
	output, err := cmd.CombinedOutput()
	if isCI() || err != nil {
		if len(output) > 0 {
			log.Debug(fmt.Sprintf("%s %q output: %s", workingDir, strings.Join(cmd.Args, " "), string(output)))
		}
		err = errorutils.CheckError(err)
	}
	return
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
		err = errors.New("unable to locate the analyzer manager package. Advanced security scans cannot be performed without this package")
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

func isCI() bool {
	return strings.ToLower(os.Getenv(coreutils.CI)) == "true"
}

func SetAnalyzerManagerEnvVariables(serverDetails *config.ServerDetails) error {
	if serverDetails == nil {
		return errors.New("cant get xray server details")
	}
	if err := os.Setenv(jfUserEnvVariable, serverDetails.User); errorutils.CheckError(err) != nil {
		return err
	}
	if err := os.Setenv(jfPasswordEnvVariable, serverDetails.Password); errorutils.CheckError(err) != nil {
		return err
	}
	if err := os.Setenv(jfPlatformUrlEnvVariable, serverDetails.Url); errorutils.CheckError(err) != nil {
		return err
	}
	if err := os.Setenv(jfTokenEnvVariable, serverDetails.AccessToken); errorutils.CheckError(err) != nil {
		return err
	}
	if !isCI() {
		analyzerManagerLogFolder, err := coreutils.CreateDirInJfrogHome(filepath.Join(coreutils.JfrogLogsDirName, analyzerManagerLogDirName))
		if err != nil {
			return err
		}
		if err = os.Setenv(logDirEnvVariable, analyzerManagerLogFolder); errorutils.CheckError(err) != nil {
			return err
		}
	}
	return nil
}

func ParseAnalyzerManagerError(scanner JasScanType, err error) error {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		exitCode := exitError.ExitCode()
		if exitCodeDescription, exitCodeExists := exitCodeErrorsMap[exitCode]; exitCodeExists {
			log.Warn(exitCodeDescription)
			return nil
		}
	}
	return scanner.FormattedError(err)
}

// Download the latest AnalyzerManager executable if not cached locally.
// By default, the zip is downloaded directly from jfrog releases.
func DownloadAnalyzerManagerIfNeeded(threadId int) error {
	downloadPath, err := GetAnalyzerManagerDownloadPath()
	if err != nil {
		return err
	}
	artDetails, remotePath, err := getAnalyzerManagerRemoteDetails(downloadPath)
	if err != nil {
		return err
	}
	// Check if the AnalyzerManager should be downloaded.
	// First get the latest AnalyzerManager checksum from Artifactory.
	client, httpClientDetails, err := dependencies.CreateHttpClient(artDetails)
	if err != nil {
		return err
	}
	downloadUrl := artDetails.ArtifactoryUrl + remotePath
	remoteFileDetails, _, err := client.GetRemoteFileDetails(downloadUrl, &httpClientDetails)
	if err != nil {
		return fmt.Errorf("couldn't get remote file details for %s: %s", downloadUrl, err.Error())
	}
	analyzerManagerDir, err := GetAnalyzerManagerDirAbsolutePath()
	if err != nil {
		return err
	}
	// Find current AnalyzerManager checksum.
	checksumFilePath := filepath.Join(analyzerManagerDir, dependencies.ChecksumFileName)
	exist, err := fileutils.IsFileExists(checksumFilePath, false)
	if err != nil {
		return err
	}
	if exist {
		var sha2 []byte
		sha2, err = fileutils.ReadFile(checksumFilePath)
		if err != nil {
			return err
		}
		// If the checksums are identical, there's no need to download.
		if remoteFileDetails.Checksum.Sha256 == string(sha2) {
			return nil
		}
	}
	// Download & unzip the analyzer manager files
	log.Debug("[thread_id: " + strconv.Itoa(threadId) + "] The 'Analyzer Manager' app is not cached locally. Downloading it now...")
	if err = dependencies.DownloadDependency(artDetails, remotePath, filepath.Join(analyzerManagerDir, AnalyzerManagerZipName), true); err != nil {
		return err
	}
	return dependencies.CreateChecksumFile(checksumFilePath, remoteFileDetails.Checksum.Sha256)
}

func getAnalyzerManagerRemoteDetails(downloadPath string) (server *config.ServerDetails, fullRemotePath string, err error) {
	var remoteRepo string
	server, remoteRepo, err = dependencies.GetRemoteDetails(coreutils.ReleasesRemoteEnv)
	if err != nil {
		return
	}
	if remoteRepo != "" {
		fullRemotePath = path.Join(remoteRepo, "artifactory", downloadPath)
		return
	}
	log.Debug("'" + coreutils.ReleasesRemoteEnv + "' environment variable is not configured. The Analyzer Manager app will be downloaded directly from releases.jfrog.io if needed.")
	// If not configured to download through a remote repository in Artifactory, download from releases.jfrog.io.
	return &config.ServerDetails{ArtifactoryUrl: coreutils.JfrogReleasesUrl}, downloadPath, nil
}
