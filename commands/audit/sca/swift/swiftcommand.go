package swift

import (
	"bytes"
	"fmt"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/ioutils"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	minSupportedSwiftVersion = "5.1.0"
	swiftNetRcfileName       = ".netrc"
	swiftrcBackupFileName    = ".jfrog.netrc.backup"
)

type SwiftCommand struct {
	cmdName          string
	serverDetails    *config.ServerDetails
	swiftVersion     *version.Version
	authArtDetails   auth.ServiceDetails
	restoreNetrcFunc func() error
	workingDirectory string
	executablePath   string
}

func getSwiftVersionAndExecPath() (*version.Version, string, error) {
	swiftExecPath, err := exec.LookPath("swift")
	if err != nil {
		return nil, "", fmt.Errorf("could not find the 'swift' executable in the system PATH %w", err)
	}
	log.Debug("Using swift executable:", swiftExecPath)
	versionData, stdErr, err := runSwiftCmd(swiftExecPath, "", []string{"--version"})
	if err != nil || stdErr != nil {
		return nil, "", err
	}
	return version.NewVersion(strings.TrimSpace(string(versionData))), swiftExecPath, nil
}

func runSwiftCmd(executablePath, srcPath string, swiftArgs []string) (stdResult, errResult []byte, err error) {
	args := make([]string, 0)
	for i := 0; i < len(swiftArgs); i++ {
		if strings.TrimSpace(swiftArgs[i]) != "" {
			args = append(args, swiftArgs[i])
		}
	}
	log.Debug("Running 'swift " + strings.Join(swiftArgs, " ") + "' command.")
	command := exec.Command(executablePath, args...)
	command.Dir = srcPath
	outBuffer := bytes.NewBuffer([]byte{})
	command.Stdout = outBuffer
	errBuffer := bytes.NewBuffer([]byte{})
	command.Stderr = errBuffer
	err = command.Run()
	errResult = errBuffer.Bytes()
	stdResult = outBuffer.Bytes()
	if err != nil {
		err = fmt.Errorf("error while running '%s %s': %s\n%s", executablePath, strings.Join(args, " "), err.Error(), strings.TrimSpace(string(errResult)))
		return
	}
	log.Debug("npm '" + strings.Join(args, " ") + "' standard output is:\n" + strings.TrimSpace(string(stdResult)))
	return
}

func (sc *SwiftCommand) SetServerDetails(serverDetails *config.ServerDetails) *SwiftCommand {
	sc.serverDetails = serverDetails
	return sc
}

func (sc *SwiftCommand) RestoreNetrcFunc() func() error {
	return sc.restoreNetrcFunc
}

func (sc *SwiftCommand) GetData() ([]byte, error) {
	var filteredConf []string
	filteredConf = append(filteredConf, "machine ", sc.serverDetails.Url, "\n")
	filteredConf = append(filteredConf, "login ", sc.serverDetails.User, "\n")
	filteredConf = append(filteredConf, "password ", sc.serverDetails.AccessToken, "\n")

	return []byte(strings.Join(filteredConf, "")), nil
}

func (sc *SwiftCommand) CreateTempNetrc() error {
	data, err := sc.GetData()
	if err != nil {
		return err
	}
	if err = removeNetrcIfExists(sc.workingDirectory); err != nil {
		return err
	}
	log.Debug("Creating temporary .netrc file.")
	return errorutils.CheckError(os.WriteFile(filepath.Join(sc.workingDirectory, swiftNetRcfileName), data, 0755))
}

func (sc *SwiftCommand) setRestoreNetrcFunc() error {
	restoreNetrcFunc, err := ioutils.BackupFile(filepath.Join(sc.workingDirectory, swiftNetRcfileName), swiftrcBackupFileName)
	if err != nil {
		return err
	}
	sc.restoreNetrcFunc = func() error {
		return restoreNetrcFunc()
	}
	return nil
}

func (sc *SwiftCommand) setArtifactoryAuth() error {
	authArtDetails, err := sc.serverDetails.CreateArtAuthConfig()
	if err != nil {
		return err
	}
	if authArtDetails.GetSshAuthHeaders() != nil {
		return errorutils.CheckErrorf("SSH authentication is not supported in this command")
	}
	sc.authArtDetails = authArtDetails
	return nil
}

func newSwiftInstallCommand() *SwiftCommand {
	return &SwiftCommand{cmdName: "install"}
}

func (sc *SwiftCommand) PreparePrerequisites() error {
	log.Debug("Preparing prerequisites...")
	var err error
	sc.swiftVersion, sc.executablePath, err = getSwiftVersionAndExecPath()
	if err != nil {
		return err
	}
	if sc.swiftVersion.Compare(minSupportedSwiftVersion) > 0 {
		return errorutils.CheckErrorf(
			"JFrog CLI swift %s command requires cocoapods client version %s or higher. The Current version is: %s", sc.cmdName, minSupportedSwiftVersion, sc.swiftVersion.GetVersion())
	}

	sc.workingDirectory, err = coreutils.GetWorkingDirectory()
	if err != nil {
		return err
	}
	log.Debug("Working directory set to:", sc.workingDirectory)
	if err = sc.setArtifactoryAuth(); err != nil {
		return err
	}

	return sc.setRestoreNetrcFunc()
}

func removeNetrcIfExists(workingDirectory string) error {
	if _, err := os.Stat(filepath.Join(workingDirectory, swiftNetRcfileName)); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errorutils.CheckError(err)
	}

	log.Debug("Removing existing .netrc file")
	return errorutils.CheckError(os.Remove(filepath.Join(workingDirectory, swiftNetRcfileName)))
}

func setArtifactoryAsResolutionServer(serverDetails *config.ServerDetails, depsRepo string) (clearResolutionServerFunc func() error, err error) {
	swiftCmd := newSwiftInstallCommand().SetServerDetails(serverDetails)
	if err = swiftCmd.PreparePrerequisites(); err != nil {
		return
	}
	if err = swiftCmd.CreateTempNetrc(); err != nil {
		return
	}
	clearResolutionServerFunc = swiftCmd.RestoreNetrcFunc()
	log.Info(fmt.Sprintf("Resolving dependencies from '%s' from repo '%s'", serverDetails.Url, depsRepo))
	return
}
