package swift

import (
	"bytes"
	"fmt"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

const (
	minSupportedSwiftVersion = "5.7.0"
)

type SwiftCommand struct {
	cmdName          string
	swiftVersion     *version.Version
	workingDirectory string
	executablePath   string
}

func getSwiftVersionAndExecPath() (*version.Version, string, error) {
	swiftExecPath, err := exec.LookPath("swift")
	if err != nil {
		return nil, "", fmt.Errorf("could not find the 'swift' executable in the system PATH %w", err)
	}
	log.Debug("Using swift executable:", swiftExecPath)
	versionData, _, err := runSwiftCmd(swiftExecPath, "", []string{"--version"})
	if err != nil {
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
	log.Debug("swift '" + strings.Join(args, " ") + "' standard output is:\n" + strings.TrimSpace(string(stdResult)))
	return
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
			"JFrog CLI swift %s command requires swift client version %s or higher. The Current version is: %s", sc.cmdName, minSupportedSwiftVersion, sc.swiftVersion.GetVersion())
	}
	return nil
}
