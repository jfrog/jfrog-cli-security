package cocoapods

import (
	"bytes"
	"fmt"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

const (
	minSupportedPodVersion = "1.15.2"
)

type PodCommand struct {
	cmdName          string
	podVersion       *version.Version
	workingDirectory string
	executablePath   string
}

func getPodVersionAndExecPath() (*version.Version, string, error) {
	podExecPath, err := exec.LookPath("pod")
	if err != nil {
		return nil, "", fmt.Errorf("could not find the 'pod' executable in the system PATH %w", err)
	}
	log.Debug("Using pod executable:", podExecPath)
	versionData, err := runPodCmd(podExecPath, "", []string{"--version"})
	if err != nil {
		return nil, "", err
	}
	return version.NewVersion(strings.TrimSpace(string(versionData))), podExecPath, nil
}

func runPodCmd(executablePath, srcPath string, podArgs []string) (stdResult []byte, err error) {
	args := make([]string, 0)
	for i := 0; i < len(podArgs); i++ {
		if strings.TrimSpace(podArgs[i]) != "" {
			args = append(args, podArgs[i])
		}
	}
	log.Debug("Running 'pod " + strings.Join(podArgs, " ") + "' command.")
	command := exec.Command(executablePath, args...)
	command.Dir = srcPath
	outBuffer := bytes.NewBuffer([]byte{})
	command.Stdout = outBuffer
	errBuffer := bytes.NewBuffer([]byte{})
	command.Stderr = errBuffer
	err = command.Run()
	errResult := errBuffer.Bytes()
	stdResult = outBuffer.Bytes()
	if err != nil {
		err = fmt.Errorf("error while running '%s %s': %s\n%s", executablePath, strings.Join(args, " "), err.Error(), strings.TrimSpace(string(errResult)))
		return
	}
	log.Debug(fmt.Sprintf("cocoapods '%s' standard output is:\n%s", strings.Join(args, " "), strings.TrimSpace(string(stdResult))))
	return
}

func (pc *PodCommand) PreparePrerequisites() error {
	log.Debug("Preparing prerequisites...")
	var err error
	pc.podVersion, pc.executablePath, err = getPodVersionAndExecPath()
	if err != nil {
		return err
	}
	if pc.podVersion.Compare(minSupportedPodVersion) > 0 {
		return errorutils.CheckErrorf(
			"JFrog CLI cocoapods %s command requires cocoapods client version %s or higher. The Current version is: %s", pc.cmdName, minSupportedPodVersion, pc.podVersion.GetVersion())
	}

	pc.workingDirectory, err = coreutils.GetWorkingDirectory()
	if err != nil {
		return err
	}
	log.Debug("Working directory set to:", pc.workingDirectory)
	return nil
}
