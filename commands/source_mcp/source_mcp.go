package source_mcp

import (
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	cmd            = "mcp-sast"
	mcpEntitlement = "local_sast_mcp"
)

type McpCommand struct {
	ServerDetails *config.ServerDetails
	Arguments     []string
	InputPipe     io.Reader
	OutputPipe    io.Writer
	ErrorPipe     io.Writer
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

func RunAmMcpWithPipes(env map[string]string, cmd string, input_pipe io.Reader, output_pipe io.Writer, error_pipe io.Writer, timeout int, args ...string) error {
	am_path, err := jas.GetAnalyzerManagerExecutable()
	if err != nil {
		return err
	}

	allArgs := append([]string{cmd}, args...)
	log.Info(fmt.Sprintf("Launching: %s; command %s; arguments %v", am_path, cmd, args))
	command := exec.Command(am_path, allArgs...)
	command.Env = utils.ToCommandEnvVars(env)

	stdin, _error := command.StdinPipe()
	if _error != nil {
		log.Error(fmt.Sprintf("Error creating MCPService stdin pipe: %v", _error))
		return _error
	}
	defer func() {
		if err := stdin.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing stdin pipe: %v", err))
		}
	}()

	stdout, _error := command.StdoutPipe()
	if _error != nil {
		log.Error(fmt.Sprintf("Error creating MCPService stdout pipe: %v", _error))
		return _error
	}
	defer func() {
		if err := stdout.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing stdout pipe: %v", err))
		}
	}()

	stderr, _error := command.StderrPipe()
	if _error != nil {
		log.Error(fmt.Sprintf("Error creating MCPService stderr pipe: %v", _error))
		return _error
	}
	defer func() {
		if err := stderr.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing stderr pipe: %v", err))
		}
	}()

	go establishPipeToFile(stdin, input_pipe)
	go establishPipeFromFile(error_pipe, stderr)
	go establishPipeFromFile(output_pipe, stdout)

	if _error := command.Start(); _error != nil {
		log.Error(fmt.Sprintf("Error starting MCPService subprocess: %v", _error))
		return _error
	}

	if timeout > 0 {
		waitCh := make(chan error, 1)
		go func() {
			waitCh <- command.Wait()
		}()
		select {
		case _error = <-waitCh:
		case <-time.After(time.Duration(timeout) * time.Second):
			log.Warn("Timeout reached")

			return nil
		}
	} else {
		_error = command.Wait()
	}

	if _error != nil {
		log.Error(fmt.Sprintf("Error waiting for MCPService subprocess: %v", _error))
		return _error
	}
	return nil
}

func (mcpCmd *McpCommand) runWithTimeout(timeout int, cmd string, envVars map[string]string) (err error) {
	err_ := jas.DownloadAnalyzerManagerIfNeeded(0)
	if err_ != nil {
		log.Error(fmt.Sprintf("Failed to download Analyzer Manager: %v", err))
	}
	return RunAmMcpWithPipes(envVars, cmd, mcpCmd.InputPipe, mcpCmd.OutputPipe, mcpCmd.ErrorPipe, timeout, mcpCmd.Arguments...)
}

func (mcpCmd *McpCommand) Run() (err error) {
	am_env, err := jas.GetAnalyzerManagerEnvVariables(mcpCmd.ServerDetails)
	if err != nil {
		return err
	}
	if entitled, err := isEntitledForSourceMCP(mcpCmd.ServerDetails); err != nil {
		return err
	} else if !entitled {
		return fmt.Errorf("it appears your current license doesn't include this feature.\nTo enable this functionality, an upgraded license is required. Please contact your JFrog representative for more details")
	}
	return mcpCmd.runWithTimeout(0, cmd, am_env)
}

func isEntitledForSourceMCP(serverDetails *config.ServerDetails) (entitled bool, err error) {
	xrayManager, err := xray.CreateXrayServiceManager(serverDetails)
	if err != nil {
		return
	}
	xrayVersion, err := xrayManager.GetVersion()
	if err != nil {
		return
	}
	return xray.IsEntitled(xrayManager, xrayVersion, mcpEntitlement)
}
