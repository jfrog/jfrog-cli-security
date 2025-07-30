package source_mcp

import (
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type McpCommand struct {
	Env        map[string]string
	Arguments  []string
	InputPipe  io.Reader
	OutputPipe io.Writer
	ErrorPipe  io.Writer
}

func establishPipeToFile(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Error("Error establishing pipe")
	}
}

func establishPipeFromFile(dst io.Writer, src io.ReadCloser) {
	defer src.Close()
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
	defer stdin.Close()

	stdout, _error := command.StdoutPipe()
	if _error != nil {
		log.Error(fmt.Sprintf("Error creating MCPService stdout pipe: %v", _error))
		return _error
	}
	defer stdout.Close()

	stderr, _error := command.StderrPipe()
	if _error != nil {
		log.Error(fmt.Sprintf("Error creating MCPService stderr pipe: %v", _error))
		return _error
	}
	defer stderr.Close()

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

func (mcpCmd *McpCommand) runWithTimeout(timeout int, cmd string) (err error) {
	err_ := jas.DownloadAnalyzerManagerIfNeeded(0)
	if err_ != nil {
		log.Error(fmt.Sprintf("Failed to download Analyzer Manager: %v", err))
	}

	return RunAmMcpWithPipes(mcpCmd.Env, cmd, mcpCmd.InputPipe, mcpCmd.OutputPipe, mcpCmd.ErrorPipe, timeout, mcpCmd.Arguments...)
}

func (mcpCmd *McpCommand) Run() (err error) {
	return mcpCmd.runWithTimeout(0, "mcp-sast")
}
