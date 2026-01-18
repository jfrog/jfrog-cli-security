package sast_server

import (
	"fmt"
	"io"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/source_mcp"
	"github.com/jfrog/jfrog-cli-security/jas"
)

const (
	cmd = "sast-server"
)

type SastServerCommand struct {
	ServerDetails *config.ServerDetails
	Arguments     []string
	InputPipe     io.Reader
	OutputPipe    io.Writer
	ErrorPipe     io.Writer
}

func (sastCmd *SastServerCommand) runWithTimeout(timeout int, cmd string, envVars map[string]string) (err error) {
	return source_mcp.RunAmWithPipesAndTimeout(envVars, cmd, sastCmd.InputPipe, sastCmd.OutputPipe, sastCmd.ErrorPipe, timeout, sastCmd.Arguments...)
}

func (sastCmd *SastServerCommand) Run() (err error) {
	am_env, err := jas.GetAnalyzerManagerEnvVariables(sastCmd.ServerDetails)
	if err != nil {
		return err
	}
	if entitled, err := source_mcp.IsEntitledForSourceMCP(sastCmd.ServerDetails); err != nil {
		return err
	} else if !entitled {
		return fmt.Errorf("it appears your current license doesn't include this feature.\nTo enable this functionality, an upgraded license is required. Please contact your JFrog representative for more details")
	}
	return sastCmd.runWithTimeout(0, cmd, am_env)
}
