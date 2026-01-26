package source_mcp

import (
	"fmt"
	"io"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
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

func (mcpCmd *McpCommand) runWithTimeout(timeout int, cmd string, envVars map[string]string) (err error) {
	return jas.RunAnalyzerManagerWithPipesAndDownload(envVars, cmd, mcpCmd.InputPipe, mcpCmd.OutputPipe, mcpCmd.ErrorPipe, timeout, mcpCmd.Arguments...)
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
