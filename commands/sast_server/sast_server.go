package sast_server

import (
	"fmt"
	"io"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
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

func (sastCmd *SastServerCommand) runWithTimeout(timeout int, envVars map[string]string) (err error) {
	return jas.RunAnalyzerManagerWithPipesAndDownload(envVars, cmd, sastCmd.InputPipe, sastCmd.OutputPipe, sastCmd.ErrorPipe, timeout, sastCmd.Arguments...)
}

func (sastCmd *SastServerCommand) Run() (err error) {
	amEnv, err := jas.GetAnalyzerManagerEnvVariables(sastCmd.ServerDetails)
	if err != nil {
		return err
	}
	if entitled, err := isEntitledForSastServer(sastCmd.ServerDetails); err != nil {
		return err
	} else if !entitled {
		return fmt.Errorf("it appears your current license doesn't include this feature.\nTo enable this functionality, an upgraded license is required. Please contact your JFrog representative for more details")
	}
	return sastCmd.runWithTimeout(0, amEnv)
}

func isEntitledForSastServer(serverDetails *config.ServerDetails) (entitled bool, err error) {
	xrayManager, err := xray.CreateXrayServiceManager(serverDetails)
	if err != nil {
		return
	}
	xrayVersion, err := xrayManager.GetVersion()
	if err != nil {
		return
	}
	return jas.IsEntitledForJas(xrayManager, xrayVersion)
}
