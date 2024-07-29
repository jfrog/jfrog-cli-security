package detect

import (
	"fmt"

	"github.com/jfrog/jfrog-client-go/utils/log"
	
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-security/utils/results/output"
)

type DetectAppsCommand struct {
	serverDetails *config.ServerDetails
}

func NewDetectAppsCommand(serverDetails *config.ServerDetails) *DetectAppsCommand {
	return &DetectAppsCommand{serverDetails: serverDetails}
}

func (daCmd *DetectAppsCommand) CommandName() string {
	return "detect"
}

func (daCmd *DetectAppsCommand) ServerDetails() (*config.ServerDetails, error) {
	return daCmd.serverDetails, nil
}

func (daCmd *DetectAppsCommand) Run() (err error) {
	serverDetails, err := daCmd.ServerDetails()
	if err != nil {
		return
	}
	appsConfig, err := RunDetectSecurityConfig(serverDetails, daCmd.params)
	if err != nil {
		return
	}
	// Print output
	log.Info(fmt.Sprintf("Detected %d targets for security scanning with the following configuration", len(appsConfig.Targets)))
	output.PrintJson(appsConfig)
	return err
}

func RunDetectSecurityConfig(serverDetails *config.ServerDetails, params *AppsDetectParams) (*configs.AppsSecurityConfig, error) {

}