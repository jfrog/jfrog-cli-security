package xsc

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

func GetConfigProfile(serverDetails *config.ServerDetails, profileName string) (*services.ConfigProfile, error) {
	xscManager, err := CreateXscServiceManager(serverDetails)
	if err != nil {
		return nil, err
	}

	xscVersion, err := xscManager.GetVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get XSC service version: %q", err)
	}

	if err = clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, services.ConfigProfileMinXscVersion); err != nil {
		log.Info("Minimal Xsc version required to utilize config profile is '%s'. All configurations will be induced from provided Env vars and files")
		return nil, err
	}

	configProfile, err := xscManager.GetConfigProfile(profileName)
	if err != nil {
		err = fmt.Errorf("failed to get config profile '%s': %q", profileName, err)
	}
	return configProfile, err
}
