package xsc

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

func GetConfigProfile(xrayVersion, xscVersion string, serverDetails *config.ServerDetails, profileName string) (*services.ConfigProfile, error) {
	if err := clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, services.ConfigProfileMinXscVersion); err != nil {
		log.Info("Minimal Xsc version required to utilize config profile is '%s'. All configurations will be induced from provided Env vars and files")
		return nil, err
	}
	xscService, err := CreateXscServiceBackwardCompatible(xrayVersion, serverDetails)
	if err != nil {
		return nil, err
	}
	configProfile, err := xscService.GetConfigProfileByName(profileName)
	if err != nil {
		err = fmt.Errorf("failed to get config profile '%s': %q", profileName, err)
	}
	return configProfile, err
}
