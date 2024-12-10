package xsc

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/jfrog/jfrog-client-go/xsc/services/utils"
)

func GetConfigProfileByName(xrayVersion, xscVersion string, serverDetails *config.ServerDetails, profileName string) (*services.ConfigProfile, error) {
	if !utils.IsXscXrayInnerService(xrayVersion) {
		// We need to validate xsc version only if we use a Xray version prior to Xsc migration
		if err := clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, services.ConfigProfileMinXscVersion); err != nil {
			log.Info(fmt.Sprintf("Minimal Xsc version required to utilize config profile by url is '%s'. All configurations will be induced from provided Env vars and files", services.ConfigProfileByUrlMinXrayVersion))
			return nil, err
		}
	}
	xscService, err := CreateXscService(xrayVersion, serverDetails)
	if err != nil {
		return nil, err
	}
	configProfile, err := xscService.GetConfigProfileByName(profileName)
	if err != nil {
		err = fmt.Errorf("failed to get config profile '%s': %q", profileName, err)
	}
	return configProfile, err
}

// TODO eran write test to this func
func GetConfigProfileByUrl(xrayVersion string, serverDetails *config.ServerDetails) (*services.ConfigProfile, error) {
	if err := clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, services.ConfigProfileByUrlMinXrayVersion); err != nil {
		log.Info(fmt.Sprintf("Minimal Xray version required to utilize config profile by url is '%s'. All configurations will be induced from provided Env vars and files", services.ConfigProfileByUrlMinXrayVersion))
		return nil, err
	}
	xscService, err := CreateXscService(xrayVersion, serverDetails)
	if err != nil {
		return nil, err
	}
	configProfile, err := xscService.GetConfigProfileByUrl(serverDetails.Url)
	if err != nil {
		err = fmt.Errorf("failed to get config profile for url '%s': %q", serverDetails.Url, err)
	}
	return configProfile, err
}
