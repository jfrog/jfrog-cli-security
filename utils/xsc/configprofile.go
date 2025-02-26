package xsc

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

func GetConfigProfileByName(xrayVersion string, serverDetails *config.ServerDetails, profileName string) (*services.ConfigProfile, error) {
	if err := clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, services.ConfigProfileNewSchemaMinXrayVersion); err != nil {
		log.Info(fmt.Sprintf("Minimal Xray version required to use a configProfile is by name '%s'. All configurations will be induced from provided Env vars and files", services.ConfigProfileNewSchemaMinXrayVersion))
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

func GetConfigProfileByUrl(xrayVersion string, serverDetails *config.ServerDetails, cloneRepoUrl string) (*services.ConfigProfile, error) {
	if err := clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, services.ConfigProfileNewSchemaMinXrayVersion); err != nil {
		log.Info(fmt.Sprintf("Minimal Xray version required to use a configProfile is by url '%s'. All configurations will be induced from provided Env vars and files", services.ConfigProfileNewSchemaMinXrayVersion))
		return nil, err
	}
	xscService, err := CreateXscService(serverDetails)
	if err != nil {
		return nil, err
	}
	configProfile, err := xscService.GetConfigProfileByUrl(cloneRepoUrl)
	if err != nil {
		err = fmt.Errorf("failed to get config profile for url '%s': %q", serverDetails.Url, err)
	}
	return configProfile, err
}
