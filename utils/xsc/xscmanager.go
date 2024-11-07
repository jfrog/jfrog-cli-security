package xsc

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/xsc"
)

const MinXscVersionForErrorReport = "1.7.7"

func CreateXscServiceManager(serviceDetails *config.ServerDetails) (*xsc.XscServicesManager, error) {
	certsPath, err := coreutils.GetJfrogCertsDir()
	if err != nil {
		return nil, err
	}
	xscDetails, err := serviceDetails.CreateXscAuthConfig()
	if err != nil {
		return nil, err
	}
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(xscDetails).
		SetCertificatesPath(certsPath).
		SetInsecureTls(serviceDetails.InsecureTls).
		Build()
	if err != nil {
		return nil, err
	}
	return xsc.New(serviceConfig)
}

func CreateXscServiceManagerAndGetVersion(serviceDetails *config.ServerDetails) (*xsc.XscServicesManager, string, error) {
	xscManager, err := CreateXscServiceManager(serviceDetails)
	if err != nil {
		return nil, "", err
	}
	xscVersion, err := xscManager.GetVersion()
	if err != nil {
		return nil, "", err
	}
	return xscManager, xscVersion, nil
}
