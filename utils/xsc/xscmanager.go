package xsc

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xscservices "github.com/jfrog/jfrog-client-go/xray/services/xsc"
	"github.com/jfrog/jfrog-client-go/xsc"
	xscservicesutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"

	"github.com/jfrog/jfrog-cli-security/utils/xray"
)

const MinXscVersionForErrorReport = "1.7.7"

func CreateXscService(xrayVersion string, serviceDetails *config.ServerDetails) (xsc.XscService, error) {
	if xscservicesutils.IsXscXrayInnerService(xrayVersion) {
		return createXscService(serviceDetails)
	}
	return createDeprecatedXscServiceManager(serviceDetails)
}

func createXscService(serviceDetails *config.ServerDetails) (*xscservices.XscInnerService, error) {
	xrayManager, err := xray.CreateXrayServiceManager(serviceDetails)
	if err != nil {
		return nil, err
	}
	return xrayManager.Xsc(), nil
}

func createDeprecatedXscServiceManager(serviceDetails *config.ServerDetails) (*xsc.XscServicesManager, error) {
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

func GetJfrogServicesVersion(serverDetails *config.ServerDetails) (xrayVersion, xscVersion string, err error) {
	xrayManager, err := xray.CreateXrayServiceManager(serverDetails)
	if err != nil {
		return
	}
	xrayVersion, err = xrayManager.GetVersion()
	if err != nil {
		return
	}
	log.Debug("Xray version: " + xrayVersion)
	xscService, err := CreateXscService(xrayVersion, serverDetails)
	if err != nil {
		return
	}
	xscVersion, e := xscService.GetVersion()
	if e != nil {
		log.Debug("Using Xray: " + e.Error())
		return
	}
	log.Debug("XSC version: " + xscVersion)
	return
}
