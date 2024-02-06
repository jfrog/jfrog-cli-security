package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
)

func CreateXrayServiceManager(serviceDetails *config.ServerDetails) (*xray.XrayServicesManager, error) {
	xrayDetails, err := serviceDetails.CreateXrayAuthConfig()
	if err != nil {
		return nil, err
	}
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(xrayDetails).
		Build()
	if err != nil {
		return nil, err
	}
	return xray.New(serviceConfig)
}

func CreateXrayServiceManagerAndGetVersion(serviceDetails *config.ServerDetails) (*xray.XrayServicesManager, string, error) {
	xrayManager, err := CreateXrayServiceManager(serviceDetails)
	if err != nil {
		return nil, "", err
	}
	xrayVersion, err := xrayManager.GetVersion()
	if err != nil {
		return nil, "", err
	}
	return xrayManager, xrayVersion, nil
}

func SendXscGitInfoRequestIfEnabled(graphScanParams *services.XrayGraphScanParams, xrayManager *xray.XrayServicesManager) (err error) {
	if graphScanParams.XscVersion, err = xrayManager.XscEnabled(); err != nil {
		return err
	}
	if graphScanParams.XscVersion != "" && graphScanParams.MultiScanId == "" {
		multiScanId, err := xrayManager.SendXscGitInfoRequest(graphScanParams.XscGitInfoContext)
		if err != nil {
			return fmt.Errorf("failed sending Git Info request to XSC service, error: %s ", err.Error())
		}
		graphScanParams.MultiScanId = multiScanId
		log.Debug(fmt.Sprintf("Created xsc git info successfully. multi_scan_id %s", multiScanId))
		if err = os.Setenv("JF_MSI", multiScanId); err != nil {
			// Not a fatal error, if not set the scan will not be shown at the XSC UI, should not fail the scan.
			log.Debug(fmt.Sprintf("failed setting MSI as environment variable. Cause: %s", err.Error()))
		}
	}
	return nil
}
