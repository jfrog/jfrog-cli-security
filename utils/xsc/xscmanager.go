package xsc

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
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

func GetXscMsiAndVersion(analyticsMetricsService *AnalyticsMetricsService) (multiScanId, xscVersion string) {
	var err error
	if analyticsMetricsService != nil {
		multiScanId = analyticsMetricsService.GetMsi()
	}
	if multiScanId != "" {
		xscManager := analyticsMetricsService.XscManager()
		if xscManager != nil {
			xscVersion, err = xscManager.GetVersion()
			if err != nil {
				log.Debug(fmt.Sprintf("Can't get XSC version for xray graph scan params. Cause: %s", err.Error()))
			}
		}
	}
	return
}
