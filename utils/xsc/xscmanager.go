package xsc

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc"
	"github.com/jfrog/jfrog-client-go/xsc/services"

	clientconfig "github.com/jfrog/jfrog-client-go/config"
)

const minXscVersionForErrorReport = "1.7.7"

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

func SendXscLogMessageIfEnabled(errorLog *services.ExternalErrorLog, xscManager *xsc.XscServicesManager) error {
	if !IsReportLogErrorEventPossible(xscManager) {
		return nil
	}
	return xscManager.SendXscLogErrorRequest(errorLog)
}

// Determines if reporting the error is feasible.
func IsReportLogErrorEventPossible(xscManager *xsc.XscServicesManager) bool {
	xscVersion, err := xscManager.GetVersion()
	if err != nil {
		log.Debug(fmt.Sprintf("failed to check availability of Xsc service:%s\nReporting to JFrog analytics is skipped...", err.Error()))
		return false
	}
	if xscVersion == "" {
		log.Debug("Xsc service is not available. Reporting to JFrog analytics is skipped...")
		return false
	}
	if err = clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, minXscVersionForErrorReport); err != nil {
		log.Debug(err.Error())
		return false
	}
	return true
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
