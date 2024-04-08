package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc"
	"github.com/jfrog/jfrog-client-go/xsc/services"

	clientconfig "github.com/jfrog/jfrog-client-go/config"
)

const minXscVersionForErrorReport = "1.7.0"

func CreateXscServiceManager(serviceDetails *config.ServerDetails) (*xsc.XscServicesManager, error) {
	xscDetails, err := serviceDetails.CreateXscAuthConfig()
	if err != nil {
		return nil, err
	}
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(xscDetails).
		Build()
	if err != nil {
		return nil, err
	}
	return xsc.New(serviceConfig)
}

func SendXscLogMessageIfEnabled(errorLog *services.ExternalErrorLog, xscManager *xsc.XscServicesManager) error {
	if !reportLogErrorEventPossible(xscManager) {
		return nil
	}
	err := xscManager.SendXscLogErrorRequest(errorLog)
	if err == nil {
		log.Info("Error successfully reported to Coralogix")
	}
	return err
}

// / Determines if reporting to Coralogix is feasible.
// Reporting to Coralogix is not feasible under the following conditions: inability to reach the Xsc server, Xsc server is disabled, or Xsc version is below the minimum required version.
func reportLogErrorEventPossible(xscManager *xsc.XscServicesManager) bool {
	xscVersion, err := xscManager.GetVersion()
	if err != nil {
		log.Warn(fmt.Sprintf("failed to check availability of Xsc service:%s\nReporting to Coralogix is skipped...", err.Error()))
		return false
	}
	if xscVersion == "" {
		log.Warn("Xsc service is not available. Reporting to Coralogix is skipped...")
		return false
	}
	if err = clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, minXscVersionForErrorReport); err != nil {
		log.Warn("Xsc version must be 1.7.0 or above in order to use Coralogix report service. Reporting to Coralogix is skipped...")
		return false
	}
	return true
}
