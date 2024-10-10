package xsc

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

// Sends an error report when the Xsc service is enabled.
// Errors returned by this function typically do not disrupt the flow, as reporting errors is optional.
func ReportError(serverDetails *config.ServerDetails, errorToReport error, source string) error {
	log.Debug("Sending an error report to JFrog analytics...")
	xscManager, err := CreateXscServiceManager(serverDetails)
	if err != nil {
		return fmt.Errorf("failed to create an HTTP client: %s.\nReporting to JFrog analytics is skipped...", err.Error())
	}

	errorLog := &services.ExternalErrorLog{
		Log_level: "error",
		Source:    source,
		Message:   errorToReport.Error(),
	}
	return sendXscLogMessageIfEnabled(errorLog, xscManager)
}

func sendXscLogMessageIfEnabled(errorLog *services.ExternalErrorLog, xscManager *xsc.XscServicesManager) error {
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
	if err = clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, MinXscVersionForErrorReport); err != nil {
		log.Debug(err.Error())
		return false
	}
	return true
}
