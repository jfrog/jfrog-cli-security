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
func ReportError(xrayVersion, xscVersion string, serverDetails *config.ServerDetails, errorToReport error, source string) error {
	if xscVersion == "" {
		log.Debug("Xsc service is not available. Reporting to JFrog analytics is skipped...")
		return nil
	}
	log.Debug("Sending an error report to JFrog analytics...")
	xscService, err := CreateXscService(xrayVersion, serverDetails)
	if err != nil {
		return fmt.Errorf("failed to create an HTTP client: %s.\nReporting to JFrog analytics is skipped", err.Error())
	}
	errorLog := &services.ExternalErrorLog{
		Log_level: "error",
		Source:    source,
		Message:   errorToReport.Error(),
	}
	return sendXscLogMessageIfEnabled(xscVersion, errorLog, xscService)
}

func sendXscLogMessageIfEnabled(xscVersion string, errorLog *services.ExternalErrorLog, xscService xsc.XscService) error {
	if !IsReportLogErrorEventPossible(xscVersion) {
		return nil
	}
	return xscService.SendXscLogErrorRequest(errorLog)
}

// Determines if reporting the error is feasible.
func IsReportLogErrorEventPossible(xscVersion string) bool {
	if err := clientutils.ValidateMinimumVersion(clientutils.Xsc, xscVersion, MinXscVersionForErrorReport); err != nil {
		log.Debug(err.Error())
		return false
	}
	return true
}
