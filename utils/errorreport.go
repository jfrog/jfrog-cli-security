package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
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
	return SendXscLogMessageIfEnabled(errorLog, xscManager)
}
