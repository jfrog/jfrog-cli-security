package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

type ReportService struct {
	client     *jfroghttpclient.JfrogHttpClient
	xscDetails auth.ServiceDetails
}

// Sends an error report to Coralogix if Xsc service is enabled.
// Errors that are returned by this function usually should not fail the flow since reporting to Coralogix is not mandatory.
func ReportToCoralogix(serverDetails *config.ServerDetails, errorToReport error, source string) error {
	log.Info("Sending an error report to Coralogix if Xsc service is enabled...")
	xscManager, err := CreateXscServiceManager(serverDetails)
	if err != nil {
		return fmt.Errorf("failed to create an HTTP client: %s.\nReporting to Coralogix is skipped...", err.Error())
	}

	errorLog := &services.ExternalErrorLog{
		Log_level: "error",
		Source:    source,
		Message:   errorToReport.Error(),
	}
	if err = SendXscLogMessageIfEnabled(errorLog, xscManager); err != nil {
		err = fmt.Errorf("%s.\nReporting to Coralogix is skipped...", err.Error())
	}
	return err
}
