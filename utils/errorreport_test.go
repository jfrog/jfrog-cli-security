package utils

import (
	"errors"
	coretests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/tests"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"
)

const (
	unsupportedXscVersionForErrorLogs = "1.6.0"
	supportedXscVersionForErrorLogs   = "1.7.5"
)

func TestReportToCoralogix(t *testing.T) {
	serverDetails := &config.ServerDetails{
		Url:            *tests.JfrogUrl,
		ArtifactoryUrl: *tests.JfrogUrl + tests.ArtifactoryEndpoint,
		XrayUrl:        *tests.JfrogUrl + tests.XrayEndpoint,
		AccessToken:    *tests.JfrogAccessToken,
		ServerId:       tests.ServerId,
	}

	// Before initiating the test we check if Xsc is enabled for the customer. If not - the test is skipped
	xscManager, err := CreateXscServiceManager(serverDetails)
	assert.NoError(t, err)

	if !reportLogErrorEventPossible(xscManager) {
		t.Skip("Skipping test since Xsc server is not enabled or below minimal required version")
	}

	errorToReport := errors.New("THIS IS NOT A REAL ERROR! This Error is posted as part of TestReportToCoralogix test")
	assert.NoError(t, ReportToCoralogix(serverDetails, errorToReport, "cli"))
}

func TestReportLogErrorEventPossible(t *testing.T) {
	// Save original environment variable value
	originalReportUsage := os.Getenv(coreutils.ReportUsage)
	defer func() {
		err := os.Setenv(coreutils.ReportUsage, originalReportUsage)
		assert.NoError(t, err)
	}()

	err := os.Setenv(coreutils.ReportUsage, "")
	assert.NoError(t, err)

	// Checking for negative response when an error is returned
	serverMock1, serverDetails, _ := coretests.CreateXscRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/xsc/api/v1/system/version" {
			w.WriteHeader(http.StatusNotFound)
			_, innerError := w.Write([]byte("Xsc service is not enabled"))
			if innerError != nil {
				return
			}
		}
	})
	defer serverMock1.Close()
	xscManager, err := CreateXscServiceManager(serverDetails)
	assert.NoError(t, err)
	assert.False(t, reportLogErrorEventPossible(xscManager))

	// Checking for negative response when an empty version is returned
	mockServer2, serverDetails := xscServer(t, "")
	defer mockServer2.Close()
	xscManager, err = CreateXscServiceManager(serverDetails)
	assert.NoError(t, err)
	assert.False(t, reportLogErrorEventPossible(xscManager))

	// Checking for negative response when Xsc version is below minXscVersionForErrorReport (1.7.0)
	mockServer3, serverDetails := xscServer(t, unsupportedXscVersionForErrorLogs)
	defer mockServer3.Close()
	xscManager, err = CreateXscServiceManager(serverDetails)
	assert.NoError(t, err)
	assert.False(t, reportLogErrorEventPossible(xscManager))

	//Checking for a positive response when Xsc is enabled and with version above 1.7.0
	mockServer4, serverDetails := xscServer(t, supportedXscVersionForErrorLogs)
	defer mockServer4.Close()
	xscManager, err = CreateXscServiceManager(serverDetails)
	assert.NoError(t, err)
	assert.True(t, reportLogErrorEventPossible(xscManager))

}