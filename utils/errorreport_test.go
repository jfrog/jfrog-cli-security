package utils

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/tests"
	clienttestutils "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	unsupportedXscVersionForErrorLogs = "1.6.0"
	supportedXscVersionForErrorLogs   = minXscVersionForErrorReport
)

func TestReportError(t *testing.T) {
	serverDetails := &config.ServerDetails{
		Url:            *tests.JfrogUrl,
		ArtifactoryUrl: *tests.JfrogUrl + tests.ArtifactoryEndpoint,
		XrayUrl:        *tests.JfrogUrl + tests.XrayEndpoint,
		AccessToken:    *tests.JfrogAccessToken,
		ServerId:       tests.ServerId,
	}

	// Prior to initiating the test, we verify whether Xsc is enabled for the customer. If not, the test is skipped.
	xscManager, err := CreateXscServiceManager(serverDetails)
	assert.NoError(t, err)

	if !isReportLogErrorEventPossible(xscManager) {
		t.Skip("Skipping test since Xsc server is not enabled or below minimal required version")
	}

	errorToReport := errors.New("THIS IS NOT A REAL ERROR! This Error is posted as part of TestReportError test")
	assert.NoError(t, ReportError(serverDetails, errorToReport, "cli"))
}

func TestReportLogErrorEventPossible(t *testing.T) {
	restoreEnvVarFunc := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "")
	defer restoreEnvVarFunc()

	testCases := []struct {
		serverCreationFunc func() (*httptest.Server, *config.ServerDetails)
		expectedResponse   bool
	}{
		{
			serverCreationFunc: func() (*httptest.Server, *config.ServerDetails) {
				serverMock, serverDetails, _ := CreateXscRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
					if r.RequestURI == "/xsc/api/v1/system/version" {
						w.WriteHeader(http.StatusNotFound)
						_, innerError := w.Write([]byte("Xsc service is not enabled"))
						if innerError != nil {
							return
						}
					}
				})
				return serverMock, serverDetails
			},
			expectedResponse: false,
		},
		{
			serverCreationFunc: func() (*httptest.Server, *config.ServerDetails) { return xscServer(t, "") },
			expectedResponse:   false,
		},
		{
			serverCreationFunc: func() (*httptest.Server, *config.ServerDetails) {
				return xscServer(t, unsupportedXscVersionForErrorLogs)
			},
			expectedResponse: false,
		},
		{
			serverCreationFunc: func() (*httptest.Server, *config.ServerDetails) { return xscServer(t, supportedXscVersionForErrorLogs) },
			expectedResponse:   true,
		},
	}

	for _, testcase := range testCases {
		mockServer, serverDetails := testcase.serverCreationFunc()
		xscManager, err := CreateXscServiceManager(serverDetails)
		assert.NoError(t, err)
		reportPossible := isReportLogErrorEventPossible(xscManager)
		if testcase.expectedResponse {
			assert.True(t, reportPossible)
		} else {
			assert.False(t, reportPossible)
		}
		mockServer.Close()
	}
}
