package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
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
		reportPossible := IsReportLogErrorEventPossible(xscManager)
		if testcase.expectedResponse {
			assert.True(t, reportPossible)
		} else {
			assert.False(t, reportPossible)
		}
		mockServer.Close()
	}
}
