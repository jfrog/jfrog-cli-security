package xsc

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	clienttestutils "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xsc/services/utils"
	"github.com/stretchr/testify/assert"
)

const (
	unsupportedXscVersionForErrorLogs = "1.6.0"
	supportedXscVersionForErrorLogs   = MinXscVersionForErrorReport
)

func TestReportLogErrorEventPossible(t *testing.T) {
	restoreEnvVarFunc := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "")
	defer restoreEnvVarFunc()

	testCases := []struct {
		name       string
		testParams validations.MockServerParams
		// serverCreationFunc func() (*httptest.Server, *config.ServerDetails)
		expectedResponse bool
	}{
		{
			name:             "Deprecate Server - Send Error fail - Xsc service is not enabled",
			testParams:       validations.MockServerParams{XrayVersion: "3.0.0", XscVersion: supportedXscVersionForErrorLogs, XscNotExists: true},
			expectedResponse: false,
		},
		{
			name:             "Deprecate Server - Send Error fail - Xsc version too low",
			testParams:       validations.MockServerParams{XrayVersion: "3.0.0", XscVersion: unsupportedXscVersionForErrorLogs},
			expectedResponse: false,
		},
		{
			name:             "Deprecate Server - Send Error success",
			testParams:       validations.MockServerParams{XrayVersion: "3.0.0", XscVersion: supportedXscVersionForErrorLogs},
			expectedResponse: true,
		},
		{
			name:             "Send Error fail - Xsc version too low",
			testParams:       validations.MockServerParams{XrayVersion: utils.MinXrayVersionXscTransitionToXray, XscVersion: unsupportedXscVersionForErrorLogs},
			expectedResponse: false,
		},
		{
			name:             "Send Error success",
			testParams:       validations.MockServerParams{XrayVersion: utils.MinXrayVersionXscTransitionToXray, XscVersion: supportedXscVersionForErrorLogs},
			expectedResponse: true,
		},
	}
	for _, testcase := range testCases {
		mockServer, serverDetails := validations.XscServer(t, testcase.testParams)
		xscService, err := CreateXscService(testcase.testParams.XrayVersion, serverDetails)
		assert.NoError(t, err)
		reportPossible := IsReportLogErrorEventPossible(testcase.testParams.XscVersion, xscService)
		if testcase.expectedResponse {
			assert.True(t, reportPossible)
		} else {
			assert.False(t, reportPossible)
		}
		mockServer.Close()
	}
}
