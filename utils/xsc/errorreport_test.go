package xsc

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	clienttestutils "github.com/jfrog/jfrog-client-go/utils/tests"
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
		name             string
		xscVersion       string
		expectedResponse bool
	}{
		{
			name:             "Send Error fail - Xsc service is not enabled",
			xscVersion:       "",
			expectedResponse: false,
		},
		{
			name:             "Send Error fail - Xsc version too low",
			xscVersion:       unsupportedXscVersionForErrorLogs,
			expectedResponse: false,
		},
		{
			name:             "Send Error success",
			xscVersion:       supportedXscVersionForErrorLogs,
			expectedResponse: true,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			reportPossible := IsReportLogErrorEventPossible(testcase.xscVersion)
			if testcase.expectedResponse {
				assert.True(t, reportPossible)
			} else {
				assert.False(t, reportPossible)
			}
		})
	}
}
