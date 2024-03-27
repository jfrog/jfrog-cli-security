package utils

import (
	"github.com/jfrog/jfrog-cli-security/tests"
	"github.com/jfrog/jfrog-client-go/artifactory/services/utils/tests/xsc"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestCalcShouldReportEvents(t *testing.T) {
	// Save original environment information.
	originalJfMsi := os.Getenv("JF_MSI")
	defer func() {
		err := os.Setenv("JF_MSI", originalJfMsi)
		assert.NoError(t, err)
	}()
	originalReportUsage := os.Getenv("JFROG_CLI_REPORT_USAGE")
	defer func() {
		err := os.Setenv("JFROG_CLI_REPORT_USAGE", originalReportUsage)
		assert.NoError(t, err)
	}()

	// Msi was already provided.
	err := os.Setenv("JF_MSI", "msi")
	assert.NoError(t, err)
	am := AnalyticsMetricsService{}
	assert.False(t, am.calcShouldReportEvents())

	// Report usage is false.
	err = os.Setenv("JF_MSI", "")
	assert.NoError(t, err)
	err = os.Setenv("JFROG_CLI_REPORT_USAGE", "false")
	assert.NoError(t, err)
	assert.False(t, am.calcShouldReportEvents())

	//TODO add version verification- i want to create mock and test it in unit test and not with specific env and version
}

func TestSendNewGeneralEventRequestToXsc(t *testing.T) {
	// TODO i need to work with a real env although its not full integration test
	// TODO this are clients tests mocks
	xsc.StartXscMockServer(t)
	am, err := NewAnalyticsMetricsService(tests.XscDetails)
	assert.NoError(t, err)
	err = am.AddGeneralEvent()
	assert.NoError(t, err)
	assert.NotEmpty(t, am.GetMsi())
}
