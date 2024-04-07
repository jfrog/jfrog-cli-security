package utils

import (
	"errors"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

const (
	lowerAnalyticsMetricsMinXscVersion  = "1.6.0"
	higherAnalyticsMetricsMinXscVersion = "1.10.0"
)

func TestCalcShouldReportEvents(t *testing.T) {
	// Save original environment information.
	msiCallback := tests.SetEnvWithCallbackAndAssert(t, JfMsiEnvVariable, "")
	defer msiCallback()
	reportUsageCallback := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "")
	defer reportUsageCallback()

	// Minimum Xsc version.
	mockServer, serverDetails := xscServer(t, xscservices.AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	assert.True(t, am.calcShouldReportEvents())

	// Lower Xsc version.
	mockServerLowerVersion, serverDetails := xscServer(t, lowerAnalyticsMetricsMinXscVersion)
	defer mockServerLowerVersion.Close()
	am = NewAnalyticsMetricsService(serverDetails)
	assert.False(t, am.calcShouldReportEvents())

	// Higher Xsc version.
	mockServerHigherVersion, serverDetails := xscServer(t, higherAnalyticsMetricsMinXscVersion)
	defer mockServerHigherVersion.Close()
	am = NewAnalyticsMetricsService(serverDetails)
	assert.True(t, am.calcShouldReportEvents())

	// JFROG_CLI_REPORT_USAGE is false.
	err := os.Setenv(JfMsiEnvVariable, "")
	assert.NoError(t, err)
	err = os.Setenv(coreutils.ReportUsage, "false")
	assert.NoError(t, err)
	assert.False(t, am.calcShouldReportEvents())
}

func TestAddGeneralEvent(t *testing.T) {
	msiCallback := tests.SetEnvWithCallbackAndAssert(t, JfMsiEnvVariable, "")
	defer msiCallback()
	usageCallback := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "true")
	defer usageCallback()
	// Successful flow.
	mockServer, serverDetails := xscServer(t, xscservices.AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	am.AddGeneralEvent(am.CreateGeneralEvent(xscservices.CliProduct, xscservices.CliEventType))
	assert.Equal(t, testMsi, am.GetMsi())

	// In case cli should not report analytics, verify that request won't be sent.
	am.shouldReportEvents = false
	am.SetMsi("test-msi")
	am.AddGeneralEvent(am.CreateGeneralEvent(xscservices.CliProduct, xscservices.CliEventType))
	assert.Equal(t, "test-msi", am.GetMsi())
}

func TestAnalyticsMetricsService_createAuditResultsFromXscAnalyticsBasicGeneralEvent(t *testing.T) {
	usageCallback := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "true")
	defer usageCallback()
	vulnerabilities := []services.Vulnerability{{IssueId: "CVE-123", Components: map[string]services.Component{"issueId_2_direct_dependency": {}}}}
	scaResults := []ScaScanResult{{XrayResults: []services.ScanResponse{{Vulnerabilities: vulnerabilities}}}}
	auditResults := Results{
		ScaResults: scaResults,
		ExtendedScanResults: &ExtendedScanResults{
			ApplicabilityScanResults: []*sarif.Run{{}, {}},
			SecretsScanResults:       []*sarif.Run{{}, {}},
			IacScanResults:           []*sarif.Run{{}, {}},
			SastScanResults:          []*sarif.Run{{}, {}},
		},
	}
	testStruct := []struct {
		name         string
		auditResults *Results
		want         xscservices.XscAnalyticsBasicGeneralEvent
	}{
		{name: "No audit results", auditResults: &Results{}, want: xscservices.XscAnalyticsBasicGeneralEvent{EventStatus: xscservices.Completed}},
		{name: "Valid audit result", auditResults: &auditResults, want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 7, EventStatus: xscservices.Completed}},
		{name: "Scan failed because jas errors.", auditResults: &Results{JasError: errors.New("jas error"), ScaResults: scaResults}, want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 1, EventStatus: xscservices.Failed}},
		{name: "Scan failed because sca errors.", auditResults: &Results{JasError: errors.New("sca error")}, want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 0, EventStatus: xscservices.Failed}},
	}
	mockServer, serverDetails := xscServer(t, xscservices.AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	am.SetStartTime()
	time.Sleep(1)
	for _, tt := range testStruct {
		t.Run(tt.name, func(t *testing.T) {
			event := am.CreateXscAnalyticsGeneralEventFinalizeFromAuditResults(tt.auditResults)
			assert.Equal(t, tt.want.TotalFindings, event.TotalFindings)
			assert.Equal(t, tt.want.EventStatus, event.EventStatus)
			totalDuration, err := time.ParseDuration(event.TotalScanDuration)
			assert.NoError(t, err)
			assert.True(t, totalDuration > 0)
		})
	}
}
