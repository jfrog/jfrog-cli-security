package utils

import (
	"errors"
	"fmt"
	coretests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const (
	testMsi                             = "27e175b8-e525-11ee-842b-7aa2c69b8f1f"
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
	mockServer, serverDetails := xscServer(t, AnalyticsMetricsMinXscVersion)
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

	// JF_MSI was already provided.
	err := os.Setenv(JfMsiEnvVariable, "msi")
	assert.NoError(t, err)
	assert.False(t, am.calcShouldReportEvents())

	// JFROG_CLI_REPORT_USAGE is false.
	err = os.Setenv(JfMsiEnvVariable, "")
	assert.NoError(t, err)
	err = os.Setenv(coreutils.ReportUsage, "false")
	assert.NoError(t, err)
	assert.False(t, am.calcShouldReportEvents())
}

func TestAddGeneralEvent(t *testing.T) {
	msiCallback := tests.SetEnvWithCallbackAndAssert(t, JfMsiEnvVariable, "")
	defer msiCallback()
	// Successful flow.
	mockServer, serverDetails := xscServer(t, AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	am.AddGeneralEvent(am.CreateGeneralEvent(CliProduct, CliEventType))
	assert.Equal(t, am.GetMsi(), testMsi)

	// In case cli should not report analytics, verify that request won't be sent.
	am.shouldReportEvents = false
	am.SetMsi("test-msi")
	am.AddGeneralEvent(am.CreateGeneralEvent(CliProduct, CliEventType))
	assert.Equal(t, "test-msi", am.GetMsi())
}

func TestAnalyticsMetricsService_createAuditResultsFromXscAnalyticsBasicGeneralEvent(t *testing.T) {
	auditResults := Results{
		ScaResults: []ScaScanResult{{}, {}},
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
		{name: "Valid audit result", auditResults: &auditResults, want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 10, EventStatus: xscservices.Completed}},
		{name: "Scan failed because jas errors.", auditResults: &Results{JasError: errors.New("jas error"), ScaResults: []ScaScanResult{{}, {}}}, want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 2, EventStatus: xscservices.Failed}},
		{name: "Scan failed because sca errors.", auditResults: &Results{JasError: errors.New("sca error")}, want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 0, EventStatus: xscservices.Failed}},
	}
	mockServer, serverDetails := xscServer(t, AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	am.SetStartTime()
	for _, tt := range testStruct {
		t.Run(tt.name, func(t *testing.T) {
			event := am.createAuditResultsFromXscAnalyticsBasicGeneralEvent(tt.auditResults)
			assert.Equal(t, tt.want.TotalFindings, event.TotalFindings)
			assert.Equal(t, tt.want.EventStatus, event.EventStatus)
			totalDuration, err := time.ParseDuration(event.TotalScanDuration)
			assert.NoError(t, err)
			assert.True(t, totalDuration > 0)
		})
	}
}

func xscServer(t *testing.T, xscVersion string) (*httptest.Server, *config.ServerDetails) {
	serverMock, serverDetails, _ := coretests.CreateXscRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/xsc/api/v1/system/version" {
			_, err := w.Write([]byte(fmt.Sprintf(`{"xsc_version": "%s"}`, xscVersion)))
			if err != nil {
				return
			}
		}
		if r.RequestURI == "/xsc/api/v1/event" {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, err := w.Write([]byte(fmt.Sprintf(`{"multi_scan_id": "%s"}`, testMsi)))
				if err != nil {
					return
				}
			}
		}
	})
	return serverMock, serverDetails
}
