package utils

import (
	"errors"
	"fmt"
	coretests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
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
	originalJfMsi := os.Getenv(jfMsiEnvVariable)
	defer func() {
		err := os.Setenv(jfMsiEnvVariable, originalJfMsi)
		assert.NoError(t, err)
	}()
	originalReportUsage := os.Getenv(coreutils.ReportUsage)
	defer func() {
		err := os.Setenv(coreutils.ReportUsage, originalReportUsage)
		assert.NoError(t, err)
	}()

	err := os.Setenv(coreutils.ReportUsage, "")
	assert.NoError(t, err)
	err = os.Setenv(jfMsiEnvVariable, "")
	assert.NoError(t, err)

	// Minimum Xsc version.
	mockServer, serverDetails := xscServer(t, AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	assert.True(t, am.calcShouldReportEvents())

	// Lower Xsc version.
	mockServer, serverDetails = xscServer(t, lowerAnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am = NewAnalyticsMetricsService(serverDetails)
	assert.False(t, am.calcShouldReportEvents())

	// Higher Xsc version.
	mockServer, serverDetails = xscServer(t, higherAnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am = NewAnalyticsMetricsService(serverDetails)
	assert.True(t, am.calcShouldReportEvents())

	// JF_MSI was already provided.
	err = os.Setenv(jfMsiEnvVariable, "msi")
	assert.NoError(t, err)
	assert.False(t, am.calcShouldReportEvents())

	// JFROG_CLI_REPORT_USAGE is false.
	err = os.Setenv(jfMsiEnvVariable, "")
	assert.NoError(t, err)
	err = os.Setenv(coreutils.ReportUsage, "false")
	assert.NoError(t, err)
	assert.False(t, am.calcShouldReportEvents())
}

func TestAddGeneralEventAndSetMsi(t *testing.T) {
	originalMsi := os.Getenv(jfMsiEnvVariable)
	defer func() {
		assert.NoError(t, os.Setenv(jfMsiEnvVariable, originalMsi))
	}()

	// Successful flow.
	mockServer, serverDetails := xscServer(t, AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	params := services.XrayGraphScanParams{}
	am.AddGeneralEventAndSetMsi(&params)
	assert.NotEmpty(t, am.GetMsi())
	assert.Equal(t, params.MultiScanId, am.GetMsi())
	assert.Equal(t, am.GetMsi(), os.Getenv(jfMsiEnvVariable))

	// In case cli should not report analytics, verify that request won't be sent.
	am.shouldReportEvents = false
	am.SetMsi("test-msi")
	am.AddGeneralEventAndSetMsi(&params)
	assert.Equal(t, "test-msi", am.GetMsi())
}

func TestCreateAuditResultsFromXscAnalyticsBasicGeneralEvent(t *testing.T) {
	mockServer, serverDetails := xscServer(t, AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	am.SetStartTime()

	// no audit results
	event := am.createAuditResultsFromXscAnalyticsBasicGeneralEvent(&Results{})
	assert.Equal(t, 0, event.TotalFindings)

	// audit result, each scan has 2 result (total 10 scan results).
	auditResults := Results{
		ScaResults: []ScaScanResult{{}, {}},
		ExtendedScanResults: &ExtendedScanResults{
			ApplicabilityScanResults: []*sarif.Run{{}, {}},
			SecretsScanResults:       []*sarif.Run{{}, {}},
			IacScanResults:           []*sarif.Run{{}, {}},
			SastScanResults:          []*sarif.Run{{}, {}},
		},
	}
	event = am.createAuditResultsFromXscAnalyticsBasicGeneralEvent(&auditResults)

	assert.Equal(t, 10, event.TotalFindings)
	assert.Equal(t, xscservices.Completed, event.EventStatus)
	totalDuration, err := time.ParseDuration(event.TotalScanDuration)
	assert.NoError(t, err)
	assert.True(t, totalDuration > 0)

	// Scan failed because sca/jas errors.
	auditResults.JasError = errors.New("jas error")
	event = am.createAuditResultsFromXscAnalyticsBasicGeneralEvent(&auditResults)
	assert.Equal(t, 10, event.TotalFindings)
	assert.Equal(t, xscservices.Failed, event.EventStatus)
	totalDuration, err = time.ParseDuration(event.TotalScanDuration)
	assert.NoError(t, err)
	assert.True(t, totalDuration > 0)

	auditResults.ScaError = errors.New("sca error")
	auditResults.JasError = nil
	event = am.createAuditResultsFromXscAnalyticsBasicGeneralEvent(&auditResults)
	assert.Equal(t, xscservices.Failed, event.EventStatus)
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
