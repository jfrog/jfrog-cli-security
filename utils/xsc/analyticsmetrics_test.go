package xsc

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

const (
	lowerAnalyticsMetricsMinXscVersion  = "1.6.0"
	higherAnalyticsMetricsMinXscVersion = "1.10.0"
)

func TestCalcShouldReportEvents(t *testing.T) {
	// Save original environment information.
	msiCallback := tests.SetEnvWithCallbackAndAssert(t, utils.JfMsiEnvVariable, "")
	defer msiCallback()
	reportUsageCallback := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "")
	defer reportUsageCallback()

	// Minimum Xsc version.
	mockServer, serverDetails := validations.XscServer(t, xscservices.AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	assert.True(t, am.calcShouldReportEvents())

	// Lower Xsc version.
	mockServerLowerVersion, serverDetails := validations.XscServer(t, lowerAnalyticsMetricsMinXscVersion)
	defer mockServerLowerVersion.Close()
	am = NewAnalyticsMetricsService(serverDetails)
	assert.False(t, am.calcShouldReportEvents())

	// Higher Xsc version.
	mockServerHigherVersion, serverDetails := validations.XscServer(t, higherAnalyticsMetricsMinXscVersion)
	defer mockServerHigherVersion.Close()
	am = NewAnalyticsMetricsService(serverDetails)
	assert.True(t, am.calcShouldReportEvents())

	// JFROG_CLI_REPORT_USAGE is false.
	err := os.Setenv(utils.JfMsiEnvVariable, "")
	assert.NoError(t, err)
	err = os.Setenv(coreutils.ReportUsage, "false")
	assert.NoError(t, err)
	assert.False(t, am.calcShouldReportEvents())
}

func TestAddGeneralEvent(t *testing.T) {
	msiCallback := tests.SetEnvWithCallbackAndAssert(t, utils.JfMsiEnvVariable, "")
	defer msiCallback()
	usageCallback := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "true")
	defer usageCallback()
	// Successful flow.
	mockServer, serverDetails := validations.XscServer(t, xscservices.AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	am.AddGeneralEvent(am.CreateGeneralEvent(xscservices.CliProduct, xscservices.CliEventType))
	assert.Equal(t, validations.TestMsi, am.GetMsi())

	// In case cli should not report analytics, verify that request won't be sent.
	am.shouldReportEvents = false
	am.SetMsi("test-msi")
	am.AddGeneralEvent(am.CreateGeneralEvent(xscservices.CliProduct, xscservices.CliEventType))
	assert.Equal(t, "test-msi", am.GetMsi())
}

func TestAnalyticsMetricsService_createAuditResultsFromXscAnalyticsBasicGeneralEvent(t *testing.T) {
	usageCallback := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "true")
	defer usageCallback()

	testStruct := []struct {
		name         string
		auditResults *results.SecurityCommandResults
		want         xscservices.XscAnalyticsBasicGeneralEvent
	}{
		{name: "No audit results", auditResults: &results.SecurityCommandResults{}, want: xscservices.XscAnalyticsBasicGeneralEvent{EventStatus: xscservices.Completed}},
		{name: "Valid audit result", auditResults: getDummyContentForGeneralEvent(true, false), want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 7, EventStatus: xscservices.Completed}},
		{name: "Scan failed with findings.", auditResults: getDummyContentForGeneralEvent(false, true), want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 1, EventStatus: xscservices.Failed}},
		{name: "Scan failed no findings.", auditResults: &results.SecurityCommandResults{Targets: []*results.TargetResults{{Errors: []error{errors.New("an error")}}}}, want: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 0, EventStatus: xscservices.Failed}},
	}
	mockServer, serverDetails := validations.XscServer(t, xscservices.AnalyticsMetricsMinXscVersion)
	defer mockServer.Close()
	am := NewAnalyticsMetricsService(serverDetails)
	am.SetStartTime()
	time.Sleep(time.Millisecond)
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

// Create a dummy content for general event. 1 SCA scan with 1 vulnerability
// withJas - Add 2 JAS results for each scan type.
// withErr - Add an error to the results.
func getDummyContentForGeneralEvent(withJas, withErr bool) *results.SecurityCommandResults {
	vulnerabilities := []services.Vulnerability{{IssueId: "XRAY-ID", Severity: "medium", Cves: []services.Cve{{Id: "CVE-123"}}, Components: map[string]services.Component{"issueId_2_direct_dependency": {}}}}

	cmdResults := results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true).SetSecretValidation(true)
	scanResults := cmdResults.NewScanResults(results.ScanTarget{Target: "target"})
	scanResults.NewScaScanResults(services.ScanResponse{Vulnerabilities: vulnerabilities})

	if withJas {
		scanResults.JasResults.ApplicabilityScanResults = []*sarif.Run{sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyPassingResult("applic_CVE-123"))}
		scanResults.JasResults.SecretsScanResults = []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 0, 0, 0, 0, ""))),
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 1, 1, 1, 1, ""))),
		}
		scanResults.JasResults.IacScanResults = []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 0, 0, 0, 0, ""))),
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 1, 1, 1, 1, ""))),
		}
		scanResults.JasResults.SastScanResults = []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 0, 0, 0, 0, ""))),
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 1, 1, 1, 1, ""))),
		}
	}

	if withErr {
		scanResults.Errors = []error{errors.New("an error")}
	}

	return cmdResults
}
