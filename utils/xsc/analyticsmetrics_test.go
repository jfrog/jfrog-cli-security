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
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"
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

	testCases := []struct {
		name                 string
		mockParams           validations.MockServerParams
		setEnvVarReportFalse bool
		expectedShouldReport bool
	}{
		{
			name:                 "Minimum Xsc version",
			mockParams:           validations.MockServerParams{XrayVersion: xscutils.MinXrayVersionXscTransitionToXray, XscVersion: xscservices.AnalyticsMetricsMinXscVersion},
			xscVersion:           xscservices.AnalyticsMetricsMinXscVersion,
			expectedShouldReport: true,
		},
		{
			name:                 "Lower Xsc version",
			xscVersion:           lowerAnalyticsMetricsMinXscVersion,
			expectedShouldReport: false,
		},
		{
			name:                 "Higher Xsc version",
			xscVersion:           higherAnalyticsMetricsMinXscVersion,
			expectedShouldReport: true,
		},
		{
			name:                 "JFROG_CLI_REPORT_USAGE is false",
			xscVersion:           higherAnalyticsMetricsMinXscVersion,
			setEnvVarReportFalse: true,
			expectedShouldReport: false,
		},
	}

	xrayVersion := xscutils.MinXrayVersionXscTransitionToXray
	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, _ := validations.XscServer(t, xrayVersion, testcase.xscVersion)
			defer mockServer.Close()

			if testcase.setEnvVarReportFalse {
				err := os.Setenv(utils.JfMsiEnvVariable, "")
				assert.NoError(t, err)
				err = os.Setenv(coreutils.ReportUsage, "false")
				assert.NoError(t, err)
			}

			if testcase.expectedShouldReport {
				assert.True(t, shouldReportEvents(testcase.xscVersion))
			} else {
				assert.False(t, shouldReportEvents(testcase.xscVersion))
			}
		})
	}
}

func TestSendStartScanEvent(t *testing.T) {
	testCases := []struct {
		name         string
		auditResults *results.SecurityCommandResults
		want         xscservices.XscAnalyticsBasicGeneralEvent
	}{
		{},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {

		})
	}
}

func TestSendScanEndedEvent(t *testing.T) {
	msiCallback := tests.SetEnvWithCallbackAndAssert(t, utils.JfMsiEnvVariable, "")
	defer msiCallback()
	usageCallback := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "true")
	defer usageCallback()

	testCases := []struct {
		name        string
		xrayVersion string
	}{}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockServer, serverDetails := validations.XscServer(t, testCase.xrayVersion, xscservices.AnalyticsMetricsMinXscVersion)
			defer mockServer.Close()

			xsc.SendNewScanEvent(testCase.xrayVersion, xscservices.AnalyticsMetricsMinXscVersion, "test-msi", serverDetails)
		})
	}
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
