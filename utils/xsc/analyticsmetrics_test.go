package xsc

import (
	"errors"
	"fmt"
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
			expectedShouldReport: true,
		},
		{
			name:                 "Lower Xsc version",
			mockParams:           validations.MockServerParams{XrayVersion: xscutils.MinXrayVersionXscTransitionToXray, XscVersion: lowerAnalyticsMetricsMinXscVersion},
			expectedShouldReport: false,
		},
		{
			name:                 "Higher Xsc version",
			mockParams:           validations.MockServerParams{XrayVersion: xscutils.MinXrayVersionXscTransitionToXray, XscVersion: higherAnalyticsMetricsMinXscVersion},
			expectedShouldReport: true,
		},
		{
			name:                 "JFROG_CLI_REPORT_USAGE is false",
			mockParams:           validations.MockServerParams{XrayVersion: xscutils.MinXrayVersionXscTransitionToXray, XscVersion: higherAnalyticsMetricsMinXscVersion},
			setEnvVarReportFalse: true,
			expectedShouldReport: false,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, _ := validations.XscServer(t, testcase.mockParams)
			defer mockServer.Close()

			if testcase.setEnvVarReportFalse {
				err := os.Setenv(utils.JfMsiEnvVariable, "")
				assert.NoError(t, err)
				err = os.Setenv(coreutils.ReportUsage, "false")
				assert.NoError(t, err)
			}

			if testcase.expectedShouldReport {
				assert.True(t, shouldReportEvents(testcase.mockParams.XscVersion))
			} else {
				assert.False(t, shouldReportEvents(testcase.mockParams.XscVersion))
			}
		})
	}
}

func TestSendStartScanEvent(t *testing.T) {
	testCases := []struct {
		name        string
		mockParams  validations.MockServerParams
		reportUsage bool
		expectedMsi string
	}{
		{
			name: "Don't report events - user disabled feature",
			mockParams: validations.MockServerParams{
				XrayVersion: xscutils.MinXrayVersionXscTransitionToXray,
				XscVersion:  xscservices.AnalyticsMetricsMinXscVersion,
				ReturnMsi:   "test-msi",
			},
			expectedMsi: "",
		},
		{
			name: "Xsc service in xray",
			mockParams: validations.MockServerParams{
				XrayVersion: xscutils.MinXrayVersionXscTransitionToXray,
				XscVersion:  xscservices.AnalyticsMetricsMinXscVersion,
				ReturnMsi:   "other-msi",
			},
			reportUsage: true,
			expectedMsi: "other-msi",
		},
		{
			name: "Deprecated Xsc version",
			mockParams: validations.MockServerParams{
				XrayVersion: "3.0.0",
				XscVersion:  xscservices.AnalyticsMetricsMinXscVersion,
				ReturnMsi:   "diff-msi",
			},
			reportUsage: true,
			expectedMsi: "diff-msi",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			msiCallback := tests.SetEnvWithCallbackAndAssert(t, utils.JfMsiEnvVariable, "")
			defer msiCallback()
			usageCallback := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, fmt.Sprintf("%t", testCase.reportUsage))
			defer usageCallback()

			mockServer, serverDetails := validations.XscServer(t, testCase.mockParams)
			defer mockServer.Close()

			msi, startTime := SendNewScanEvent(testCase.mockParams.XrayVersion, testCase.mockParams.XscVersion, serverDetails, CreateAnalyticsEvent(xscservices.CliProduct, xscservices.CliEventType, serverDetails))
			if testCase.reportUsage {
				assert.NotEmpty(t, startTime)
			}
			assert.Equal(t, testCase.expectedMsi, msi)
		})
	}
}

func TestCreateFinalizedEvent(t *testing.T) {

	time := time.Now()

	testCases := []struct {
		name         string
		auditResults *results.SecurityCommandResults
		expected     xscservices.XscAnalyticsGeneralEventFinalize
	}{
		{
			name:         "No audit results",
			auditResults: &results.SecurityCommandResults{MultiScanId: "msi", StartTime: time},
			expected: xscservices.XscAnalyticsGeneralEventFinalize{
				XscAnalyticsBasicGeneralEvent: xscservices.XscAnalyticsBasicGeneralEvent{EventStatus: xscservices.Completed},
			},
		},
		{
			name:         "Valid audit result",
			auditResults: getDummyContentForGeneralEvent(true, false, false),
			expected: xscservices.XscAnalyticsGeneralEventFinalize{
				XscAnalyticsBasicGeneralEvent: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 7, EventStatus: xscservices.Completed},
			},
		},
		{
			name:         "Scan failed with findings",
			auditResults: getDummyContentForGeneralEvent(false, true, false),
			expected: xscservices.XscAnalyticsGeneralEventFinalize{
				XscAnalyticsBasicGeneralEvent: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 1, EventStatus: xscservices.Failed},
			},
		},
		{
			name:         "Valid audit results with Watches and GitRepoUrl",
			auditResults: getDummyContentForGeneralEvent(false, false, true),
			expected: xscservices.XscAnalyticsGeneralEventFinalize{
				XscAnalyticsBasicGeneralEvent: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 1, EventStatus: xscservices.Completed},
				GitRepoUrl:                    "github.com/my-user/my-repo.git",
			},
		},
		{
			name:         "Scan failed no findings.",
			auditResults: &results.SecurityCommandResults{MultiScanId: "msi", StartTime: time, Targets: []*results.TargetResults{{Errors: []error{errors.New("an error")}}}},
			expected: xscservices.XscAnalyticsGeneralEventFinalize{
				XscAnalyticsBasicGeneralEvent: xscservices.XscAnalyticsBasicGeneralEvent{TotalFindings: 0, EventStatus: xscservices.Failed},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			event := createFinalizedEvent(testCase.auditResults)
			assert.Equal(t, testCase.expected.TotalFindings, event.TotalFindings)
			assert.Equal(t, testCase.expected.EventStatus, event.EventStatus)
			assert.Equal(t, testCase.expected.GitRepoUrl, event.GitRepoUrl)
			assert.Equal(t, testCase.auditResults.MultiScanId, event.MultiScanId)
			assert.NotEmpty(t, event.TotalScanDuration)
		})
	}
}

// Create a dummy content for general event. 1 SCA scan with 1 vulnerability
// withJas - Add 2 JAS results for each scan type.
// withErr - Add an error to the results.
func getDummyContentForGeneralEvent(withJas, withErr, withResultContext bool) *results.SecurityCommandResults {
	vulnerabilities := []services.Vulnerability{{IssueId: "XRAY-ID", Severity: "medium", Cves: []services.Cve{{Id: "CVE-123"}}, Components: map[string]services.Component{"issueId_2_direct_dependency": {}}}}

	cmdResults := results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true).SetSecretValidation(true)
	cmdResults.StartTime = time.Now()
	cmdResults.MultiScanId = "msi"
	scanResults := cmdResults.NewScanResults(results.ScanTarget{Target: "target"})
	scanResults.NewScaScanResults(0, services.ScanResponse{Vulnerabilities: vulnerabilities})

	if withJas {
		scanResults.JasResults.ApplicabilityScanResults = validations.NewMockJasRuns(sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyPassingResult("applic_CVE-123")))

		scanResults.JasResults.JasVulnerabilities.SecretsScanResults = validations.NewMockJasRuns(
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 0, 0, 0, 0, ""))),
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 1, 1, 1, 1, ""))),
		)
		scanResults.JasResults.JasVulnerabilities.IacScanResults = validations.NewMockJasRuns(
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 0, 0, 0, 0, ""))),
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 1, 1, 1, 1, ""))),
		)
		scanResults.JasResults.JasVulnerabilities.SastScanResults = validations.NewMockJasRuns(
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 0, 0, 0, 0, ""))),
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("", 1, 1, 1, 1, ""))),
		)
	}

	if withErr {
		scanResults.Errors = []error{errors.New("an error")}
	}

	if withResultContext {
		cmdResults.SetResultsContext(results.ResultContext{
			GitRepoHttpsCloneUrl: "https://github.com/my-user/my-repo",
		})
	}

	return cmdResults
}
