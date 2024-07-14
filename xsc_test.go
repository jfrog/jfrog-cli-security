package main

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	"github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"

	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

func TestReportError(t *testing.T) {
	serverDetails := &config.ServerDetails{
		Url:            *tests.JfrogUrl,
		ArtifactoryUrl: *tests.JfrogUrl + tests.ArtifactoryEndpoint,
		XrayUrl:        *tests.JfrogUrl + tests.XrayEndpoint,
		AccessToken:    *tests.JfrogAccessToken,
		ServerId:       tests.ServerId,
	}

	// Prior to initiating the test, we verify whether Xsc is enabled for the customer. If not, the test is skipped.
	xscManager, err := xsc.CreateXscServiceManager(serverDetails)
	assert.NoError(t, err)

	if !xsc.IsReportLogErrorEventPossible(xscManager) {
		t.Skip("Skipping test since Xsc server is not enabled or below minimal required version")
	}

	errorToReport := errors.New("THIS IS NOT A REAL ERROR! This Error is posted as part of TestReportError test")
	assert.NoError(t, xsc.ReportError(serverDetails, errorToReport, "cli"))
}

func initXscTest(t *testing.T) func() {
	// Make sure the audit request will work with xsc and not xray
	assert.NoError(t, os.Setenv(coreutils.ReportUsage, "true"))
	return func() {
		assert.NoError(t, os.Setenv(coreutils.ReportUsage, "false"))
	}
}

// In the npm tests we use a watch flag, so we would get only violations
func TestXscAuditNpmJsonWithWatch(t *testing.T) {
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	output := testAuditNpm(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		SecurityViolations: 1,
		Licenses:           1,
	})
}

func TestXscAuditNpmSimpleJsonWithWatch(t *testing.T) {
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	output := testAuditNpm(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		SecurityViolations: 1,
		Licenses:           1,
	})
}

func TestXscAuditMavenJson(t *testing.T) {
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	output := testXscAuditMaven(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Licenses:        1,
	})
}

func TestXscAuditMavenSimpleJson(t *testing.T) {
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	output := testXscAuditMaven(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Licenses:        1,
	})
}

func TestXscAnalyticsForAudit(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	securityTestUtils.ValidateXscVersion(t, xscservices.AnalyticsMetricsMinXscVersion)
	reportUsageCallBack := clientTests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "true")
	defer reportUsageCallBack()
	// Scan npm project and verify that analytics general event were sent to XSC.
	output := testAuditNpm(t, string(format.SimpleJson))
	validateAnalyticsBasicEvent(t, output)
}

func validateAnalyticsBasicEvent(t *testing.T, output string) {
	// Get MSI.
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)

	// Verify analytics metrics.
	am := xsc.NewAnalyticsMetricsService(tests.XscDetails)
	assert.NotNil(t, am)
	assert.NotEmpty(t, results.MultiScanId)
	event, err := am.GetGeneralEvent(results.MultiScanId)
	assert.NoError(t, err)

	// Event creation and addition information.
	assert.Equal(t, xscservices.CliProduct, event.Product)
	assert.Equal(t, xscservices.CliEventType, event.EventType)
	assert.NotEmpty(t, event.AnalyzerManagerVersion)
	assert.NotEmpty(t, event.EventStatus)
	// The information that was added after updating the event with the scan's results.
	assert.NotEmpty(t, event.TotalScanDuration)
	assert.True(t, event.TotalFindings > 0)
}
