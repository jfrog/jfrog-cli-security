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

	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	"github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"

	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

func TestReportError(t *testing.T) {
	cleanUp := integration.InitXscTest(t, func() {securityTestUtils.ValidateXscVersion(t, xsc.MinXscVersionForErrorReport)})
	defer cleanUp()
	errorToReport := errors.New("THIS IS NOT A REAL ERROR! This Error is posted as part of TestReportError test")
	assert.NoError(t, xsc.ReportError(tests.XscDetails, errorToReport, "cli"))
}


// In the npm tests we use a watch flag, so we would get only violations
func TestXscAuditNpmJsonWithWatch(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := testAuditNpm(t, string(format.Json), false)
	securityTestUtils.VerifyJsonScanResults(t, output, 1, 0, 1)
}

func TestXscAuditNpmSimpleJsonWithWatch(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := testAuditNpm(t, string(format.SimpleJson), true)
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1, 1)
}

func TestXscAuditMavenJson(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := testXscAuditMaven(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}

func TestXscAuditMavenSimpleJson(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := testXscAuditMaven(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 0, 1, 1)
}

func TestXscAnalyticsForAudit(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	// Scan npm project and verify that analytics general event were sent to XSC.
	output := testAuditNpm(t, string(format.SimpleJson), false)
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

func TestAdvancedSecurityDockerScanWithXsc(t *testing.T) {
	testCli, cleanup := initNativeDockerWithXrayTest(t)
	restoreFunc := initXscTest(t)
	defer restoreFunc()
	defer cleanup()
	runAdvancedSecurityDockerScan(t, testCli, "jfrog/demo-security:latest")
}
