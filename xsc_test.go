package main

import (
	"encoding/json"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/scangraph"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestXscAnalyticsForAudit(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion, services.AnalyticsMetricsMinXscVersion)
	reportUsageCallBack := tests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "true")
	defer reportUsageCallBack()
	// Scan npm project and verify that analytics general event were sent to XSC.
	output := testXrayAuditNpm(t, string(format.SimpleJson))
	validateAnalyticsBasicEvent(t, output)
}

func validateAnalyticsBasicEvent(t *testing.T, output string) {
	// Get MSI.
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)

	// Verify analytics metrics.
	am := utils.NewAnalyticsMetricsService(securityTests.XscDetails)
	assert.NotNil(t, am)
	event, err := am.GetGeneralEvent(results.MultiScanId)
	assert.NoError(t, err)

	// Event creation and addition information.
	assert.Equal(t, "cli", event.Product)
	assert.Equal(t, 1, event.EventType)
	assert.NotEmpty(t, event.EventStatus)
	assert.NotEmpty(t, event.AnalyzerManagerVersion)
	// The information that was added after updating the event with the scan's results.
	assert.NotEmpty(t, event.TotalScanDuration)
	assert.True(t, event.TotalFindings > 0)
}
