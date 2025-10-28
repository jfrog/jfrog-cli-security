package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"

	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	"github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"

	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

func TestReportError(t *testing.T) {
	xrayVersion, xscVersion, cleanUp := integration.InitXscTest(t)
	securityTestUtils.ValidateXscVersion(t, xscVersion, xsc.MinXscVersionForErrorReport)
	defer cleanUp()
	errorToReport := errors.New("THIS IS NOT A REAL ERROR! This Error is posted as part of TestReportError test")
	assert.NoError(t, xsc.ReportError(xrayVersion, xscVersion, tests.XscDetails, errorToReport, "cli", ""))
}

// In the npm tests we use a watch flag, so we would get only violations
func TestXscAuditNpmJsonWithWatch(t *testing.T) {
	_, _, cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	testCases := []struct {
		name     string
		format   format.OutputFormat
		withVuln bool
	}{
		{
			name:   "No violations (JSON)",
			format: format.Json,
		},
		{
			name:     "No violations (Simple JSON)",
			format:   format.SimpleJson,
			withVuln: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validationsParams := validations.ValidationParams{
				Total:      &validations.TotalCount{Licenses: 1, Violations: 1},
				Violations: &validations.ViolationCount{ValidateType: &validations.ScaViolationCount{Security: 1}},
			}
			if tc.withVuln {
				validationsParams.Total.Vulnerabilities = 1
				validationsParams.Vulnerabilities = &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sca: 1}}
			}
			validations.ValidateCommandOutput(t, testAuditNpm(t, tc.format, "xsc-", tc.withVuln), tc.format, validationsParams)
		})
	}
}

func TestXscAuditMaven(t *testing.T) {
	_, _, cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	for _, format := range []format.OutputFormat{format.Json, format.SimpleJson} {
		t.Run(string(format), func(t *testing.T) {
			validations.ValidateCommandOutput(t, testAuditMaven(t, format), format, validations.ValidationParams{
				Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
			})
		})
	}
}

func TestXscAnalyticsForAudit(t *testing.T) {
	xrayVersion, xscVersion, cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	// Scan npm project and verify that analytics general event were sent to XSC.
	output := testAuditNpm(t, format.SimpleJson, "xsc-analytics", false)
	validateAnalyticsBasicEvent(t, xrayVersion, xscVersion, output)
}

func validateAnalyticsBasicEvent(t *testing.T, xrayVersion, xscVersion, output string) {
	// Get MSI.
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(output), &results)
	require.NoError(t, err)

	// Verify analytics metrics.
	event, err := xsc.GetScanEvent(xrayVersion, xscVersion, results.MultiScanId, tests.XscDetails, "")
	require.NoError(t, err)
	assert.NotNil(t, event)
	assert.NotEmpty(t, results.MultiScanId)

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
	testCli, cleanupDocker := integration.InitNativeDockerTest(t)
	defer cleanupDocker()
	cleanUpXsc := integration.PrepareXscForTest(t)
	defer cleanUpXsc()
	runAdvancedSecurityDockerScan(t, testCli, "jfrog/demo-security:latest")
}
