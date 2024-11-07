package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	"github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"

	"github.com/jfrog/jfrog-client-go/xray/services"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

func TestReportError(t *testing.T) {
	cleanUp := integration.InitXscTest(t, func() { securityTestUtils.ValidateXscVersion(t, xsc.MinXscVersionForErrorReport) })
	defer cleanUp()
	errorToReport := errors.New("THIS IS NOT A REAL ERROR! This Error is posted as part of TestReportError test")
	assert.NoError(t, xsc.ReportError(tests.XscDetails, errorToReport, "cli"))
}

// In the npm tests we use a watch flag, so we would get only violations
func TestXscAuditNpmJsonWithWatch(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := runAuditNpm(t, string(format.Json), false)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		SecurityViolations: 1,
		Licenses:           1,
	})
}

func TestXscAuditNpmSimpleJsonWithWatch(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := runAuditNpm(t, string(format.SimpleJson), true)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		SecurityViolations: 1,
		Vulnerabilities:    1,
		Licenses:           1,
	})
}

func TestXscAuditMavenJson(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := runXscAuditMaven(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Licenses:        1,
	})
}

func TestXscAuditMavenSimpleJson(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := runXscAuditMaven(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Licenses:        1,
	})
}

func TestXscAnalyticsForAudit(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	// Scan npm project and verify that analytics general event were sent to XSC.
	output := runAuditNpm(t, string(format.SimpleJson), false)
	validateAnalyticsBasicEvent(t, output)
}

func validateAnalyticsBasicEvent(t *testing.T, output string) (event *xscservices.XscAnalyticsGeneralEvent) {
	// Get MSI.
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)

	// Verify analytics metrics.
	am := xsc.NewAnalyticsMetricsService(tests.XscDetails)
	assert.NotNil(t, am)
	assert.NotEmpty(t, results.MultiScanId)
	event, err = am.GetGeneralEvent(results.MultiScanId)
	assert.NoError(t, err)

	// Event creation and addition information.
	assert.Equal(t, xscservices.CliProduct, event.Product)
	assert.Equal(t, xscservices.CliEventType, event.EventType)
	assert.NotEmpty(t, event.AnalyzerManagerVersion)
	assert.NotEmpty(t, event.EventStatus)
	// The information that was added after updating the event with the scan's results.
	assert.NotEmpty(t, event.TotalScanDuration)
	assert.True(t, event.TotalFindings > 0)
	return
}

func TestXscAnalyticsGitAudit(t *testing.T) {
	cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	// scan a dirty git project and validate with XSC
	output := runGitAudit(t, "dirty")
	validateAnalyticsGitEvent(t, output, services.XscGitInfoContext{
		GitRepoUrl:  "https://github.com/attiasas/test-security-git.git",
		GitRepoName: "test-security-git",
		GitProject:  "attiasas",
		GitProvider: "github",
		BranchName:  "dirty_branch",
		LastCommit:  "5fc36ff0666e5ce9dba6c0a1c539ee640cabe0b0",
	})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		ExactResultsMatch: true,
		Iac:               1,
		Vulnerabilities:   5,
	})
}
func validateAnalyticsGitEvent(t *testing.T, output string, expected services.XscGitInfoContext) {
	event := validateAnalyticsBasicEvent(t, output)
	require.NotNil(t, event.GitInfo)
	assert.Equal(t, expected, *event.GitInfo)
}

func TestAdvancedSecurityDockerScanWithXsc(t *testing.T) {
	cleanUpXsc := integration.InitXscTest(t)
	defer cleanUpXsc()
	testCli, cleanupDocker := integration.InitNativeDockerTest(t)
	defer cleanupDocker()
	runAdvancedSecurityDockerScan(t, testCli, "jfrog/demo-security:latest")
}
