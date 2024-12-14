package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/progressbar"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"

	"github.com/jfrog/jfrog-cli-security/cli"
	"github.com/jfrog/jfrog-cli-security/cli/docs"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	"github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"

	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/jfrog/jfrog-client-go/xray/services/utils"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

func TestReportError(t *testing.T) {
	xrayVersion, xscVersion, cleanUp := integration.InitXscTest(t, func() { securityTestUtils.ValidateXscVersion(t, xsc.MinXscVersionForErrorReport) })
	defer cleanUp()
	errorToReport := errors.New("THIS IS NOT A REAL ERROR! This Error is posted as part of TestReportError test")
	assert.NoError(t, xsc.ReportError(xrayVersion, xscVersion, tests.XscDetails, errorToReport, "cli"))
}

// In the npm tests we use a watch flag, so we would get only violations
func TestXscAuditNpmJsonWithWatch(t *testing.T) {
	_, _, cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := testAuditNpm(t, string(format.Json), false)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Violations: 1},
	})
}

func TestXscAuditNpmSimpleJsonWithWatch(t *testing.T) {
	_, _, cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := testAuditNpm(t, string(format.SimpleJson), true)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Violations: 1, Vulnerabilities: 1},
	})
}

func TestXscAuditViolationsWithIgnoreRule(t *testing.T) {
	// Init XSC tests also enabled analytics reporting.
	_, _, cleanUpXsc := integration.InitXscTest(t, func() { securityTestUtils.ValidateXrayVersion(t, services.MinXrayVersionGitRepoKey) })
	defer cleanUpXsc()
	// Create the audit command with git repo context injected.
	cliToRun, cleanUpHome := integration.InitTestWithMockCommandOrParams(t, false, getAuditCommandWithXscGitContext(validations.TestMockGitInfo))
	defer cleanUpHome()
	// Create the project to scan
	_, cleanUpProject := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(tests.GetTestResourcesPath()), "projects", "jas", "jas"))
	defer cleanUpProject()
	// Create a watch for the git repo so we will also get violations
	// TODO: how to create a watch and policy connected to a git repo?
	_, cleanUpWatch := securityTestUtils.CreateTestWatch(t, "git-repo-policy", "git-repo-watch", utils.Critical)
	defer cleanUpWatch()
	// Run the audit command with git repo and verify violations are reported to the platform.
	output := testAuditCommand(t, cliToRun, auditCommandTestParams{Format: string(format.SimpleJson), WithLicense: true, WithVuln: true})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Licenses: 100, Violations: 100, Vulnerabilities: 100}})
	// Create an ignore rule for the git repo
	securityTestUtils.CreateTestIgnoreRule(t, utils.IgnoreFilters{GitRepositories: []string{validations.TestMockGitInfo.GitRepoHttpsCloneUrl}})
	// Run the audit command and verify no issues.
	output = testAuditCommand(t, cliToRun, auditCommandTestParams{Format: string(format.SimpleJson)})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{ExactResultsMatch: true, Total: &validations.TotalCount{}})
}

// TODO: replace with 'Git Audit' command when it will be available.
// This method generate an audit command that will report analytics (if enabled) with the git info context provided.
// The method will generate multi-scan-id and provide it to the audit command.
// The method will also provide the git repo clone url to the audit command.
func getAuditCommandWithXscGitContext(gitInfoContext xscservices.XscGitInfoContext) func() components.Command {
	return func() components.Command {
		return components.Command{
			Name:  docs.Audit,
			Flags: docs.GetCommandFlags(docs.Audit),
			Action: func(c *components.Context) error {
				xrayVersion, xscVersion, serverDetails, auditCmd, err := cli.CreateAuditCmd(c)
				if err != nil {
					return err
				}
				// Generate the analytics event with the git info context.
				event := xsc.CreateAnalyticsEvent(xscservices.CliProduct, xscservices.CliEventType, serverDetails)
				event.GitInfo = &gitInfoContext
				event.IsGitInfoFlow = true
				// Report analytics and get the multi scan id that was generated and attached to the git context.
				multiScanId, startTime := xsc.SendNewScanEvent(xrayVersion, xscVersion, serverDetails, event)
				// Set the multi scan id to the audit command to be used in the scans.
				auditCmd.SetMultiScanId(multiScanId)
				// Set the git repo context to the audit command to pass to the scanners to create violations if applicable.
				auditCmd.SetGitRepoHttpsCloneUrl(gitInfoContext.GitRepoHttpsCloneUrl)
				err = progressbar.ExecWithProgress(auditCmd)
				// Send the final event to the platform.
				xsc.SendScanEndedEvent(xrayVersion, xscVersion, serverDetails, multiScanId, startTime, 0, err)
				return err
			},
		}
	}
}

func TestXscAuditMavenJson(t *testing.T) {
	_, _, cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := testAuditMaven(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

func TestXscAuditMavenSimpleJson(t *testing.T) {
	_, _, cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	output := testAuditMaven(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

func TestXscAnalyticsForAudit(t *testing.T) {
	xrayVersion, xscVersion, cleanUp := integration.InitXscTest(t)
	defer cleanUp()
	// Scan npm project and verify that analytics general event were sent to XSC.
	output := testAuditNpm(t, string(format.SimpleJson), false)
	validateAnalyticsBasicEvent(t, xrayVersion, xscVersion, output)
}

func validateAnalyticsBasicEvent(t *testing.T, xrayVersion, xscVersion, output string) {
	// Get MSI.
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)

	// Verify analytics metrics.
	event, err := xsc.GetScanEvent(xrayVersion, xscVersion, results.MultiScanId, tests.XscDetails)
	assert.NoError(t, err)
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
	_, _, cleanUpXsc := integration.InitXscTest(t)
	defer cleanUpXsc()
	testCli, cleanupDocker := integration.InitNativeDockerTest(t)
	defer cleanupDocker()
	runAdvancedSecurityDockerScan(t, testCli, "jfrog/demo-security:latest")
}
