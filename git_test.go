package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-security/commands/git/contributors"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/jfrog/jfrog-client-go/xray/services/utils"
	// xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"
)

func TestCountContributorsFlags(t *testing.T) {
	_, _, testCleanUp := integration.InitGitTest(t, "")
	defer testCleanUp()

	err := securityTests.PlatformCli.WithoutCredentials().Exec("git", "count-contributors", "--token", "token", "--owner", "owner", "--scm-api-url", "url")
	assert.EqualError(t, err, "Mandatory flag 'scm-type' is missing")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "cc", "--scm-type", "github", "--owner", "owner", "--scm-api-url", "url")
	assert.ErrorContains(t, err, "Mandatory flag 'token' is missing")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "cc", "--scm-type", "gitlab", "--token", "token", "--scm-api-url", "url")
	assert.EqualError(t, err, "Mandatory flag 'owner' is missing")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "cc", "--scm-type", "bitbucket", "--token", "token", "--owner", "owner")
	assert.EqualError(t, err, "Mandatory flag 'scm-api-url' is missing")

	// Test token env variable
	bitbucketCallback := tests.SetEnvWithCallbackAndAssert(t, contributors.BitbucketTokenEnvVar, "token")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "count-contributors", "--scm-type", "bitbucket", "--owner", "owner", "--scm-api-url", "url")
	assert.NotContains(t, err.Error(), "Providing a token is mandatory")
	bitbucketCallback()
	gitlabCallback := tests.SetEnvWithCallbackAndAssert(t, contributors.GitlabTokenEnvVar, "token")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "count-contributors", "--scm-type", "gitlab", "--owner", "owner", "--scm-api-url", "url")
	assert.NotContains(t, err.Error(), "Providing a token is mandatory")
	gitlabCallback()
	githubCallback := tests.SetEnvWithCallbackAndAssert(t, contributors.GithubTokenEnvVar, "token")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "count-contributors", "--scm-type", "github", "--owner", "owner", "--scm-api-url", "url")
	assert.NotContains(t, err.Error(), "Providing a token is mandatory")
	githubCallback()

	// Test unsupported scm type
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "cc", "--scm-type", "bad-type", "--token", "token", "--owner", "owner", "--scm-api-url", "url")
	assert.ErrorContains(t, err, "Unsupported SCM type")
}

func testGitAuditCommand(t *testing.T, params auditCommandTestParams) (string, error) {
	return securityTests.PlatformCli.RunCliCmdWithOutputs(t, append([]string{"git", "audit"}, getAuditCmdArgs(params)...)...)
}

// TODO: replace with 'Git Audit' command when it will be available.
// This method generate an audit command that will report analytics (if enabled) with the git info context provided.
// The method will generate multi-scan-id and provide it to the audit command.
// The method will also provide the git repo clone url to the audit command.
// func getAuditCommandWithXscGitContext(gitInfoContext xscservices.XscGitInfoContext) func() components.Command {
// 	return func() components.Command {
// 		return components.Command{
// 			Name:  docs.Audit,
// 			Flags: docs.GetCommandFlags(docs.Audit),
// 			Action: func(c *components.Context) error {
// 				xrayVersion, xscVersion, serverDetails, auditCmd, err := cli.CreateAuditCmd(c)
// 				if err != nil {
// 					return err
// 				}
// 				// Generate the analytics event with the git info context.
// 				event := xsc.CreateAnalyticsEvent(xscservices.CliProduct, xscservices.CliEventType, serverDetails)
// 				event.GitInfo = &gitInfoContext
// 				event.IsGitInfoFlow = true
// 				// Report analytics and get the multi scan id that was generated and attached to the git context.
// 				multiScanId, startTime := xsc.SendNewScanEvent(xrayVersion, xscVersion, serverDetails, event)
// 				// Set the multi scan id to the audit command to be used in the scans.
// 				auditCmd.SetMultiScanId(multiScanId)
// 				// Set the git repo context to the audit command to pass to the scanners to create violations if applicable.
// 				auditCmd.SetGitRepoHttpsCloneUrl(gitInfoContext.GitRepoHttpsCloneUrl)
// 				err = progressbar.ExecWithProgress(auditCmd)
// 				// Send the final event to the platform.
// 				xsc.SendScanEndedEvent(xrayVersion, xscVersion, serverDetails, multiScanId, startTime, 0, err)
// 				return err
// 			},
// 		}
// 	}
// }

func createTestProjectRunGitAuditAndValidate(t *testing.T, projectPath string, gitAuditParams auditCommandTestParams, xrayVersion, xscVersion, expectError string, validationParams validations.ValidationParams) {
	// Create the project to scan
	_, cleanUpProject := securityTestUtils.CreateTestProjectFromZipAndChdir(t, projectPath)
	defer cleanUpProject()
	// Run the audit command with git repo and verify violations are reported to the platform.
	output, err := testGitAuditCommand(t, gitAuditParams)
	if expectError != "" {
		assert.ErrorContains(t, err, expectError)
	} else {
		assert.NoError(t, err)
	}
	validations.VerifySimpleJsonResults(t, output, validationParams)
	validateAnalyticsBasicEvent(t, xrayVersion, xscVersion, output)
}

func TestGitAuditSimpleJson(t *testing.T) {
	xrayVersion, xscVersion, testCleanUp := integration.InitGitTest(t, scangraph.GraphScanMinXrayVersion)
	defer testCleanUp()
	createTestProjectRunGitAuditAndValidate(t,
		filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "git", "projects", "gitlab"),
		auditCommandTestParams{Format: string(format.SimpleJson), WithLicense: true, WithVuln: true},
		xrayVersion, xscVersion, "",
		validations.ValidationParams{
			Total: &validations.TotalCount{Licenses: 3, Vulnerabilities: 2},
			Vulnerabilities: &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sca: 2}},
		},
	)
}

func TestGitAuditViolationsWithIgnoreRule(t *testing.T) {
	xrayVersion, xscVersion, testCleanUp := integration.InitGitTest(t, services.MinXrayVersionGitRepoKey)
	defer testCleanUp()

	// // Create the project to scan
	// _, cleanUpProject := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "jas", "jas"))
	// defer cleanUpProject()

	projectPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "git", "projects", "issues")

	// Create policy and watch for the git repo so we will also get violations (unknown = all vulnerabilities will be reported as violations)
	policyName, cleanUpPolicy := securityTestUtils.CreateTestSecurityPolicy(t, "git-repo-ignore-rule-policy", utils.Unknown, true, false)
	defer cleanUpPolicy()
	_, cleanUpWatch := securityTestUtils.CreateWatchForTests(t, policyName, "git-repo-ignore-rule-watch", xscutils.GetGitRepoUrlKey(validations.TestMockGitInfo.GitRepoHttpsCloneUrl))
	defer cleanUpWatch()

	// Run the audit command with git repo and verify violations are reported to the platform.
	createTestProjectRunGitAuditAndValidate(t, projectPath,
		auditCommandTestParams{Format: string(format.SimpleJson), WithLicense: true, WithVuln: true},
		xrayVersion, xscVersion, "",
		validations.ValidationParams{
			Total: &validations.TotalCount{Licenses: 3, Violations: 16, Vulnerabilities: 16},
			// Check that we have at least one violation for each scan type. (IAC is not supported yet)
			Violations: &validations.ViolationCount{ValidateScan: &validations.ScanCount{Sca: 1, Sast: 1, Secrets: 1}},
		},
	)

	// Create an ignore rules for the git repo
	cleanUpCveIgnoreRule := securityTestUtils.CreateTestIgnoreRules(t, "security cli tests - Sca ignore rule", utils.IgnoreFilters{
		GitRepositories: []string{xscutils.GetGitRepoUrlKey(validations.TestMockGitInfo.GitRepoHttpsCloneUrl)},
		CVEs:            []string{"any"}, Licenses: []string{"any"},
	})
	defer cleanUpCveIgnoreRule()
	cleanUpExposureIgnoreRule := securityTestUtils.CreateTestIgnoreRules(t, "security cli tests - Exposure ignore rule", utils.IgnoreFilters{
		GitRepositories: []string{xscutils.GetGitRepoUrlKey(validations.TestMockGitInfo.GitRepoHttpsCloneUrl)},
		Exposures:       &utils.ExposuresFilterName{Categories: []utils.ExposureType{utils.SecretExposureType, utils.IacExposureType}},
	})
	defer cleanUpExposureIgnoreRule()
	cleanSastUpIgnoreRule := securityTestUtils.CreateTestIgnoreRules(t, "security cli tests - Sast ignore rule", utils.IgnoreFilters{
		GitRepositories: []string{xscutils.GetGitRepoUrlKey(validations.TestMockGitInfo.GitRepoHttpsCloneUrl)},
		Sast:            &utils.SastFilterName{Rule: []string{"any"}},
	})
	defer cleanSastUpIgnoreRule()

	createTestProjectRunGitAuditAndValidate(t, projectPath,
		auditCommandTestParams{Format: string(format.SimpleJson)},
		xrayVersion, xscVersion, "",
		// No Violations should be reported since all violations are ignored.
		validations.ValidationParams{ExactResultsMatch: true, Total: &validations.TotalCount{}, Violations: &validations.ViolationCount{ValidateScan: &validations.ScanCount{}}},
	)

	// // Run the audit command and verify no issues. (all violations are ignored)
	// output, err = testGitAuditCommand(t, gitAuditCommandTestParams{gitInfoContext: &validations.TestMockGitInfo, auditCommandTestParams: auditCommandTestParams{Format: string(format.SimpleJson)}})
	// assert.NoError(t, err)
	// validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{ExactResultsMatch: true, Total: &validations.TotalCount{}, Violations: &validations.ViolationCount{ValidateScan: &validations.ScanCount{}}})
}

func TestGitAuditJasViolationsProjectKeySimpleJson(t *testing.T) {
	xrayVersion, xscVersion, testCleanUp := integration.InitGitTest(t, services.MinXrayVersionGitRepoKey)
	defer testCleanUp()

	if *securityTests.JfrogTestProjectKey == "" {
		t.Skipf("skipping test. %s is not set.", securityTests.TestJfrogPlatformProjectKeyEnvVar)
	}

	// Create the project to scan
	// _, cleanUpProject := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "jas", "jas"))
	// defer cleanUpProject()

	// Create policy and watch for the project so we will get violations (unknown = all vulnerabilities will be reported as violations)
	policyName, cleanUpPolicy := securityTestUtils.CreateTestSecurityPolicy(t, "project-key-jas-violations-policy", utils.Unknown, true, false)
	defer cleanUpPolicy()
	_, cleanUpWatch := securityTestUtils.CreateTestProjectKeyWatch(t, policyName, "project-key-jas-violations-watch", *securityTests.JfrogTestProjectKey)
	defer cleanUpWatch()

	// Run the audit command with git repo and verify violations are reported to the platform.
	createTestProjectRunGitAuditAndValidate(t,
		filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "git", "projects", "issues"),
		auditCommandTestParams{Format: string(format.SimpleJson), ProjectKey: *securityTests.JfrogTestProjectKey},
		xrayVersion, xscVersion, results.NewFailBuildError().Error(),
		validations.ValidationParams{
			Total: &validations.TotalCount{Violations: 16},
			// Check that we have at least one violation for each scan type. (IAC is not supported yet)
			Violations: &validations.ViolationCount{ValidateScan: &validations.ScanCount{Sca: 1, Sast: 1, Secrets: 1}},
		},
	)

	// // Run the audit command with project key.
	// output, err := testGitAuditCommand(t, gitAuditCommandTestParams{gitInfoContext: &validations.TestMockGitInfo, auditCommandTestParams: auditCommandTestParams{Format: string(format.SimpleJson), ProjectKey: *securityTests.JfrogTestProjectKey}})
	// // verify violations are reported and the build fails.
	// assert.ErrorContains(t, err, results.NewFailBuildError().Error())
	// validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
	// 	Total: &validations.TotalCount{Violations: 14},
	// 	// Check that we have at least one violation for each scan type. (IAC is not supported yet)
	// 	Violations: &validations.ViolationCount{ValidateScan: &validations.ScanCount{Sca: 1, Sast: 1, Secrets: 1}},
	// })
}

func TestXrayAuditJasSkipNotApplicableCvesViolations(t *testing.T) {
	xrayVersion, xscVersion, testCleanUp := integration.InitGitTest(t, services.MinXrayVersionGitRepoKey)
	defer testCleanUp()

	// // Create the project to scan
	// _, cleanUpProject := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "jas", "jas"))
	// defer cleanUpProject()

	projectPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "git", "projects", "issues")

	// Create policy and watch for the git repo so we will also get violations - This watch DO NOT skip not-applicable results
	var firstPolicyCleaned, firstWatchCleaned bool
	policyName, cleanUpPolicy := securityTestUtils.CreateTestSecurityPolicy(t, "without-skip-non-applicable-policy", utils.Low, false, false)
	defer func() {
		if !firstPolicyCleaned {
			cleanUpPolicy()
		}
	}()
	watchName, cleanUpWatch := securityTestUtils.CreateWatchForTests(t, policyName, "without-skip-not-applicable-watch", xscutils.GetGitRepoUrlKey(validations.TestMockGitInfo.GitRepoHttpsCloneUrl))
	defer func() {
		if !firstWatchCleaned {
			cleanUpWatch()
		}
	}()

	// Run the git audit command and verify violations are reported to the platform.
	createTestProjectRunGitAuditAndValidate(t, projectPath,
		auditCommandTestParams{Format: string(format.SimpleJson), Watches: []string{watchName}, DisableFailOnFailedBuildFlag: true},
		xrayVersion, xscVersion, "",
		validations.ValidationParams{
			Violations: &validations.ViolationCount{
				ValidateScan:                &validations.ScanCount{Sca: 8, Sast: 2, Secrets: 2},
				ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{NotApplicable: 1, NotCovered: 7},
			},
			ExactResultsMatch: true,
		},
	)

	// params := gitAuditCommandTestParams{gitInfoContext: &validations.TestMockGitInfo, auditCommandTestParams: auditCommandTestParams{Format: string(format.SimpleJson), Watches: []string{watchName}, DisableFailOnFailedBuildFlag: true}}

	// // Run the git audit command and verify violations are reported to the platform.
	// output, err := testGitAuditCommand(t, params)
	// assert.NoError(t, err)
	// validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
	// 	Violations: &validations.ViolationCount{
	// 		ValidateScan:                &validations.ScanCount{Sca: 17, Sast: 1, Secrets: 15},
	// 		ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{NotApplicable: 5, Applicable: 2, NotCovered: 10},
	// 	},
	// 	ExactResultsMatch: true,
	// })

	// We clean the initially created Policy and Watch that are related to the Git Repo resource, because we must have all related policies with skipNotApplicable=true
	cleanUpWatch()
	firstWatchCleaned = true
	cleanUpPolicy()
	firstPolicyCleaned = true

	// Create policy and watch for the git repo so we will also get violations - This watch DO NOT skip not-applicable results
	skipPolicyName, skipCleanUpPolicy := securityTestUtils.CreateTestSecurityPolicy(t, "skip-non-applicable-policy", utils.Low, false, true)
	defer skipCleanUpPolicy()
	skipWatchName, skipCleanUpWatch := securityTestUtils.CreateWatchForTests(t, skipPolicyName, "skip-not-applicable-watch", xscutils.GetGitRepoUrlKey(validations.TestMockGitInfo.GitRepoHttpsCloneUrl))
	defer skipCleanUpWatch()

	// Run the audit command with git repo and verify violations are reported to the platform and not applicable issues are skipped.
	createTestProjectRunGitAuditAndValidate(t, projectPath,
		auditCommandTestParams{Format: string(format.SimpleJson), Watches: []string{skipWatchName}, DisableFailOnFailedBuildFlag: true},
		xrayVersion, xscVersion, "",
		validations.ValidationParams{
			Violations: &validations.ViolationCount{
				ValidateScan:                &validations.ScanCount{Sca: 7, Sast: 2, Secrets: 2},
				ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{NotCovered: 7},
			},
			ExactResultsMatch: true,
		},
	)

	// params.Watches = []string{skipWatchName}
	// output, err = testGitAuditCommand(t, params)
	// assert.NoError(t, err)
	// validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
	// 	Violations: &validations.ViolationCount{
	// 		ValidateScan:                &validations.ScanCount{Sca: 12, Sast: 1, Secrets: 15},
	// 		ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 2, NotCovered: 10},
	// 	},
	// 	ExactResultsMatch: true,
	// })
}
