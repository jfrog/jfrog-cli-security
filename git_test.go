package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"

	"github.com/jfrog/jfrog-cli-security/commands/git/contributors"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"

	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"

	"github.com/jfrog/jfrog-client-go/utils/tests"
)

func TestCountContributorsFlags(t *testing.T) {
	integration.InitGitTest(t)
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

func initGitAuditTest(t *testing.T) {
	integration.InitGitTest(t)
	securityTestUtils.ValidateXrayVersion(t, scangraph.GraphScanMinXrayVersion)
}

func TestGitAuditNoXsc(t *testing.T) {
	initGitAuditTest(t)
	output := runGitAudit(t, "clean")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		ExactResultsMatch: true,
		Vulnerabilities:   6,

		Applicable:    2,
		NotApplicable: 1,
		Undetermined:  1,
		Iac:           1,
		Sast:          1,
	})
}

func runGitAudit(t *testing.T, project string) string {
	// Configure a new server named "default"
	integration.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	// Create a new project from the given zip file
	_, cleanUp := securityTestUtils.CreateTestProjectFromZipAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "git", "projects", project))
	defer cleanUp()
	// Run the git audit command
	return securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, "git", "audit", "--format="+string(format.SimpleJson))
}
