package main

import (
	"github.com/jfrog/jfrog-cli-security/commands/git"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCountContributorsFlags(t *testing.T) {
	err := securityTests.PlatformCli.WithoutCredentials().Exec("git", "count-contributors", "--token", "token", "--owner", "owner", "--scm-api-url", "url")
	assert.EqualError(t, err, "Mandatory flag 'scm-type' is missing")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "cc", "--scm-type", "github", "--owner", "owner", "--scm-api-url", "url")
	assert.ErrorContains(t, err, "Providing a token is mandatory")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "cc", "--scm-type", "gitlab", "--token", "token", "--scm-api-url", "url")
	assert.EqualError(t, err, "Mandatory flag 'owner' is missing")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "cc", "--scm-type", "bitbucket", "--token", "token", "--owner", "owner")
	assert.EqualError(t, err, "Mandatory flag 'scm-api-url' is missing")

	// Test token env variable
	bitbucketCallback := tests.SetEnvWithCallbackAndAssert(t, git.BitbucketTokenEnvVar, "token")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "count-contributors", "--scm-type", "bitbucket", "--owner", "owner", "--scm-api-url", "url")
	assert.NotContains(t, err.Error(), "Providing a token is mandatory")
	bitbucketCallback()
	gitlabCallback := tests.SetEnvWithCallbackAndAssert(t, git.GitlabTokenEnvVar, "token")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "count-contributors", "--scm-type", "gitlab", "--owner", "owner", "--scm-api-url", "url")
	assert.NotContains(t, err.Error(), "Providing a token is mandatory")
	gitlabCallback()
	githubCallback := tests.SetEnvWithCallbackAndAssert(t, git.GithubTokenEnvVar, "token")
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "count-contributors", "--scm-type", "github", "--owner", "owner", "--scm-api-url", "url")
	assert.NotContains(t, err.Error(), "Providing a token is mandatory")
	githubCallback()

	// Test supported scm type
	err = securityTests.PlatformCli.WithoutCredentials().Exec("git", "cc", "--scm-type", "bad-type", "--token", "token", "--owner", "owner", "--scm-api-url", "url")
	assert.ErrorContains(t, err, "Unsupported SCM type")
}
