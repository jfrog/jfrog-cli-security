package main

import (
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGitContribution(t *testing.T) {
	//output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "git", "contributing")
	err := securityTests.PlatformCli.WithoutCredentials().Exec("git", "contributing", "--scm-type", "github", "--token", "token", "--owner", "gailazar300", "--repo-name", "jfrog-cli-go", "--months", "6")
	assert.NoError(t, err)
	//assert.Equal(t, "audit", output)
}
