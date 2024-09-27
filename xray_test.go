package main

import (
	"fmt"
	"testing"

	securityDocs "github.com/jfrog/jfrog-cli-security/cli/docs"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	securityIntegrationTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/stretchr/testify/assert"
)

func TestXrayCurl(t *testing.T) {
	integration.InitXrayTest(t, "")
	// Configure a new server named "default".
	securityIntegrationTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	// Check curl command with the default configured server.
	err := securityTests.PlatformCli.WithoutCredentials().Exec("xr", "curl", "-XGET", "/api/v1/system/version")
	assert.NoError(t, err)
	// Check curl command with '--server-id' flag
	err = securityTests.PlatformCli.WithoutCredentials().Exec("xr", "curl", "-XGET", "/api/system/version", "--server-id=default")
	assert.NoError(t, err)
	// Check curl command with invalid server id - should get an error.
	err = securityTests.PlatformCli.WithoutCredentials().Exec("xr", "curl", "-XGET", "/api/system/version", "--server-id=not_configured_name")
	assert.EqualError(t, err, "Server ID 'not_configured_name' does not exist.")
}

func TestXrayOfflineDBSyncV3(t *testing.T) {
	integration.InitXrayTest(t, "")
	// Validate license-id
	err := securityTests.PlatformCli.WithoutCredentials().Exec("xr", "ou")
	assert.EqualError(t, err, "Mandatory flag 'license-id' is missing")
	// Periodic valid only with stream
	err = securityTests.PlatformCli.WithoutCredentials().Exec("xr", "ou", "--license-id=123", "--periodic")
	assert.EqualError(t, err, fmt.Sprintf("the %s option is only valid with %s", securityDocs.Periodic, securityDocs.Stream))
	err = securityTests.PlatformCli.WithoutCredentials().Exec("xr", "ou", "--license-id=123", "--stream=", "--periodic")
	assert.EqualError(t, err, fmt.Sprintf("the %s option is only valid with %s", securityDocs.Periodic, securityDocs.Stream))
	// Invalid stream
	err = securityTests.PlatformCli.WithoutCredentials().Exec("xr", "ou", "--license-id=123", "--stream=bad_name")
	assert.ErrorContains(t, err, "Invalid stream type")
}
