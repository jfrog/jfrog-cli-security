package main

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/log"
	"github.com/jfrog/jfrog-cli-security/cli"
	integrationUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"

	configTests "github.com/jfrog/jfrog-cli-security/tests"

	clientLog "github.com/jfrog/jfrog-client-go/utils/log"

	"os"
	"testing"
)

func TestMain(m *testing.M) {
	setupIntegrationTests()
	result := m.Run()
	tearDownIntegrationTests()
	os.Exit(result)
}

func setupIntegrationTests() {
	// Disable usage report.
	if err := os.Setenv(coreutils.ReportUsage, "false"); err != nil {
		clientLog.Error(fmt.Sprintf("Couldn't set env: %s. Error: %s", coreutils.ReportUsage, err.Error()))
		os.Exit(1)
	}
	// Disable progress bar and confirmation messages.
	if err := os.Setenv(coreutils.CI, "true"); err != nil {
		clientLog.Error(fmt.Sprintf("Couldn't set env: %s. Error: %s", coreutils.CI, err.Error()))
		os.Exit(1)
	}
	// General
	configTests.InitTestFlags()
	log.SetDefaultLogger()
	// Init
	integrationUtils.InitTestCliDetails(cli.GetJfrogCliSecurityApp())
	integrationUtils.AuthenticateArtifactory()
	integrationUtils.AuthenticateXsc()
	integrationUtils.CreateRequiredRepositories()
}

func tearDownIntegrationTests() {
	// Important - Virtual repositories must be deleted first
	integrationUtils.DeleteRepos(configTests.CreatedVirtualRepositories)
	integrationUtils.DeleteRepos(configTests.CreatedNonVirtualRepositories)
}
