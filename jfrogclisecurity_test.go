package main

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/log"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	CliIntegrationTests = "github.com/jfrog/jfrog-cli-security/tests/integration"
)

func TestMain(m *testing.M) {
	setupTests()
	result := m.Run()

	os.Exit(result)
}

func TestUnitTests(t *testing.T) {
	// Create temp jfrog home
	cleanUpJfrogHome, err := coreTests.SetJfrogHome()
	if err != nil {
		clientLog.Error(err)
		os.Exit(1)
	}
	// Clean from previous tests.
	defer cleanUpJfrogHome()

	packages := clientTests.GetTestPackages("./...")
	packages = clientTests.ExcludeTestsPackage(packages, CliIntegrationTests)
	assert.NoError(t, clientTests.RunTests(packages, false))
}

func setupTests() {
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
	flag.Parse()
	log.SetDefaultLogger()
}
