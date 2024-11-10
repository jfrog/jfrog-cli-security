package main

import (
	"github.com/stretchr/testify/assert"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"

	clientLog "github.com/jfrog/jfrog-client-go/utils/log"

	"os"
	"testing"
)

const (
	CliIntegrationTests = "github.com/jfrog/jfrog-cli-security"
)

func TestUnitTests(t *testing.T) {
	integration.InitUnitTest(t)
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
