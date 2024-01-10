package main

import (
	"github.com/stretchr/testify/assert"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	configTests "github.com/jfrog/jfrog-cli-security/tests"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"

	clientLog "github.com/jfrog/jfrog-client-go/utils/log"

	"os"
	"testing"
)

func TestUnitTests(t *testing.T) {
	if *configTests.SkipUnitTests {
		t.Skip("Skipping unit tests.")
	}
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
	assert.NoError(t, clientTests.RunTests(packages, *configTests.HideUnitTestLog))
}
