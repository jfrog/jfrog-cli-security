package main

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"

	clientLog "github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/tests/utils"
)

const (
	CliIntegrationTests = "github.com/jfrog/jfrog-cli-security"
)

func TestUnitTests(t *testing.T) {
	utils.InitUnitTest(t)
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
