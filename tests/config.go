package tests

import (
	"flag"
	"os"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
)

// Integration tests - global variables
var (
	XrDetails *config.ServerDetails
	XrAuth    auth.ServiceDetails

	XscDetails *config.ServerDetails
	XscAuth    auth.ServiceDetails

	RtDetails     *config.ServerDetails
	RtAuth        auth.ServiceDetails
	RtHttpDetails httputils.HttpClientDetails

	PlatformCli *coreTests.JfrogCli

	TestApplication *components.App

	timestampAdded bool
)

// Test flags
var (
	TestSecurity   *bool
	TestDockerScan *bool

	JfrogUrl           *string
	JfrogUser          *string
	JfrogPassword      *string
	JfrogSshKeyPath    *string
	JfrogSshPassphrase *string
	JfrogAccessToken   *string

	ContainerRegistry *string

	HideUnitTestLog *bool
	SkipUnitTests   *bool
	ciRunId         *string
)

func getTestUrlDefaultValue() string {
	if os.Getenv(TestJfrogUrlEnvVar) != "" {
		return os.Getenv(TestJfrogUrlEnvVar)
	}
	return "http://localhost:8083/"
}

func getTestUserDefaultValue() string {
	if os.Getenv(TestJfrogUserEnvVar) != "" {
		return os.Getenv(TestJfrogUserEnvVar)
	}
	return "admin"
}

func init() {
	TestSecurity = flag.Bool("test.security", true, "Test Security")
	TestDockerScan = flag.Bool("test.dockerScan", false, "Test Docker scan")

	JfrogUrl = flag.String("jfrog.url", getTestUrlDefaultValue(), "JFrog platform url")
	JfrogUser = flag.String("jfrog.user", getTestUserDefaultValue(), "JFrog platform  username")
	JfrogPassword = flag.String("jfrog.password", "password", "JFrog platform password")

	JfrogSshKeyPath = flag.String("jfrog.sshKeyPath", "", "Ssh key file path")
	JfrogSshPassphrase = flag.String("jfrog.sshPassphrase", "", "Ssh key passphrase")
	JfrogAccessToken = flag.String("jfrog.adminToken", os.Getenv(TestJfrogTokenEnvVar), "JFrog platform admin token")

	ContainerRegistry = flag.String("test.containerRegistry", "localhost:8083", "Container registry")

	HideUnitTestLog = flag.Bool("test.hideUnitTestLog", false, "Hide unit tests logs and print it in a file")
	SkipUnitTests = flag.Bool("test.skipUnitTests", false, "Skip unit tests")

	ciRunId = flag.String("ci.runId", "", "A unique identifier used as a suffix to create repositories and builds in the tests")
}
