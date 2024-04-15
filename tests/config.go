package tests

import (
	"flag"

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

func init() {
	TestSecurity = flag.Bool("test.security", true, "Test Security")
	TestDockerScan = flag.Bool("test.dockerScan", false, "Test Docker scan")

	JfrogUrl = flag.String("jfrog.url", "http://localhost:8081/", "JFrog platform url")
	JfrogUser = flag.String("jfrog.user", "admin", "JFrog platform  username")
	JfrogPassword = flag.String("jfrog.password", "password", "JFrog platform password")
	JfrogSshKeyPath = flag.String("jfrog.sshKeyPath", "", "Ssh key file path")
	JfrogSshPassphrase = flag.String("jfrog.sshPassphrase", "", "Ssh key passphrase")
	JfrogAccessToken = flag.String("jfrog.adminToken", "", "JFrog platform admin token")

	ContainerRegistry = flag.String("test.containerRegistry", "localhost:8082", "Container registry")

	HideUnitTestLog = flag.Bool("test.hideUnitTestLog", false, "Hide unit tests logs and print it in a file")
	SkipUnitTests = flag.Bool("test.skipUnitTests", false, "Skip unit tests")

	ciRunId = flag.String("ci.runId", "", "A unique identifier used as a suffix to create repositories and builds in the tests")
}
