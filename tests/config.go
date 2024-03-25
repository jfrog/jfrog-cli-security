package tests

import (
	"flag"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
)

// Integration tests - global variables
var (
	XrDetails *config.ServerDetails
	XrAuth    auth.ServiceDetails

	RtDetails     *config.ServerDetails
	RtAuth        auth.ServiceDetails
	RtHttpDetails httputils.HttpClientDetails

	PlatformCli *coreTests.JfrogCli

	TestApplication *components.App

	timestampAdded bool
)

// Test flags
var (
	AllTests        *bool
	TestUnit        *bool
	TestArtifactory *bool
	TestXray        *bool
	TestAudit       *bool
	TestScan        *bool
	TestDockerScan  *bool

	JfrogUrl           *string
	JfrogUser          *string
	JfrogPassword      *string
	JfrogSshKeyPath    *string
	JfrogSshPassphrase *string
	JfrogAccessToken   *string

	ContainerRegistry *string
	ciRunId           *string
)

func init() {
	AllTests = flag.Bool("test.all", false, "Run all tests")
	TestUnit = flag.Bool("test.unit", true, "Unit tests")
	TestArtifactory = flag.Bool("test.artifactory", false, "Test Artifactory integration")
	TestXray = flag.Bool("test.xray", false, "Test Xray integration")
	TestAudit = flag.Bool("test.audit", false, "Test Audit command")
	TestScan = flag.Bool("test.scan", false, "Test Scan commands")
	TestDockerScan = flag.Bool("test.dockerScan", false, "Test Docker scan")

	JfrogUrl = flag.String("jfrog.url", "http://localhost:8081/", "JFrog platform url")
	JfrogUser = flag.String("jfrog.user", "admin", "JFrog platform  username")
	JfrogPassword = flag.String("jfrog.password", "password", "JFrog platform password")
	JfrogSshKeyPath = flag.String("jfrog.sshKeyPath", "", "Ssh key file path")
	JfrogSshPassphrase = flag.String("jfrog.sshPassphrase", "", "Ssh key passphrase")
	JfrogAccessToken = flag.String("jfrog.adminToken", "", "JFrog platform admin token")

	ContainerRegistry = flag.String("test.containerRegistry", "localhost:8082", "Container registry")
	ciRunId = flag.String("ci.runId", "", "A unique identifier used as a suffix to create repositories and builds in the tests")
}

func InitTestFlags() {
	flag.Parse()
	shouldRunAllTests := *AllTests
	if shouldRunAllTests {
		clientLog.Info("All tests flag is set. Running all tests.")
		*TestUnit = true
		*TestArtifactory = true
		*TestXray = true
		*TestAudit = true
		*TestScan = true
		*TestDockerScan = true
	}
}
