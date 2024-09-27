package tests

import (
	"flag"
	"os"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"

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

	PlatformCli     *coreTests.JfrogCli
	TestApplication *components.App

	timestampAdded bool
	RunAllTests    bool
)

// Test flags
var (
	TestUnit        *bool
	TestArtifactory *bool
	TestXray        *bool
	TestXsc         *bool
	TestAudit       *bool
	TestScan        *bool
	TestDockerScan  *bool
	TestEnrich      *bool
	TestGit         *bool

	JfrogUrl         *string
	JfrogUser        *string
	JfrogPassword    *string
	JfrogAccessToken *string

	JfrogSshKeyPath    *string
	JfrogSshPassphrase *string
	ContainerRegistry  *string
	ciRunId            *string
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

func getTestPasswordDefaultValue() string {
	if os.Getenv(TestJfrogPasswordEnvVar) != "" {
		return os.Getenv(TestJfrogPasswordEnvVar)
	}
	return "password"
}

func init() {
	TestUnit = flag.Bool("test.unit", false, "Run unit tests")
	TestArtifactory = flag.Bool("test.artifactory", false, "Run Artifactory integration tests")
	TestXsc = flag.Bool("test.xsc", false, "Run XSC integration tests")
	TestXray = flag.Bool("test.xray", false, "Run Xray commands integration tests")
	TestAudit = flag.Bool("test.audit", false, "Run Audit command integration tests")
	TestScan = flag.Bool("test.scan", false, "Run Other scan commands integration tests")
	TestDockerScan = flag.Bool("test.dockerScan", false, "Run Docker scan command integration tests")
	TestEnrich = flag.Bool("test.enrich", false, "Run Enrich command integration tests")
	TestGit = flag.Bool("test.git", false, "Run Git commands integration tests")

	JfrogUrl = flag.String("jfrog.url", getTestUrlDefaultValue(), "JFrog platform url")
	JfrogUser = flag.String("jfrog.user", getTestUserDefaultValue(), "JFrog platform  username")
	JfrogPassword = flag.String("jfrog.password", getTestPasswordDefaultValue(), "JFrog platform password")
	JfrogAccessToken = flag.String("jfrog.adminToken", os.Getenv(TestJfrogTokenEnvVar), "JFrog platform admin token")

	JfrogSshKeyPath = flag.String("jfrog.sshKeyPath", "", "Ssh key file path")
	JfrogSshPassphrase = flag.String("jfrog.sshPassphrase", "", "Ssh key passphrase")
	ContainerRegistry = flag.String("test.containerRegistry", "localhost:8084", "Container registry")
	ciRunId = flag.String("ci.runId", "", "A unique identifier used as a suffix to create repositories and builds in the tests")
}

func InitTestFlags() {
	flag.Parse()
	shouldRunAllTests := !isAtLeastOneFlagSet(TestUnit, TestArtifactory, TestXray, TestXsc, TestAudit, TestScan, TestDockerScan, TestEnrich, TestGit)
	if shouldRunAllTests {
		log.Info("Running all tests. To run only specific tests, please specify the desired test flags.")
		*TestUnit = true
		*TestArtifactory = true
		*TestXray = true
		*TestXsc = true
		*TestAudit = true
		*TestScan = true
		*TestDockerScan = true
		*TestEnrich = true
		*TestGit = true
	}
}

func isAtLeastOneFlagSet(flagPointers ...*bool) bool {
	for _, flagPointer := range flagPointers {
		if *flagPointer {
			return true
		}
	}
	return false
}
