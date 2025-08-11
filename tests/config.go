package tests

import (
	"flag"
	"net/url"
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
	TestScan        *bool
	TestDockerScan  *bool
	TestCuration    *bool
	TestEnrich      *bool
	TestGit         *bool

	TestAuditGeneral    *bool
	TestAuditNewSca     *bool
	TestAuditJas        *bool
	TestAuditJavaScript *bool
	TestAuditJava       *bool
	TestAuditCTypes     *bool
	TestAuditGo         *bool
	TestAuditPython     *bool
	TestAuditCocoapods  *bool
	TestAuditSwift      *bool

	JfrogUrl         *string
	JfrogUser        *string
	JfrogPassword    *string
	JfrogAccessToken *string

	JfrogSshKeyPath    *string
	JfrogSshPassphrase *string
	ContainerRegistry  *string
	CiRunId            *string
	// Used for tests that require a project key
	JfrogTestProjectKey *string
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

func getTestContainerDefaultValue(jfrogUrl string) string {
	if os.Getenv(TestJfrogContainerEnvVar) != "" {
		return os.Getenv(TestJfrogContainerEnvVar)
	}
	// remove protocol and trailing slash from the JFrog URL
	parsedUrl, err := url.Parse(jfrogUrl)
	if err != nil {
		log.Error("Failed to parse JFrog URL:", err)
		return "localhost:8084"
	}
	return parsedUrl.Host
}

func init() {
	TestUnit = flag.Bool("test.unit", false, "Run unit tests")
	TestArtifactory = flag.Bool("test.artifactory", false, "Run Artifactory integration tests")
	TestXsc = flag.Bool("test.xsc", false, "Run XSC integration tests")
	TestXray = flag.Bool("test.xray", false, "Run Xray commands integration tests")
	TestScan = flag.Bool("test.scan", false, "Run Other scan commands integration tests")
	TestDockerScan = flag.Bool("test.dockerScan", false, "Run Docker scan command integration tests")
	TestCuration = flag.Bool("test.curation", false, "Run Curation command integration tests")
	TestEnrich = flag.Bool("test.enrich", false, "Run Enrich command integration tests")
	TestGit = flag.Bool("test.git", false, "Run Git commands integration tests")

	TestAuditGeneral = flag.Bool("test.audit", false, "Run general (Detection, NoTech, MultiTech...) audit integration tests")
	TestAuditNewSca = flag.Bool("test.audit.NewSca", false, "Run audit command with new SCA integration tests")
	TestAuditJas = flag.Bool("test.audit.Jas", false, "Run Jas audit integration tests")
	TestAuditJavaScript = flag.Bool("test.audit.JavaScript", false, "Run JavaScript technologies (Npm, Pnpm, Yarn) audit integration tests")
	TestAuditJava = flag.Bool("test.audit.Java", false, "Run Java technologies (Maven, Gradle) audit integration tests")
	TestAuditCTypes = flag.Bool("test.audit.C", false, "Run C/C++/C# technologies (Nuget/DotNet, Conan) audit integration tests")
	TestAuditGo = flag.Bool("test.audit.Go", false, "Run Go technologies (GoLang) audit integration tests")
	TestAuditPython = flag.Bool("test.audit.Python", false, "Run Python technologies (Pip, PipEnv, Poetry) audit integration tests")
	TestAuditCocoapods = flag.Bool("test.audit.Cocoapods", false, "Run Cocoapods technologies audit integration tests")
	TestAuditSwift = flag.Bool("test.audit.Swift", false, "Run Swift technologies audit integration tests")

	JfrogUrl = flag.String("jfrog.url", getTestUrlDefaultValue(), "JFrog platform url")
	JfrogUser = flag.String("jfrog.user", getTestUserDefaultValue(), "JFrog platform  username")
	JfrogPassword = flag.String("jfrog.password", getTestPasswordDefaultValue(), "JFrog platform password")
	JfrogAccessToken = flag.String("jfrog.adminToken", os.Getenv(TestJfrogTokenEnvVar), "JFrog platform admin token")

	JfrogSshKeyPath = flag.String("jfrog.sshKeyPath", "", "Ssh key file path")
	JfrogSshPassphrase = flag.String("jfrog.sshPassphrase", "", "Ssh key passphrase")
	ContainerRegistry = flag.String("test.containerRegistry", getTestContainerDefaultValue(*JfrogUrl), "Container registry")
	CiRunId = flag.String("ci.runId", "", "A unique identifier used as a suffix to create repositories and builds in the tests")
	JfrogTestProjectKey = flag.String("jfrog.projectKey", os.Getenv(TestJfrogPlatformProjectKeyEnvVar), "Project key used for tests")
}

func InitTestFlags() {
	flag.Parse()
	// If no test types flags were set, run all types
	shouldRunAllTests := !isAtLeastOneFlagSet(TestUnit, TestArtifactory, TestXray, TestXsc, TestAuditGeneral, TestAuditNewSca, TestAuditJas, TestAuditJavaScript, TestAuditJava, TestAuditCTypes, TestAuditGo, TestAuditPython, TestAuditCocoapods, TestAuditSwift, TestScan, TestDockerScan, TestCuration, TestEnrich, TestGit)
	if shouldRunAllTests {
		log.Info("Running all tests. To run only specific tests, please specify the desired test flags.")
		*TestUnit = true
		*TestArtifactory = true
		*TestXray = true
		*TestXsc = true
		*TestAuditGeneral = true
		*TestAuditNewSca = true
		*TestAuditJas = true
		*TestAuditJavaScript = true
		*TestAuditJava = true
		*TestAuditCTypes = true
		*TestAuditGo = true
		*TestAuditPython = true
		*TestAuditCocoapods = true
		*TestAuditSwift = true
		*TestScan = true
		*TestDockerScan = true
		*TestCuration = true
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
