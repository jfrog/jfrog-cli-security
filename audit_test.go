package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/jasutils"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"

	"github.com/jfrog/jfrog-cli-security/cli"
	"github.com/jfrog/jfrog-cli-security/cli/docs"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/validations"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/stretchr/testify/assert"

	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/progressbar"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	securityIntegrationTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestXrayAuditNpmJson(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	output := testAuditNpm(t, string(format.Json), false)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total:      &validations.TotalCount{Licenses: 1, Violations: 1},
		Violations: &validations.ViolationCount{ValidateType: &validations.ScaViolationCount{Security: 1}},
	})
}

func TestXrayAuditNpmSimpleJson(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	output := testAuditNpm(t, string(format.SimpleJson), true)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total:      &validations.TotalCount{Licenses: 1, Vulnerabilities: 1, Violations: 1},
		Violations: &validations.ViolationCount{ValidateType: &validations.ScaViolationCount{Security: 1}},
	})
}

func testAuditNpm(t *testing.T, format string, withVuln bool) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "npm", "npm"))
	defer cleanUp()
	// Run npm install before executing jfrog xr npm-audit
	assert.NoError(t, exec.Command("npm", "install").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	watchName, deleteWatch := securityTestUtils.CreateTestPolicyAndWatch(t, "audit-policy", "audit-watch", xrayUtils.High)
	defer deleteWatch()
	args := []string{"audit", "--npm", "--licenses", "--format=" + format, "--watches=" + watchName, "--fail=false"}
	if withVuln {
		args = append(args, "--vuln")
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, args...)
}

func TestXrayAuditConanJson(t *testing.T) {
	integration.InitAuditCTest(t, scangraph.GraphScanMinXrayVersion)
	output := testAuditConan(t, string(format.Json), true)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 2, Vulnerabilities: 8},
	})
}

func TestXrayAuditConanSimpleJson(t *testing.T) {
	integration.InitAuditCTest(t, scangraph.GraphScanMinXrayVersion)
	output := testAuditConan(t, string(format.SimpleJson), true)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 2, Vulnerabilities: 8},
	})
}

func testAuditConan(t *testing.T, format string, withVuln bool) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "conan"))
	defer cleanUp()
	// Run conan install before executing jfrog audit
	assert.NoError(t, exec.Command("conan").Run())
	watchName, deleteWatch := securityTestUtils.CreateTestPolicyAndWatch(t, "audit-curation-policy", "audit-curation-watch", xrayUtils.High)
	defer deleteWatch()
	args := []string{"audit", "--licenses", "--format=" + format, "--watches=" + watchName, "--fail=false"}
	if withVuln {
		args = append(args, "--vuln")
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, args...)
}

func TestXrayAuditPnpmJson(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPnpm(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

func TestXrayAuditPnpmSimpleJson(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPnpm(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

func testXrayAuditPnpm(t *testing.T, format string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "npm", "npm-no-lock"))
	defer cleanUp()
	// Run pnpm install before executing audit
	assert.NoError(t, exec.Command("pnpm", "install").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--pnpm", "--licenses", "--format="+format)
}

func TestXrayAuditYarnV2Json(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	testXrayAuditYarn(t, "yarn-v2", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.Json))
		validations.VerifyJsonResults(t, output, validations.ValidationParams{
			Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
		})
	})
}

func TestXrayAuditYarnV2SimpleJson(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	testXrayAuditYarn(t, "yarn-v3", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.SimpleJson))
		validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
			Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
		})
	})
}

func TestXrayAuditYarnV1Json(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	testXrayAuditYarn(t, "yarn-v1", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.Json))
		validations.VerifyJsonResults(t, output, validations.ValidationParams{
			Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
		})
	})
}

func TestXrayAuditYarnV1JsonWithoutDevDependencies(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	unsetEnv := clientTests.SetEnvWithCallbackAndAssert(t, "NODE_ENV", "production")
	defer unsetEnv()
	testXrayAuditYarn(t, "yarn-v1", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.Json))
		var results []services.ScanResponse
		err := json.Unmarshal([]byte(output), &results)
		assert.NoError(t, err)
		assert.Len(t, results[0].Vulnerabilities, 0)
	})
}

func TestXrayAuditYarnV1SimpleJson(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	testXrayAuditYarn(t, "yarn-v1", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.SimpleJson))
		validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
			Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
		})
	})
}

func testXrayAuditYarn(t *testing.T, projectDirName string, yarnCmd func()) {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "yarn", projectDirName))
	defer cleanUp()
	// Run yarn install before executing jf audit --yarn. Return error to assert according to test.
	assert.NoError(t, exec.Command("yarn").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	yarnCmd()
}

func runXrayAuditYarnWithOutput(t *testing.T, format string) string {
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--yarn", "--licenses", "--format="+format)
}

// Tests NuGet audit by providing simple NuGet project + multi-project NuGet project and asserts any error.
func TestXrayAuditNugetJson(t *testing.T) {
	integration.InitAuditCTest(t, scangraph.GraphScanMinXrayVersion)
	var testdata = []struct {
		projectName        string
		format             string
		restoreTech        string
		minVulnerabilities int
		minLicences        int
	}{
		{
			projectName:        "single4.0",
			format:             string(format.Json),
			restoreTech:        "nuget",
			minVulnerabilities: 2,
			minLicences:        0,
		},
		{
			projectName:        "single5.0",
			format:             string(format.Json),
			restoreTech:        "dotnet",
			minVulnerabilities: 3,
			minLicences:        2,
		},
		{
			projectName:        "single5.0",
			format:             string(format.Json),
			restoreTech:        "",
			minVulnerabilities: 3,
			minLicences:        2,
		},
		{
			projectName:        "multi",
			format:             string(format.Json),
			restoreTech:        "dotnet",
			minVulnerabilities: 4,
			minLicences:        3,
		},
		{
			projectName:        "multi",
			format:             string(format.Json),
			restoreTech:        "",
			minVulnerabilities: 4,
			minLicences:        3,
		},
	}
	for _, test := range testdata {
		runInstallCommand := test.restoreTech != ""
		t.Run(fmt.Sprintf("projectName:%s,runInstallCommand:%t", test.projectName, runInstallCommand),
			func(t *testing.T) {
				output := testXrayAuditNuget(t, test.projectName, test.format, test.restoreTech)
				validations.VerifyJsonResults(t, output, validations.ValidationParams{
					Total: &validations.TotalCount{Licenses: test.minLicences, Vulnerabilities: test.minVulnerabilities},
				})
			})
	}
}

func TestXrayAuditNugetSimpleJson(t *testing.T) {
	integration.InitAuditCTest(t, scangraph.GraphScanMinXrayVersion)
	var testdata = []struct {
		projectName        string
		format             string
		restoreTech        string
		minVulnerabilities int
		minLicences        int
	}{
		{
			projectName:        "single4.0",
			format:             string(format.SimpleJson),
			restoreTech:        "nuget",
			minVulnerabilities: 2,
			minLicences:        0,
		},
		{
			projectName:        "single5.0",
			format:             string(format.SimpleJson),
			restoreTech:        "dotnet",
			minVulnerabilities: 3,
			minLicences:        2,
		},
		{
			projectName:        "single5.0",
			format:             string(format.SimpleJson),
			restoreTech:        "",
			minVulnerabilities: 3,
			minLicences:        2,
		},
	}
	for _, test := range testdata {
		runInstallCommand := test.restoreTech != ""
		t.Run(fmt.Sprintf("projectName:%s,runInstallCommand:%t", test.projectName, runInstallCommand),
			func(t *testing.T) {
				output := testXrayAuditNuget(t, test.projectName, test.format, test.restoreTech)
				validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
					Total: &validations.TotalCount{Licenses: test.minLicences, Vulnerabilities: test.minVulnerabilities},
				})
			})
	}
}

func testXrayAuditNuget(t *testing.T, projectName, format string, restoreTech string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "nuget", projectName))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	// Run NuGet/Dotnet restore before executing jfrog xr audit (NuGet)
	if restoreTech != "" {
		output, err := exec.Command(restoreTech, "restore").CombinedOutput()
		assert.NoError(t, err, string(output))
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--nuget", "--format="+format, "--licenses")
}

func TestXrayAuditGradleJson(t *testing.T) {
	integration.InitAuditJavaTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditGradle(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 3, Vulnerabilities: 3},
	})
}

func TestXrayAuditGradleSimpleJson(t *testing.T) {
	integration.InitAuditJavaTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditGradle(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 3, Vulnerabilities: 3},
	})
}

func testXrayAuditGradle(t *testing.T, format string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "gradle", "gradle"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--gradle", "--licenses", "--format="+format)
}

func TestXrayAuditMavenJson(t *testing.T) {
	integration.InitAuditJavaTest(t, scangraph.GraphScanMinXrayVersion)
	output := testAuditMaven(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

func TestXrayAuditMavenSimpleJson(t *testing.T) {
	integration.InitAuditJavaTest(t, scangraph.GraphScanMinXrayVersion)
	output := testAuditMaven(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

func testAuditMaven(t *testing.T, format string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "maven", "maven"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--mvn", "--licenses", "--format="+format)
}

func TestXrayAuditGoJson(t *testing.T) {
	integration.InitAuditGoTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditGo(t, false, string(format.Json), "simple-project")
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 4}})
}

func TestXrayAuditGoSimpleJson(t *testing.T) {
	integration.InitAuditGoTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditGo(t, true, string(format.SimpleJson), "simple-project")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 3, Vulnerabilities: 4},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{NotCovered: 1, NotApplicable: 3},
		},
	})
}

func testXrayAuditGo(t *testing.T, noCreds bool, format, project string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "go", project))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit

	addDummyPackageDescriptor(t, false)

	cliToRun := securityTests.PlatformCli
	if noCreds {
		cliToRun = securityTests.PlatformCli.WithoutCredentials()
		// Configure a new server named "default"
		securityIntegrationTestUtils.CreateJfrogHomeConfig(t, true)
		defer securityTestUtils.CleanTestsHomeEnv()
	}
	return cliToRun.RunCliCmdWithOutput(t, "audit", "--go", "--licenses", "--format="+format)
}

func TestXrayAuditNoTech(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Run audit on empty folder, expect an error
	err := securityTests.PlatformCli.Exec("audit")
	assert.NoError(t, err)
}

func TestXrayAuditMultiProjects(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects"))
	defer cleanUp()
	// Set working-dirs flag with multiple projects
	workingDirsFlag := fmt.Sprintf("--working-dirs=%s, %s ,%s, %s",
		filepath.Join("package-managers", "maven", "maven"), filepath.Join("package-managers", "nuget", "single4.0"),
		filepath.Join("package-managers", "python", "pip", "pip-project"), filepath.Join("jas", "jas"))
	// Configure a new server named "default"
	securityIntegrationTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	output := securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, "audit", "--format="+string(format.SimpleJson), workingDirsFlag)

	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 43},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 27, Sast: 1, Iac: 9, Secrets: 6},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, NotCovered: 22, NotApplicable: 2},
		},
	})
}

func TestXrayAuditPipJson(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPip(t, string(format.Json), "")
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
	})
}

func TestXrayAuditCocoapods(t *testing.T) {
	integration.InitAuditCocoapodsTest(t, scangraph.CocoapodsScanMinXrayVersion)
	output := testXrayAuditCocoapods(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 1}})
}

func TestXrayAuditSwift(t *testing.T) {
	output := testXrayAuditSwift(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 1},
	})
}

func TestXrayAuditPipSimpleJson(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPip(t, string(format.SimpleJson), "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
	})
}

func TestXrayAuditPipJsonWithRequirementsFile(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPip(t, string(format.Json), "requirements.txt")
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 2}})
}

func TestXrayAuditPipSimpleJsonWithRequirementsFile(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPip(t, string(format.SimpleJson), "requirements.txt")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 2}})
}

func testXrayAuditPip(t *testing.T, format, requirementsFile string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "pip", "pip-project"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	args := []string{"audit", "--pip", "--licenses", "--format=" + format}
	if requirementsFile != "" {
		args = append(args, "--requirements-file="+requirementsFile)
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, args...)
}

func testXrayAuditCocoapods(t *testing.T, format string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "cocoapods"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	args := []string{"audit", "--format=" + format}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, args...)
}

func testXrayAuditSwift(t *testing.T, format string) string {
	integration.InitAuditSwiftTest(t, scangraph.SwiftScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "swift"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	args := []string{"audit", "--format=" + format}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, args...)
}

func TestXrayAuditPipenvJson(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPipenv(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
	})
}

func TestXrayAuditPipenvSimpleJson(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPipenv(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
	})
}

func testXrayAuditPipenv(t *testing.T, format string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "pipenv", "pipenv-project"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--pipenv", "--licenses", "--format="+format)
}

func TestXrayAuditPoetryJson(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPoetry(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
	})
}

func TestXrayAuditPoetrySimpleJson(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditPoetry(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
	})
}

func testXrayAuditPoetry(t *testing.T, format string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "poetry", "poetry-project"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--poetry", "--licenses", "--format="+format)
}

func addDummyPackageDescriptor(t *testing.T, hasPackageJson bool) {
	descriptor := "package.json"
	if hasPackageJson {
		descriptor = "pom.xml"
	}
	dummyFile, err := os.Create(descriptor)
	assert.NoError(t, err)
	assert.NoError(t, dummyFile.Close())
}

// JAS

func TestXrayAuditSastCppFlagSimpleJson(t *testing.T) {
	integration.InitAuditJasTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("package-managers", "c"), "3", false, "*out*")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total:           &validations.TotalCount{Vulnerabilities: 2},
		Vulnerabilities: &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sast: 2}},
	})
}
func TestXrayAuditSastCSharpFlagSimpleJson(t *testing.T) {
	// Placeholder until C# Sast is implemented
	integration.InitAuditJasTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("package-managers", "dotnet", "dotnet-single"), "3", false, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total:           &validations.TotalCount{Vulnerabilities: 1},
		Vulnerabilities: &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sast: 1}},
	})
}

func TestXrayAuditJasMissingContextSimpleJson(t *testing.T) {
	integration.InitAuditJasTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("package-managers", "maven", "missing-context"), "3", false, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: &validations.VulnerabilityCount{ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{MissingContext: 1}},
	})
}

func TestXrayAuditNotEntitledForJas(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	cliToRun, cleanUp := integration.InitTestWithMockCommandOrParams(t, false, getNoJasAuditMockCommand)
	defer cleanUp()
	output := testXrayAuditJas(t, cliToRun, filepath.Join("jas", "jas"), "3", false, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 8}})
}

func getNoJasAuditMockCommand() components.Command {
	return components.Command{
		Name:  docs.Audit,
		Flags: docs.GetCommandFlags(docs.Audit),
		Action: func(c *components.Context) error {
			_, _, _, auditCmd, err := cli.CreateAuditCmd(c)
			if err != nil {
				return err
			}
			// Disable Jas for this test
			auditCmd.SetUseJas(false)
			return progressbar.ExecWithProgress(auditCmd)
		},
	}
}

func TestXrayAuditJasSimpleJson(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), "3", false, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 23},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 7, Sast: 1, Iac: 9, Secrets: 6},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, Undetermined: 1, NotCovered: 1, NotApplicable: 2},
		},
	})
}

func TestXrayAuditJasSimpleJsonWithTokenValidation(t *testing.T) {
	integration.InitAuditGeneralTests(t, jasutils.DynamicTokenValidationMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), "3", true, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Secrets: 5},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Inactive: 5},
		},
	})
}

func TestXrayAuditJasSimpleJsonWithOneThread(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), "1", false, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 23},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 7, Sast: 1, Iac: 9, Secrets: 6},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, Undetermined: 1, NotCovered: 1, NotApplicable: 2},
		},
	})
}

func TestXrayAuditJasSimpleJsonWithConfig(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas-config"), "3", false, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 8},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 7, Secrets: 1},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, Undetermined: 1, NotCovered: 1, NotApplicable: 2},
		},
	})
}

func TestXrayAuditJasNoViolationsSimpleJson(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("package-managers", "npm", "npm"), "3", false, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total:           &validations.TotalCount{Vulnerabilities: 1},
		Vulnerabilities: &validations.VulnerabilityCount{ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{NotApplicable: 1}},
	})
}

func testXrayAuditJas(t *testing.T, testCli *coreTests.JfrogCli, project string, threads string, validateSecrets bool, customExclusion string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), filepath.Join("projects", project)))
	defer cleanUp()
	// Configure a new server named "default"
	securityIntegrationTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	args := []string{"audit", "--format=" + string(format.SimpleJson), "--threads=" + threads}
	if validateSecrets {
		args = append(args, "--secrets", "--validate-secrets")
	}
	if len(customExclusion) != 0 {
		args = append(args, "--exclusions", customExclusion)
	}
	return testCli.WithoutCredentials().RunCliCmdWithOutput(t, args...)
}

func TestXrayAuditDetectTech(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "maven", "maven"))
	defer cleanUp()
	// Run generic audit on mvn project with a vulnerable dependency
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--licenses", "--format="+string(format.SimpleJson))
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)
	// Expects the ImpactedPackageType of the known vulnerability to be maven
	assert.Equal(t, strings.ToLower(results.Vulnerabilities[0].ImpactedDependencyType), "maven")
}

func TestXrayRecursiveScan(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	projectDir := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers")
	// Creating an inner NPM project
	tempDirPath, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(projectDir, "npm", "npm"))
	defer cleanUp()
	// Creating an inner .NET project
	dotnetDirPath, err := os.MkdirTemp(tempDirPath, "dotnet-project")
	assert.NoError(t, err)
	dotnetProjectToCopyPath := filepath.Join(projectDir, "dotnet", "dotnet-single")
	assert.NoError(t, biutils.CopyDir(dotnetProjectToCopyPath, dotnetDirPath, true, nil))

	// We anticipate the execution of a recursive scan to encompass both the inner NPM project and the inner .NET project.
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--format=json")

	// We anticipate the identification of five vulnerabilities: four originating from the .NET project and one from the NPM project.
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 4}})

	var results []services.ScanResponse
	err = json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)
	// We anticipate receiving an array with a length of 2 to confirm that we have obtained results from two distinct inner projects.
	assert.Len(t, results, 2)
}

func TestAuditOnEmptyProject(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), filepath.Join("projects", "empty_project", "python_project_with_no_deps")))
	defer cleanUp()
	// Configure a new server named "default"
	securityIntegrationTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()

	output := securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, "audit", "--format="+string(format.SimpleJson))
	// No issues should be found in an empty project
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{})
}

// xray-url only - the following tests check the case of adding "xray-url", instead of "url", which is the more common one

func TestXrayAuditNotEntitledForJasWithXrayUrl(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	cliToRun, cleanUp := integration.InitTestWithMockCommandOrParams(t, true, getNoJasAuditMockCommand)
	defer cleanUp()
	output := testXrayAuditJas(t, cliToRun, filepath.Join("jas", "jas"), "3", false, "")
	// Verify that scan results are printed
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 8}})
	// Verify that JAS results are not printed
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{})
}

func TestXrayAuditJasSimpleJsonWithXrayUrl(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	cliToRun := integration.GetTestCli(cli.GetJfrogCliSecurityApp(), true)
	output := testXrayAuditJas(t, cliToRun, filepath.Join("jas", "jas"), "3", false, "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 24},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 7, Sast: 1, Iac: 9, Secrets: 6},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, Undetermined: 1, NotCovered: 1, NotApplicable: 2},
		},
	})
}

// custom excluded folders

func TestXrayAuditJasSimpleJsonWithCustomExclusions(t *testing.T) {
	integration.InitAuditJasTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), "3", false, "non_existing_folder")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 24},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 7, Sast: 2, Iac: 9, Secrets: 6},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, Undetermined: 1, NotCovered: 1, NotApplicable: 2},
		},
	})
}

// test audit command parameters
type auditCommandTestParams struct {
	// Will combined with "," if provided and be used as --working-dirs flag value
	WorkingDirsToScan []string
	// Will be combined with ";" if provided and be used as --exclusions flag value
	CustomExclusion []string
	// --format flag value if provided
	Format string
	// Will combined with "," if provided and be used as --watches flag value
	Watches []string
	// --project flag value if provided.
	ProjectKey string
	// --fail flag value if provided, must be provided with 'createWatchesFuncs' to create watches for the test
	DisableFailOnFailedBuildFlag bool
	// -- vuln flag 'True' value must be provided with 'createWatchesFuncs' to create watches for the test
	WithVuln bool
	// --licenses flag value if provided
	WithLicense bool
}

func getAuditCmdArgs(params auditCommandTestParams) (args []string) {
	if len(params.WorkingDirsToScan) > 0 {
		args = append(args, "--working-dirs="+strings.Join(params.WorkingDirsToScan, ","))
	}
	if len(params.CustomExclusion) > 0 {
		args = append(args, "--exclusions="+strings.Join(params.CustomExclusion, ";"))
	}
	if params.Format != "" {
		args = append(args, "--format="+params.Format)
	}
	if params.WithLicense {
		args = append(args, "--licenses")
	}
	if params.ProjectKey != "" {
		args = append(args, "--project="+params.ProjectKey)
	}
	if len(params.Watches) > 0 {
		args = append(args, "--watches="+strings.Join(params.Watches, ","))
	}
	// Default value for --fail flag is 'true'. Unless we directly pass DisableFailOnFailedBuildFlag=true, the flow will fail when security issues are found
	if params.DisableFailOnFailedBuildFlag {
		args = append(args, "--fail=false")
	}
	if params.WithVuln {
		args = append(args, "--vuln")
	}
	return args
}
