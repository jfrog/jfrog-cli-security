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
	output := testAuditNpm(t, string(format.Json), false)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		SecurityViolations: 1,
		Licenses:           1,
	})
}

func TestXrayAuditNpmSimpleJson(t *testing.T) {
	output := testAuditNpm(t, string(format.SimpleJson), true)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		SecurityViolations: 1,
		Vulnerabilities:    1,
		Licenses:           1,
	})
}

func testAuditNpm(t *testing.T, format string, withVuln bool) string {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "npm", "npm"))
	defer cleanUp()
	// Run npm install before executing jfrog xr npm-audit
	assert.NoError(t, exec.Command("npm", "install").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	watchName, deleteWatch := securityTestUtils.CreateTestWatch(t, "audit-policy", "audit-watch", xrayUtils.High)
	defer deleteWatch()
	args := []string{"audit", "--npm", "--licenses", "--format=" + format, "--watches=" + watchName, "--fail=false"}
	if withVuln {
		args = append(args, "--vuln")
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, args...)
}

func TestXrayAuditConanJson(t *testing.T) {
	output := testAuditConan(t, string(format.Json), true)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 8,
		Licenses:        2,
	})
}

func TestXrayAuditConanSimpleJson(t *testing.T) {
	output := testAuditConan(t, string(format.SimpleJson), true)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 8,
		Licenses:        2,
	})
}

func testAuditConan(t *testing.T, format string, withVuln bool) string {
	integration.InitAuditCTest(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "conan"))
	defer cleanUp()
	// Run conan install before executing jfrog audit
	assert.NoError(t, exec.Command("conan").Run())
	watchName, deleteWatch := securityTestUtils.CreateTestWatch(t, "audit-curation-policy", "audit-curation-watch", xrayUtils.High)
	defer deleteWatch()
	args := []string{"audit", "--licenses", "--format=" + format, "--watches=" + watchName, "--fail=false"}
	if withVuln {
		args = append(args, "--vuln")
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, args...)
}

func TestXrayAuditPnpmJson(t *testing.T) {
	output := testXrayAuditPnpm(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Licenses:        1,
	})
}

func TestXrayAuditPnpmSimpleJson(t *testing.T) {
	output := testXrayAuditPnpm(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Licenses:        1,
	})
}

func testXrayAuditPnpm(t *testing.T, format string) string {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "npm", "npm-no-lock"))
	defer cleanUp()
	// Run pnpm install before executing audit
	assert.NoError(t, exec.Command("pnpm", "install").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--pnpm", "--licenses", "--format="+format)
}

func TestXrayAuditYarnV2Json(t *testing.T) {
	testXrayAuditYarn(t, "yarn-v2", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.Json))
		validations.VerifyJsonResults(t, output, validations.ValidationParams{
			Vulnerabilities: 1,
			Licenses:        1,
		})
	})
}

func TestXrayAuditYarnV2SimpleJson(t *testing.T) {
	testXrayAuditYarn(t, "yarn-v3", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.SimpleJson))
		validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
			Vulnerabilities: 1,
			Licenses:        1,
		})
	})
}

func TestXrayAuditYarnV1Json(t *testing.T) {
	testXrayAuditYarn(t, "yarn-v1", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.Json))
		validations.VerifyJsonResults(t, output, validations.ValidationParams{
			Vulnerabilities: 1,
			Licenses:        1,
		})
	})
}

func TestXrayAuditYarnV1JsonWithoutDevDependencies(t *testing.T) {
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
	testXrayAuditYarn(t, "yarn-v1", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.SimpleJson))
		validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
			Vulnerabilities: 1,
			Licenses:        1,
		})
	})
}

func testXrayAuditYarn(t *testing.T, projectDirName string, yarnCmd func()) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
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
					Vulnerabilities: test.minVulnerabilities,
					Licenses:        test.minLicences,
				})
			})
	}
}

func TestXrayAuditNugetSimpleJson(t *testing.T) {
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
					Vulnerabilities: test.minVulnerabilities,
					Licenses:        test.minLicences,
				})
			})
	}
}

func testXrayAuditNuget(t *testing.T, projectName, format string, restoreTech string) string {
	integration.InitAuditCTest(t, scangraph.GraphScanMinXrayVersion)
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
	output := testXrayAuditGradle(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 3,
		Licenses:        3,
	})
}

func TestXrayAuditGradleSimpleJson(t *testing.T) {
	output := testXrayAuditGradle(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 3,
		Licenses:        3,
	})
}

func testXrayAuditGradle(t *testing.T, format string) string {
	integration.InitAuditJavaTest(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "gradle", "gradle"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--gradle", "--licenses", "--format="+format)
}

func TestXrayAuditMavenJson(t *testing.T) {
	output := testXscAuditMaven(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Licenses:        1,
	})
}

func TestXrayAuditMavenSimpleJson(t *testing.T) {
	output := testXscAuditMaven(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Licenses:        1,
	})
}

func testXscAuditMaven(t *testing.T, format string) string {
	integration.InitAuditJavaTest(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "maven", "maven"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--mvn", "--licenses", "--format="+format)
}

func TestXrayAuditGoJson(t *testing.T) {
	output := testXrayAuditGo(t, false, string(format.Json), "simple-project")
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Licenses: 1, Vulnerabilities: 4})
}

func TestXrayAuditGoSimpleJson(t *testing.T) {
	output := testXrayAuditGo(t, true, string(format.SimpleJson), "simple-project")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Licenses: 3, Vulnerabilities: 4, NotCovered: 2, NotApplicable: 2})
}

func testXrayAuditGo(t *testing.T, noCreds bool, format, project string) string {
	integration.InitAuditGoTest(t, scangraph.GraphScanMinXrayVersion)
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
		Sast:    1,
		Iac:     9,
		Secrets: 6,

		Vulnerabilities: 35,
		Applicable:      3,
		Undetermined:    0,
		NotCovered:      22,
		NotApplicable:   2,
	})
}

func TestXrayAuditPipJson(t *testing.T) {
	output := testXrayAuditPip(t, string(format.Json), "")
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 3,
		Licenses:        1,
	})
}

func TestXrayAuditPipSimpleJson(t *testing.T) {
	output := testXrayAuditPip(t, string(format.SimpleJson), "")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 3,
		Licenses:        1,
	})
}

func TestXrayAuditPipJsonWithRequirementsFile(t *testing.T) {
	output := testXrayAuditPip(t, string(format.Json), "requirements.txt")
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Vulnerabilities: 2})
}

func TestXrayAuditPipSimpleJsonWithRequirementsFile(t *testing.T) {
	output := testXrayAuditPip(t, string(format.SimpleJson), "requirements.txt")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Vulnerabilities: 2})
}

func testXrayAuditPip(t *testing.T, format, requirementsFile string) string {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
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

func TestXrayAuditPipenvJson(t *testing.T) {
	output := testXrayAuditPipenv(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 3,
		Licenses:        1,
	})
}

func TestXrayAuditPipenvSimpleJson(t *testing.T) {
	output := testXrayAuditPipenv(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 3,
		Licenses:        1,
	})
}

func testXrayAuditPipenv(t *testing.T, format string) string {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "pipenv", "pipenv-project"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--pipenv", "--licenses", "--format="+format)
}

func TestXrayAuditPoetryJson(t *testing.T) {
	output := testXrayAuditPoetry(t, string(format.Json))
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 3,
		Licenses:        1,
	})
}

func TestXrayAuditPoetrySimpleJson(t *testing.T) {
	output := testXrayAuditPoetry(t, string(format.SimpleJson))
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 3,
		Licenses:        1,
	})
}

func testXrayAuditPoetry(t *testing.T, format string) string {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
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
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("package-managers", "c"), "3", false, true)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: 1,
		Sast:            1,
	})
}

func TestXrayAuditWithoutSastCppFlagSimpleJson(t *testing.T) {
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("package-managers", "c"), "3", false, false)
	// verify no results for Sast
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{})
}

func TestXrayAuditJasMissingContextSimpleJson(t *testing.T) {
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("package-managers", "maven", "missing-context"), "3", false, false)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{MissingContext: 1})
}

func TestXrayAuditNotEntitledForJas(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	cliToRun, cleanUp := integration.InitTestWithMockCommandOrParams(t, false, getNoJasAuditMockCommand)
	defer cleanUp()
	output := testXrayAuditJas(t, cliToRun, filepath.Join("jas", "jas"), "3", false, false)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Vulnerabilities: 8})
}

func getNoJasAuditMockCommand() components.Command {
	return components.Command{
		Name:  docs.Audit,
		Flags: docs.GetCommandFlags(docs.Audit),
		Action: func(c *components.Context) error {
			auditCmd, err := cli.CreateAuditCmd(c)
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
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), "3", false, false)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Sast:    1,
		Iac:     9,
		Secrets: 6,

		Vulnerabilities: 8,
		Applicable:      3,
		Undetermined:    1,
		NotCovered:      1,
		NotApplicable:   2,
	})
}

func TestXrayAuditJasSimpleJsonWithTokenValidation(t *testing.T) {
	integration.InitAuditGeneralTests(t, jasutils.DynamicTokenValidationMinXrayVersion)
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), "3", true, false)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Vulnerabilities: 5, Inactive: 5})
}

func TestXrayAuditJasSimpleJsonWithOneThread(t *testing.T) {
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), "1", false, false)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Sast:    1,
		Iac:     9,
		Secrets: 6,

		Vulnerabilities: 8,
		Applicable:      3,
		Undetermined:    1,
		NotCovered:      1,
		NotApplicable:   2,
	})
}

func TestXrayAuditJasSimpleJsonWithConfig(t *testing.T) {
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("jas", "jas-config"), "3", false, false)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Secrets: 1,

		Vulnerabilities: 8,
		Applicable:      3,
		Undetermined:    1,
		NotCovered:      1,
		NotApplicable:   2,
	})
}

func TestXrayAuditJasNoViolationsSimpleJson(t *testing.T) {
	output := testXrayAuditJas(t, securityTests.PlatformCli, filepath.Join("package-managers", "npm", "npm"), "3", false, false)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Vulnerabilities: 1, NotApplicable: 1})
}

func testXrayAuditJas(t *testing.T, testCli *coreTests.JfrogCli, project string, threads string, validateSecrets, validateSastCpp bool) string {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), filepath.Join("projects", project)))
	defer cleanUp()
	// Configure a new server named "default"
	securityIntegrationTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	args := []string{"audit", "--format=" + string(format.SimpleJson), "--threads=" + threads}
	if validateSecrets {
		args = append(args, "--secrets", "--validate-secrets")
	}
	if validateSastCpp {
		unsetEnv := clientTests.SetEnvWithCallbackAndAssert(t, "JFROG_SAST_ENABLE_CPP", "1")
		defer unsetEnv()
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
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Vulnerabilities: 4})

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
	cliToRun, cleanUp := integration.InitTestWithMockCommandOrParams(t, true, getNoJasAuditMockCommand)
	defer cleanUp()
	output := testXrayAuditJas(t, cliToRun, filepath.Join("jas", "jas"), "3", false, false)
	// Verify that scan results are printed
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Vulnerabilities: 8})
	// Verify that JAS results are not printed
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{})
}

func TestXrayAuditJasSimpleJsonWithXrayUrl(t *testing.T) {
	cliToRun := integration.GetTestCli(cli.GetJfrogCliSecurityApp(), true)
	output := testXrayAuditJas(t, cliToRun, filepath.Join("jas", "jas"), "3", false, false)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Sast:    1,
		Iac:     9,
		Secrets: 6,

		Vulnerabilities: 8,
		Applicable:      3,
		Undetermined:    1,
		NotCovered:      1,
		NotApplicable:   2,
	})
}
