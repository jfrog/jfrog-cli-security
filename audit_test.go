package main

import (
	"encoding/json"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/utils"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	"github.com/jfrog/jfrog-cli-security/scangraph"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestXrayAuditNpmJson(t *testing.T) {
	output := testXrayAuditNpm(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}

func TestXrayAuditNpmSimpleJson(t *testing.T) {
	output := testXrayAuditNpm(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1)
}

func testXrayAuditNpm(t *testing.T, format string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	npmProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "npm", "npm")
	// Copy the npm project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(npmProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Run npm install before executing jfrog xr npm-audit
	assert.NoError(t, exec.Command("npm", "install").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--npm", "--licenses", "--format="+format)
}

func TestXrayAuditPnpmJson(t *testing.T) {
	output := testXrayAuditPnpm(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}

func TestXrayAuditPnpmSimpleJson(t *testing.T) {
	output := testXrayAuditPnpm(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1)
}

func testXrayAuditPnpm(t *testing.T, format string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	npmProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "npm", "npm-no-lock")
	// Copy the npm project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(npmProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Run pnpm install before executing audit
	assert.NoError(t, exec.Command("pnpm", "install").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--pnpm", "--licenses", "--format="+format)
}

func TestXrayAuditYarnV2Json(t *testing.T) {
	testXrayAuditYarn(t, "yarn-v2", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.Json))
		securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
	})
}

func TestXrayAuditYarnV2SimpleJson(t *testing.T) {
	testXrayAuditYarn(t, "yarn-v3", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.SimpleJson))
		securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1)
	})
}

func TestXrayAuditYarnV1Json(t *testing.T) {
	testXrayAuditYarn(t, "yarn-v1", func() {
		output := runXrayAuditYarnWithOutput(t, string(format.Json))
		securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
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
		securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1)
	})
}

func testXrayAuditYarn(t *testing.T, projectDirName string, yarnCmd func()) {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	yarnProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "yarn", projectDirName)
	// Copy the Yarn project from the testdata to a temp directory
	assert.NoError(t, biutils.CopyDir(yarnProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
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
			minVulnerabilities: 5,
			minLicences:        3,
		},
		{
			projectName:        "multi",
			format:             string(format.Json),
			restoreTech:        "",
			minVulnerabilities: 5,
			minLicences:        3,
		},
	}
	for _, test := range testdata {
		runInstallCommand := test.restoreTech != ""
		t.Run(fmt.Sprintf("projectName:%s,runInstallCommand:%t", test.projectName, runInstallCommand),
			func(t *testing.T) {
				output := testXrayAuditNuget(t, test.projectName, test.format, test.restoreTech)
				securityTestUtils.VerifyJsonScanResults(t, output, 0, test.minVulnerabilities, test.minLicences)
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
				securityTestUtils.VerifySimpleJsonScanResults(t, output, test.minVulnerabilities, test.minLicences)
			})
	}
}

func testXrayAuditNuget(t *testing.T, projectName, format string, restoreTech string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	projectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "nuget", projectName)

	assert.NoError(t, biutils.CopyDir(projectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	// Run NuGet/Dotnet restore before executing jfrog xr audit (NuGet)
	if restoreTech != "" {
		_, err := exec.Command(restoreTech, "restore").CombinedOutput()
		assert.NoError(t, err)
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--nuget", "--format="+format, "--licenses")
}

func TestXrayAuditGradleJson(t *testing.T) {
	output := testXrayAuditGradle(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 3, 3)
}

func TestXrayAuditGradleSimpleJson(t *testing.T) {
	output := testXrayAuditGradle(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 3, 3)
}

func testXrayAuditGradle(t *testing.T, format string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	gradleProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "gradle", "gradle")
	// Copy the gradle project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(gradleProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--gradle", "--licenses", "--format="+format)
}

func TestXrayAuditMavenJson(t *testing.T) {
	output := testXrayAuditMaven(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}

func TestXrayAuditMavenSimpleJson(t *testing.T) {
	output := testXrayAuditMaven(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1)
}

func testXrayAuditMaven(t *testing.T, format string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	mvnProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "maven", "maven")
	// Copy the maven project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(mvnProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--mvn", "--licenses", "--format="+format)
}

func TestXrayAuditNoTech(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Run audit on empty folder, expect an error
	err := securityTests.PlatformCli.Exec("audit")
	assert.NoError(t, err)
}

func TestXrayAuditMultiProjects(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	multiProject := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects")
	// Copy the multi project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(multiProject, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	workingDirsFlag := fmt.Sprintf("--working-dirs=%s, %s ,%s, %s",
		filepath.Join(tempDirPath, "package-managers", "maven", "maven"), filepath.Join(tempDirPath, "package-managers", "nuget", "single4.0"),
		filepath.Join(tempDirPath, "package-managers", "python", "pip", "pip-project"), filepath.Join(tempDirPath, "jas", "jas-test"))
	// Configure a new server named "default"
	securityTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	output := securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, "audit", "--format="+string(format.SimpleJson), workingDirsFlag)
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 35, 0)
	securityTestUtils.VerifySimpleJsonJasResults(t, output, 1, 9, 7, 6, 0, 25, 1)
}

func TestXrayAuditPipJson(t *testing.T) {
	output := testXrayAuditPip(t, string(format.Json), "")
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 3, 1)
}

func TestXrayAuditPipSimpleJson(t *testing.T) {
	output := testXrayAuditPip(t, string(format.SimpleJson), "")
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 3, 1)
}

func TestXrayAuditPipJsonWithRequirementsFile(t *testing.T) {
	output := testXrayAuditPip(t, string(format.Json), "requirements.txt")
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 2, 0)
}

func TestXrayAuditPipSimpleJsonWithRequirementsFile(t *testing.T) {
	output := testXrayAuditPip(t, string(format.SimpleJson), "requirements.txt")
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 2, 0)
}

func testXrayAuditPip(t *testing.T, format, requirementsFile string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	pipProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "python", "pip", "pip-project")
	// Copy the pip project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(pipProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
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
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 3, 1)
}

func TestXrayAuditPipenvSimpleJson(t *testing.T) {
	output := testXrayAuditPipenv(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 3, 1)
}

func testXrayAuditPipenv(t *testing.T, format string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	pipenvProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "python", "pipenv", "pipenv-project")
	// Copy the pipenv project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(pipenvProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--pipenv", "--licenses", "--format="+format)
}

func TestXrayAuditPoetryJson(t *testing.T) {
	output := testXrayAuditPoetry(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 3, 1)
}

func TestXrayAuditPoetrySimpleJson(t *testing.T) {
	output := testXrayAuditPoetry(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 3, 1)
}

func testXrayAuditPoetry(t *testing.T, format string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	poetryProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "python", "poetry", "poetry-project")
	// Copy the poetry project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(poetryProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
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

func TestXrayAuditJasSimpleJson(t *testing.T) {
	output := testXrayAuditJas(t, string(format.SimpleJson), filepath.Join("jas", "jas-test"))
	securityTestUtils.VerifySimpleJsonJasResults(t, output, 1, 9, 7, 3, 0, 3, 1)
}

func TestXrayAuditJasSimpleJsonWithConfig(t *testing.T) {
	output := testXrayAuditJas(t, string(format.SimpleJson), filepath.Join("jas", "jas-config"))
	securityTestUtils.VerifySimpleJsonJasResults(t, output, 0, 0, 1, 3, 0, 3, 1)
}

func TestXrayAuditJasNoViolationsSimpleJson(t *testing.T) {
	output := testXrayAuditJas(t, string(format.SimpleJson), filepath.Join("package-managers", "npm", "npm"))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 0)
	securityTestUtils.VerifySimpleJsonJasResults(t, output, 0, 0, 0, 0, 0, 0, 1)
}

func testXrayAuditJas(t *testing.T, format string, project string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	projectDir := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), filepath.Join("projects", project))
	// Copy the multi project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(projectDir, tempDirPath, true, nil))
	// Configure a new server named "default"
	securityTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	baseWd, err := os.Getwd()
	assert.NoError(t, err)
	chdirCallback := clientTests.ChangeDirWithCallback(t, baseWd, tempDirPath)
	defer chdirCallback()
	return securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, "audit", "--format="+format)
}

func TestXrayAuditDetectTech(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	mvnProjectPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "maven", "maven")
	// Copy the maven project from the testdata to a temp dir
	assert.NoError(t, biutils.CopyDir(mvnProjectPath, tempDirPath, true, nil))
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	// Run generic audit on mvn project with a vulnerable dependency
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--licenses", "--format="+string(format.SimpleJson))
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)
	// Expects the ImpactedPackageType of the known vulnerability to be maven
	assert.Equal(t, strings.ToLower(results.Vulnerabilities[0].ImpactedDependencyType), "maven")
}

func TestXrayRecursiveScan(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	projectDir := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers")
	// Creating an inner NPM project
	npmDirPath, err := os.MkdirTemp(tempDirPath, "npm-project")
	assert.NoError(t, err)
	npmProjectToCopyPath := filepath.Join(projectDir, "npm", "npm")
	assert.NoError(t, biutils.CopyDir(npmProjectToCopyPath, npmDirPath, true, nil))

	// Creating an inner .NET project
	dotnetDirPath, err := os.MkdirTemp(tempDirPath, "dotnet-project")
	assert.NoError(t, err)
	dotnetProjectToCopyPath := filepath.Join(projectDir, "dotnet", "dotnet-single")
	assert.NoError(t, biutils.CopyDir(dotnetProjectToCopyPath, dotnetDirPath, true, nil))

	curWd, err := os.Getwd()
	assert.NoError(t, err)

	chDirCallback := clientTests.ChangeDirWithCallback(t, curWd, tempDirPath)
	defer chDirCallback()

	// We anticipate the execution of a recursive scan to encompass both the inner NPM project and the inner .NET project.
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--format=json")

	// We anticipate the identification of five vulnerabilities: four originating from the .NET project and one from the NPM project.
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 5, 0)

	var results []services.ScanResponse
	err = json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)
	// We anticipate receiving an array with a length of 2 to confirm that we have obtained results from two distinct inner projects.
	assert.Len(t, results, 2)
}

func TestXscAnalyticsForAudit(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	securityTestUtils.ValidateXscVersion(t, xscservices.AnalyticsMetricsMinXscVersion)
	reportUsageCallBack := clientTests.SetEnvWithCallbackAndAssert(t, coreutils.ReportUsage, "true")
	defer reportUsageCallBack()
	// Scan npm project and verify that analytics general event were sent to XSC.
	output := testXrayAuditNpm(t, string(format.SimpleJson))
	validateAnalyticsBasicEvent(t, output)
}

func validateAnalyticsBasicEvent(t *testing.T, output string) {
	// Get MSI.
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)

	// Verify analytics metrics.
	am := utils.NewAnalyticsMetricsService(securityTests.XscDetails)
	assert.NotNil(t, am)
	assert.NotEmpty(t, results.MultiScanId)
	event, err := am.GetGeneralEvent(results.MultiScanId)
	assert.NoError(t, err)

	// Event creation and addition information.
	assert.Equal(t, "cli", event.Product)
	assert.Equal(t, 1, event.EventType)
	assert.NotEmpty(t, event.AnalyzerManagerVersion)
	assert.NotEmpty(t, event.EventStatus)
	// The information that was added after updating the event with the scan's results.
	assert.NotEmpty(t, event.TotalScanDuration)
	assert.True(t, event.TotalFindings > 0)
}
