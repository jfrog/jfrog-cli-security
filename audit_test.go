package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"

	"github.com/jfrog/jfrog-cli-security/cli"
	"github.com/jfrog/jfrog-cli-security/cli/docs"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-cli-security/utils/formats"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/stretchr/testify/assert"

	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/progressbar"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	scangraphstrategy "github.com/jfrog/jfrog-cli-security/sca/scan/scangraph"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	securityIntegrationTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

// test audit command parameters
type auditCommandTestParams struct {
	// Will combined with "," if provided and be used as --working-dirs flag value
	WorkingDirsToScan []string
	// Will be combined with ";" if provided and be used as --exclusions flag value
	CustomExclusion []string
	// --format flag value if provided
	Format format.OutputFormat
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
	// --sbom flag value if provided
	WithSbom bool
	// adds "--secrets", "--validate-secrets" flags if true
	ValidateSecrets bool
	// --threads flag value if provided
	Threads int
	// adds '--requirements-file' flag with the given value
	WithRequirementsFile string
}

func getAuditCmdArgs(params auditCommandTestParams) (args []string) {
	args = []string{"audit"}
	if len(params.WorkingDirsToScan) > 0 {
		args = append(args, "--working-dirs="+strings.Join(params.WorkingDirsToScan, ","))
	}
	if len(params.CustomExclusion) > 0 {
		args = append(args, "--exclusions="+strings.Join(params.CustomExclusion, ";"))
	}
	if params.Format != "" {
		args = append(args, "--format="+string(params.Format))
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
	if params.WithRequirementsFile != "" {
		args = append(args, "--requirements-file="+params.WithRequirementsFile)
	}
	if params.WithVuln {
		args = append(args, "--vuln")
	}
	if params.ValidateSecrets {
		args = append(args, "--secrets", "--validate-secrets")
	}
	if params.WithSbom {
		args = append(args, "--sbom")
	}
	if params.Threads > 0 {
		args = append(args, "--threads="+strconv.Itoa(params.Threads))
	}
	return args
}

func TestXrayAuditNpm(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	testCases := []struct {
		name     string
		format   format.OutputFormat
		withVuln bool
	}{
		{
			name:   "No violations (JSON)",
			format: format.Json,
		},
		{
			name:     "No violations (Simple JSON)",
			format:   format.SimpleJson,
			withVuln: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validationsParams := validations.ValidationParams{
				Total:      &validations.TotalCount{Licenses: 1, Violations: 1},
				Violations: &validations.ViolationCount{ValidateType: &validations.ScaViolationCount{Security: 1}},
			}
			if tc.withVuln {
				validationsParams.Total.Vulnerabilities = 1
				validationsParams.Vulnerabilities = &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sca: 1}}
			}
			validations.ValidateCommandOutput(t, testAuditNpm(t, tc.format, "xray-", tc.withVuln), tc.format, validationsParams)
		})
	}
}

func testAuditNpm(t *testing.T, format format.OutputFormat, violationContextPrefix string, withVuln bool) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "npm", "npm"))
	defer cleanUp()
	// Run npm install before executing jfrog audit
	assert.NoError(t, exec.Command("npm", "install").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	watchName, deleteWatch := securityTestUtils.CreateTestPolicyAndWatch(t, violationContextPrefix+string(format)+"-npm-audit-policy", violationContextPrefix+string(format)+"-npm-audit-watch", xrayUtils.High)
	defer deleteWatch()
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	params := auditCommandTestParams{
		WithLicense:                  true,
		Format:                       format,
		Watches:                      []string{watchName},
		DisableFailOnFailedBuildFlag: true,
	}
	if withVuln {
		params.WithVuln = true
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(params), "--npm")...)
}

func TestXrayAuditConan(t *testing.T) {
	integration.InitAuditCTest(t, scangraph.GraphScanMinXrayVersion)
	testCases := []struct {
		name     string
		format   format.OutputFormat
		withVuln bool
	}{
		{
			name:   "No violations (JSON)",
			format: format.Json,
		},
		{
			name:     "No violations (Simple JSON)",
			format:   format.SimpleJson,
			withVuln: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validationsParams := validations.ValidationParams{
				Total:      &validations.TotalCount{Licenses: 2, Violations: 4},
			}
			if tc.withVuln {
				validationsParams.Total.Vulnerabilities = 8
				// Not supported in JSON format
				validationsParams.Vulnerabilities = &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sca: 8}}
				validationsParams.Violations = &validations.ViolationCount{ValidateType: &validations.ScaViolationCount{Security: 4}}
			}
			validations.ValidateCommandOutput(t, testAuditConan(t, tc.format, tc.withVuln), tc.format, validationsParams)
		})
	}
}

func testAuditConan(t *testing.T, format format.OutputFormat, withVuln bool) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "conan"))
	defer cleanUp()
	// Run conan install before executing jfrog audit
	assert.NoError(t, exec.Command("conan").Run())
	watchName, deleteWatch := securityTestUtils.CreateTestPolicyAndWatch(t, string(format)+"-conan-audit-policy", string(format)+"-conan-audit-watch", xrayUtils.High)
	defer deleteWatch()
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	params := auditCommandTestParams{
		WithLicense:                  true,
		Format:                       format,
		Watches:                      []string{watchName},
		DisableFailOnFailedBuildFlag: true,
	}
	if withVuln {
		params.WithVuln = true
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, getAuditCmdArgs(params)...)
}

func TestXrayAuditPnpmJson(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	for _, format := range []format.OutputFormat{format.Json, format.SimpleJson} {
		t.Run(string(format), func(t *testing.T) {
			validations.ValidateCommandOutput(t, testXrayAuditPnpm(t, format), format, validations.ValidationParams{
				Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
			})
		})
	}
}

func testXrayAuditPnpm(t *testing.T, format format.OutputFormat) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "npm", "npm-no-lock"))
	defer cleanUp()
	// Run pnpm install before executing audit
	assert.NoError(t, exec.Command("pnpm", "install").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(auditCommandTestParams{WithLicense: true, Format: format}), "--pnpm")...)
}

func TestXrayAuditYarn(t *testing.T) {
	integration.InitAuditJavaScriptTest(t, scangraph.GraphScanMinXrayVersion)
	testCases := []struct {
		name              string
		project           string
		format            format.OutputFormat
		noDevDependencies bool
	}{
		{
			name:    "Yarn v1",
			project: "yarn-v1",
			format:  format.Json,
		},
		{
			name:              "Yarn v1 without dev dependencies",
			project:           "yarn-v1",
			format:            format.Json,
			noDevDependencies: true,
		},
		{
			name:    "Yarn v2",
			project: "yarn-v2",
			format:  format.Json,
		},
		{
			name:    "Yarn v3",
			project: "yarn-v3",
			format:  format.SimpleJson,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validationsParams := validations.ValidationParams{Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1}}
			if tc.noDevDependencies {
				unsetEnv := clientTests.SetEnvWithCallbackAndAssert(t, "NODE_ENV", "production")
				defer unsetEnv()
				validationsParams.Total.Vulnerabilities = 0
			}
			validations.ValidateCommandOutput(t, runXrayAuditYarnWithOutput(t, tc.project, tc.format), tc.format, validationsParams)
		})
	}
}

func runXrayAuditYarnWithOutput(t *testing.T, projectDirName string, format format.OutputFormat) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "yarn", projectDirName))
	defer cleanUp()
	// Run yarn install before executing jf audit --yarn. Return error to assert according to test.
	assert.NoError(t, exec.Command("yarn").Run())
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, true)
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	params := auditCommandTestParams{Format: format, WithLicense: true}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(params), "--yarn")...)
}

func TestXrayAuditNugetDotNet(t *testing.T) {
	integration.InitAuditCTest(t, scangraph.GraphScanMinXrayVersion)
	var testdata = []struct {
		projectName        string
		format             format.OutputFormat
		restoreTech        string
		minVulnerabilities int
		minLicences        int
	}{
		{
			projectName:        "single4.0",
			format:             format.Json,
			restoreTech:        "nuget",
			minVulnerabilities: 2,
			minLicences:        0,
		},
		{
			projectName:        "single5.0",
			format:             format.Json,
			restoreTech:        "dotnet",
			minVulnerabilities: 3,
			minLicences:        2,
		},
		{
			projectName:        "single5.0",
			format:             format.Json,
			restoreTech:        "",
			minVulnerabilities: 3,
			minLicences:        2,
		},
		{
			projectName:        "multi",
			format:             format.Json,
			restoreTech:        "dotnet",
			minVulnerabilities: 4,
			minLicences:        3,
		},
		{
			projectName:        "multi",
			format:             format.Json,
			restoreTech:        "",
			minVulnerabilities: 4,
			minLicences:        3,
		},
		{
			projectName:        "single4.0",
			format:             format.SimpleJson,
			restoreTech:        "nuget",
			minVulnerabilities: 2,
			minLicences:        0,
		},
		{
			projectName:        "single5.0",
			format:             format.SimpleJson,
			restoreTech:        "dotnet",
			minVulnerabilities: 3,
			minLicences:        2,
		},
		{
			projectName:        "single5.0",
			format:             format.SimpleJson,
			restoreTech:        "",
			minVulnerabilities: 3,
			minLicences:        2,
		},
	}
	for _, test := range testdata {
		runInstallCommand := test.restoreTech != ""
		t.Run(fmt.Sprintf("projectName:%s,runInstallCommand:%t", test.projectName, runInstallCommand),
			func(t *testing.T) {
				validations.ValidateCommandOutput(t, testXrayAuditNuget(t, test.projectName, test.format, test.restoreTech), test.format, validations.ValidationParams{
					Total: &validations.TotalCount{Licenses: test.minLicences, Vulnerabilities: test.minVulnerabilities},
				})
			})
	}
}

func testXrayAuditNuget(t *testing.T, projectName string, format format.OutputFormat, restoreTech string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "nuget", projectName))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	// Run NuGet/Dotnet restore before executing jfrog xr audit (NuGet)
	if restoreTech != "" {
		output, err := exec.Command(restoreTech, "restore").CombinedOutput()
		assert.NoError(t, err, string(output))
	}
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(auditCommandTestParams{WithLicense: true, Format: format}), "--nuget")...)
}

func TestXrayAuditGradle(t *testing.T) {
	integration.InitAuditJavaTest(t, scangraph.GraphScanMinXrayVersion)
	for _, format := range []format.OutputFormat{format.Json, format.SimpleJson} {
		t.Run(string(format), func(t *testing.T) {
			validations.ValidateCommandOutput(t, testXrayAuditGradle(t, format), format, validations.ValidationParams{
				Total: &validations.TotalCount{Licenses: 3, Vulnerabilities: 3},
			})
		})
	}
}

func testXrayAuditGradle(t *testing.T, format format.OutputFormat) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "gradle", "gradle"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(auditCommandTestParams{WithLicense: true, Format: format}), "--gradle")...)
}

func TestXrayAuditMaven(t *testing.T) {
	integration.InitAuditJavaTest(t, scangraph.GraphScanMinXrayVersion)
	for _, format := range []format.OutputFormat{format.Json, format.SimpleJson} {
		t.Run(string(format), func(t *testing.T) {
			validations.ValidateCommandOutput(t, testAuditMaven(t, format), format, validations.ValidationParams{
				Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
			})
		})
	}
}

func testAuditMaven(t *testing.T, format format.OutputFormat) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "maven", "maven"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(auditCommandTestParams{WithLicense: true, Format: format}), "--mvn")...)
}

func TestXrayAuditGo(t *testing.T) {
	integration.InitAuditGoTest(t, scangraph.GraphScanMinXrayVersion)
	for _, outFormat := range []format.OutputFormat{format.Json, format.SimpleJson} {
		t.Run(string(outFormat), func(t *testing.T) {
			validationParams := validations.ValidationParams{
				Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 4},
			}
			if outFormat == format.SimpleJson {
				validationParams.Vulnerabilities = &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sca: 4}}
				validationParams.Vulnerabilities.ValidateApplicabilityStatus = &validations.ApplicabilityStatusCount{NotCovered: 1, NotApplicable: 3}
			}
			validations.ValidateCommandOutput(t, testXrayAuditGo(t, outFormat, "simple-project"), outFormat, validationParams)
		})
	}
}

func testXrayAuditGo(t *testing.T, format format.OutputFormat, project string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "go", project))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	// Run audit command without creds flags
	return securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, append(getAuditCmdArgs(auditCommandTestParams{WithLicense: true, Format: format}), "--go")...)
}

func TestXrayAuditNoTech(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	prevWd := securityTestUtils.ChangeWD(t, tempDirPath)
	defer clientTests.ChangeDirAndAssert(t, prevWd)
	cleanUp := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUp()
	// Run audit on empty folder
	assert.NoError(t, securityTests.PlatformCli.Exec("audit"))
}

func TestXrayAuditMultiProjects(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects"))
	defer cleanUp()
	// Configure a new server named "default"
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()

	params := auditCommandTestParams{
		WorkingDirsToScan: []string{
			filepath.Join("package-managers", "maven", "maven"),
			filepath.Join("package-managers", "nuget", "single4.0"),
			filepath.Join("package-managers", "python", "pip", "pip-project"),
			filepath.Join("jas", "jas"),
		},
		Format: format.SimpleJson,
	}
	output := securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, getAuditCmdArgs(params)...)
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 43},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 27, Sast: 1, Iac: 9, Secrets: 6},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, NotCovered: 22, NotApplicable: 2},
		},
	})
}

func TestXrayAuditPip(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	testCases := []struct {
		name             string
		outFormat        format.OutputFormat
		requirementsFile string
	}{
		{
			name:      "Pip JSON format",
			outFormat: format.Json,
		},
		{
			name:      "Pip Simple JSON format",
			outFormat: format.SimpleJson,
		},
		{
			name:             "Pip JSON format with requirements file",
			outFormat:        format.Json,
			requirementsFile: "requirements.txt",
		},
		{
			name:             "Pip Simple JSON format with requirements file",
			outFormat:        format.SimpleJson,
			requirementsFile: "requirements.txt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := testXrayAuditPip(t, tc.outFormat, tc.requirementsFile)
			validationParams := validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 2}}
			if tc.requirementsFile == "" {
				validationParams = validations.ValidationParams{
					Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
				}
			}
			validations.ValidateCommandOutput(t, output, tc.outFormat, validationParams)
		})
	}
}

func testXrayAuditPip(t *testing.T, outFormat format.OutputFormat, requirementsFile string) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "pip", "pip-project"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	params := auditCommandTestParams{
		WithLicense:          true,
		Format:               outFormat,
		WithRequirementsFile: requirementsFile,
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(params), "--pip")...)
}

func TestXrayAuditCocoapods(t *testing.T) {
	integration.InitAuditCocoapodsTest(t, scangraph.CocoapodsScanMinXrayVersion)
	output := testXrayAuditCocoapods(t, format.Json)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 1}})
}

func testXrayAuditCocoapods(t *testing.T, format format.OutputFormat) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "cocoapods"))
	defer cleanUp()
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, getAuditCmdArgs(auditCommandTestParams{Format: format})...)
}

func TestXrayAuditSwift(t *testing.T) {
	output := testXrayAuditSwift(t, format.Json)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 1},
	})
}

func testXrayAuditSwift(t *testing.T, format format.OutputFormat) string {
	integration.InitAuditSwiftTest(t, scangraph.SwiftScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "swift"))
	defer cleanUp()
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, getAuditCmdArgs(auditCommandTestParams{Format: format})...)
}

func TestXrayAuditPipenv(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	testCases := []struct {
		name   string
		format format.OutputFormat
	}{
		{
			name:   "Pipenv JSON format",
			format: format.Json,
		},
		{
			name:   "Pipenv Simple JSON format",
			format: format.SimpleJson,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validations.ValidateCommandOutput(t, testXrayAuditPipenv(t, tc.format), tc.format, validations.ValidationParams{
				Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
			})
		})
	}
}

func testXrayAuditPipenv(t *testing.T, format format.OutputFormat) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "pipenv", "pipenv-project"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(auditCommandTestParams{WithLicense: true, Format: format}), "--pipenv")...)
}

func TestXrayAuditPoetry(t *testing.T) {
	integration.InitAuditPythonTest(t, scangraph.GraphScanMinXrayVersion)
	testCases := []struct {
		name   string
		format format.OutputFormat
	}{
		{
			name:   "Poetry JSON format",
			format: format.Json,
		},
		{
			name:   "Poetry Simple JSON format",
			format: format.SimpleJson,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validations.ValidateCommandOutput(t, testXrayAuditPoetry(t, tc.format), tc.format, validations.ValidationParams{
				Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 3},
			})
		})
	}
}

func testXrayAuditPoetry(t *testing.T, format format.OutputFormat) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "poetry", "poetry-project"))
	defer cleanUp()
	// Add dummy descriptor file to check that we run only specific audit
	addDummyPackageDescriptor(t, false)
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, append(getAuditCmdArgs(auditCommandTestParams{WithLicense: true, Format: format}), "--poetry")...)
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

func TestAuditJasCycloneDx(t *testing.T) {
	integration.InitAuditJasTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("jas", "jas-npm"), auditCommandTestParams{
		WithSbom: true,
		Threads:  3,
		Format:   format.CycloneDx,
	})
	validations.VerifyCycloneDxResults(t, output, validations.ValidationParams{
		Total:          &validations.TotalCount{Vulnerabilities: 6, SbomComponents: 6},
		SbomComponents: &validations.SbomCount{Direct: 2, Transitive: 4},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 3, Sast: 2, Secrets: 1},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{NotCovered: 2, NotApplicable: 1},
		},
	})
}

func TestXrayAuditSastCppFlagSimpleJson(t *testing.T) {
	integration.InitAuditJasTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("package-managers", "c"), auditCommandTestParams{
		Threads:         3,
		CustomExclusion: []string{"*out*"},
		Format:          format.SimpleJson,
	})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total:           &validations.TotalCount{Vulnerabilities: 2},
		Vulnerabilities: &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sast: 2}},
	})
}
func TestXrayAuditSastCSharpFlagSimpleJson(t *testing.T) {
	integration.InitAuditJasTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("package-managers", "dotnet", "dotnet-single"), auditCommandTestParams{
		Threads: 3,
		Format:  format.SimpleJson,
	})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total:           &validations.TotalCount{Vulnerabilities: 1},
		Vulnerabilities: &validations.VulnerabilityCount{ValidateScan: &validations.ScanCount{Sast: 1}},
	})
}

func TestXrayAuditJasMissingContextSimpleJson(t *testing.T) {
	integration.InitAuditJasTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("package-managers", "maven", "missing-context"), auditCommandTestParams{
		Threads: 3,
		Format:  format.SimpleJson,
	})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: &validations.VulnerabilityCount{ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{MissingContext: 1}},
	})
}

func TestXrayAuditNotEntitledForJas(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	cliToRun, cleanUp := integration.InitTestWithMockCommandOrParams(t, false, getNoJasAuditMockCommand)
	defer cleanUp()
	output := testXrayAuditWithCleanHome(t, cliToRun, filepath.Join("jas", "jas"), auditCommandTestParams{
		Threads: 3,
		Format:  format.SimpleJson,
	})
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
			auditCmd.SetBomGenerator(buildinfo.NewBuildInfoBomGenerator()).SetScaScanStrategy(scangraphstrategy.NewScanGraphStrategy())
			return progressbar.ExecWithProgress(auditCmd)
		},
	}
}

func TestXrayAuditJasSimpleJson(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), auditCommandTestParams{
		Threads: 3,
		Format:  format.SimpleJson,
	})
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
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), auditCommandTestParams{
		ValidateSecrets: true,
		Threads:         3,
		Format:          format.SimpleJson,
	})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Secrets: 5},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Inactive: 5},
		},
	})
}

func TestXrayAuditJasSimpleJsonWithOneThread(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), auditCommandTestParams{
		Threads: 1,
		Format:  format.SimpleJson,
	})
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
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("jas", "jas-config"), auditCommandTestParams{
		Threads: 3,
		Format:  format.SimpleJson,
	})
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
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("package-managers", "npm", "npm"), auditCommandTestParams{
		Threads: 3,
		Format:  format.SimpleJson,
	})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total:           &validations.TotalCount{Vulnerabilities: 1},
		Vulnerabilities: &validations.VulnerabilityCount{ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{NotApplicable: 1}},
	})
}

func testXrayAuditWithCleanHome(t *testing.T, testCli *coreTests.JfrogCli, project string, params auditCommandTestParams) string {
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), filepath.Join("projects", project)))
	defer cleanUp()
	// Configure a new server named "default"
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	return testCli.WithoutCredentials().RunCliCmdWithOutput(t, getAuditCmdArgs(params)...)
}

func TestXrayAuditDetectTech(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "maven", "maven"))
	defer cleanUp()
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
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
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "audit", "--format=json")
	// We anticipate the identification of five vulnerabilities: four originating from the .NET project and one from the NPM project.
	validations.VerifyJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 4}})
	var results []services.ScanResponse
	err = json.Unmarshal([]byte(output), &results)
	assert.NoError(t, err)
	// We anticipate receiving an array with a length of 2 to confirm that we have obtained results from two distinct inner projects.
	assert.Len(t, results, 2)
}

func TestAuditNoDependencyProject(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), filepath.Join("projects", "empty_project", "python_project_with_no_deps")))
	defer cleanUp()
	cleanUpHome := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()
	output := securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, "audit", "--format="+string(format.SimpleJson))
	// No issues should be found in an empty project
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{ExactResultsMatch: true})
}

// xray-url only - the following tests check the case of adding "xray-url", instead of "url", which is the more common one

func TestXrayAuditNotEntitledForJasWithXrayUrl(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	cliToRun, cleanUp := integration.InitTestWithMockCommandOrParams(t, true, getNoJasAuditMockCommand)
	defer cleanUp()
	output := testXrayAuditWithCleanHome(t, cliToRun, filepath.Join("jas", "jas"), auditCommandTestParams{
		Threads: 3,
		Format:  format.SimpleJson,
	})
	// Verify that scan results are printed
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: 8}})
	// Verify that JAS results are not printed
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{})
}

func TestXrayAuditJasSimpleJsonWithXrayUrl(t *testing.T) {
	integration.InitAuditGeneralTests(t, scangraph.GraphScanMinXrayVersion)
	cliToRun := integration.GetXrayTestCli(cli.GetJfrogCliSecurityApp(), true)
	output := testXrayAuditWithCleanHome(t, cliToRun, filepath.Join("jas", "jas"), auditCommandTestParams{
		Threads: 3,
		Format:  format.SimpleJson,
	})
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
	output := testXrayAuditWithCleanHome(t, securityTests.PlatformCli, filepath.Join("jas", "jas"), auditCommandTestParams{
		CustomExclusion: []string{"non_existing_folder"},
		Threads:         3,
		Format:          format.SimpleJson,
	})
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Vulnerabilities: 24},
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 7, Sast: 2, Iac: 9, Secrets: 6},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, Undetermined: 1, NotCovered: 1, NotApplicable: 2},
		},
	})
}
