package main

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	securityIntegrationTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
)

// test malicious-scan command parameters
type maliciousScanCommandTestParams struct {
	// Will be combined with "," if provided and be used as --working-dirs flag value
	WorkingDirsToScan []string
	// --format flag value if provided
	Format format.OutputFormat
	// --threads flag value if provided
	Threads int
	// --min-severity flag value if provided
	MinSeverity string
}

func getMaliciousScanCmdArgs(params maliciousScanCommandTestParams) (args []string) {
	args = []string{"malicious-scan"}
	if len(params.WorkingDirsToScan) > 0 {
		workingDirs := ""
		for i, dir := range params.WorkingDirsToScan {
			if i > 0 {
				workingDirs += ","
			}
			workingDirs += dir
		}
		args = append(args, "--working-dirs="+workingDirs)
	}
	if params.Format != "" {
		args = append(args, "--format="+string(params.Format))
	}
	if params.Threads > 0 {
		args = append(args, "--threads="+strconv.Itoa(params.Threads))
	}
	if params.MinSeverity != "" {
		args = append(args, "--min-severity="+params.MinSeverity)
	}
	return args
}

func testMaliciousScan(t *testing.T, params maliciousScanCommandTestParams, errorExpected bool) string {
	output, err := runMaliciousScan(t, params)
	if errorExpected {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
	return output
}

func runMaliciousScan(t *testing.T, params maliciousScanCommandTestParams) (string, error) {
	cleanUp := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUp()
	return securityTests.PlatformCli.RunCliCmdWithOutputs(t, getMaliciousScanCmdArgs(params)...)
}

func TestMaliciousScanWithMaliciousFile(t *testing.T) {
	testCases := []struct {
		name   string
		format format.OutputFormat
	}{
		{
			name:   "Malicious scan with findings (Simple JSON)",
			format: format.SimpleJson,
		},
		{
			name:   "Malicious scan with findings (Table)",
			format: format.Table,
		},
		{
			name:   "Malicious scan with findings (SARIF)",
			format: format.Sarif,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validationsParams := validations.ValidationParams{
				Vulnerabilities: &validations.VulnerabilityCount{
					ValidateScan: &validations.ScanCount{MaliciousCode: 1},
				},
			}
			validations.ValidateCommandOutput(t, testMaliciousScanWithMaliciousFile(t, tc.format), tc.format, validationsParams)
		})
	}
}

func testMaliciousScanWithMaliciousFile(t *testing.T, format format.OutputFormat) string {
	maliciousProjectPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "jas", "jas", "malicious")
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, maliciousProjectPath)
	defer cleanUp()

	params := maliciousScanCommandTestParams{
		Format: format,
	}
	return testMaliciousScan(t, params, false)
}

func TestMaliciousScanNoMaliciousFile(t *testing.T) {
	testCases := []struct {
		name   string
		format format.OutputFormat
	}{
		{
			name:   "Malicious scan without findings (Simple JSON)",
			format: format.SimpleJson,
		},
		{
			name:   "Malicious scan without findings (Table)",
			format: format.Table,
		},
		{
			name:   "Malicious scan without findings (SARIF)",
			format: format.Sarif,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validationsParams := validations.ValidationParams{
				Vulnerabilities: &validations.VulnerabilityCount{
					ValidateScan: &validations.ScanCount{MaliciousCode: 0},
				},
			}
			validations.ValidateCommandOutput(t, testMaliciousScanNoMaliciousFile(t, tc.format), tc.format, validationsParams)
		})
	}
}

func testMaliciousScanNoMaliciousFile(t *testing.T, format format.OutputFormat) string {
	// Use a project directory that doesn't contain malicious files
	emptyProjectPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "empty_project", "python_project_with_no_deps")
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, emptyProjectPath)
	defer cleanUp()

	params := maliciousScanCommandTestParams{
		Format: format,
	}
	return testMaliciousScan(t, params, false)
}

func TestMaliciousScanWithWorkingDirs(t *testing.T) {
	maliciousProjectPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "jas", "jas", "malicious")
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, maliciousProjectPath)
	defer cleanUp()

	params := maliciousScanCommandTestParams{
		WorkingDirsToScan: []string{"."},
		Format:            format.SimpleJson,
	}
	output := testMaliciousScan(t, params, false)
	validationsParams := validations.ValidationParams{
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan: &validations.ScanCount{MaliciousCode: 1},
		},
	}
	validations.ValidateCommandOutput(t, output, format.SimpleJson, validationsParams)
}
