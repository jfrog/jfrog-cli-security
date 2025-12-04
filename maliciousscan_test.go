package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	securityIntegrationTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
)

type maliciousScanCommandTestParams struct {
	WorkingDirsToScan []string
	Format            format.OutputFormat
	Threads           int
	MinSeverity       string
}

func getMaliciousScanCmdArgs(params maliciousScanCommandTestParams) (args []string) {
	args = []string{"malicious-scan"}
	if len(params.WorkingDirsToScan) > 0 {
		args = append(args, "--working-dirs="+strings.Join(params.WorkingDirsToScan, ","))
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

func runMaliciousScan(t *testing.T, params maliciousScanCommandTestParams) (string, error) {
	cleanUp := securityIntegrationTestUtils.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUp()
	return securityTests.PlatformCli.RunCliCmdWithOutputs(t, getMaliciousScanCmdArgs(params)...)
}

func TestMaliciousScan(t *testing.T) {
	testCases := []struct {
		name           string
		format         format.OutputFormat
		projectPath    string
		expectedIssues int
	}{
		{
			name:           "Malicious scan with findings (Simple JSON)",
			format:         format.SimpleJson,
			projectPath:    filepath.Join("projects", "jas", "jas", "malicious"),
			expectedIssues: 1,
		},
		{
			name:           "Malicious scan without findings (Simple JSON)",
			format:         format.SimpleJson,
			projectPath:    filepath.Join("projects", "empty_project", "python_project_with_no_deps"),
			expectedIssues: 0,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fullProjectPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), tc.projectPath)
			_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, fullProjectPath)
			defer cleanUp()

			params := maliciousScanCommandTestParams{
				Format: tc.format,
			}
			output, err := runMaliciousScan(t, params)
			assert.NoError(t, err)

			validationsParams := validations.ValidationParams{
				Vulnerabilities: &validations.VulnerabilityCount{
					ValidateScan: &validations.ScanCount{MaliciousCode: tc.expectedIssues},
				},
			}
			if tc.expectedIssues == 0 {
				validationsParams.ExactResultsMatch = true
			}
			validations.ValidateCommandOutput(t, output, tc.format, validationsParams)
		})
	}
}

func TestMaliciousScanWithWorkingDirs(t *testing.T) {
	maliciousProjectPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "jas", "jas", "malicious")
	_, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, maliciousProjectPath)
	defer cleanUp()

	params := maliciousScanCommandTestParams{
		WorkingDirsToScan: []string{"."},
		Format:            format.SimpleJson,
	}
	output, err := runMaliciousScan(t, params)
	assert.NoError(t, err)

	validationsParams := validations.ValidationParams{
		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan: &validations.ScanCount{MaliciousCode: 1},
		},
	}
	validations.ValidateCommandOutput(t, output, format.SimpleJson, validationsParams)
}
