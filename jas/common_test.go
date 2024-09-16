package jas

import (
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

func TestExcludeSuppressResults(t *testing.T) {
	tests := []struct {
		name           string
		sarifResults   []*sarif.Result
		expectedOutput []*sarif.Result
	}{
		{
			sarifResults: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1"),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
			expectedOutput: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1"),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
		},
		{
			sarifResults: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
			expectedOutput: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
		},
		{
			sarifResults: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
			},
			expectedOutput: []*sarif.Result{},
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, excludeSuppressResults(test.sarifResults))
	}
}

func TestAddScoreToRunRules(t *testing.T) {
	tests := []struct {
		name           string
		sarifRun       *sarif.Run
		expectedOutput []*sarif.ReportingDescriptor
	}{
		{
			sarifRun: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file1", 0, 0, 0, 0, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file2", 0, 0, 0, 0, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule2", "warning"),
			),
			expectedOutput: []*sarif.ReportingDescriptor{
				sarif.NewRule("rule1").WithProperties(sarif.Properties{"security-severity": "6.9"}),
				sarif.NewRule("rule2").WithProperties(sarif.Properties{"security-severity": "6.9"}),
			},
		},
		{
			sarifRun: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule1", "none"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule2", "note"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule3", "info"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule4", "warning"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule5", "error"),
			),
			expectedOutput: []*sarif.ReportingDescriptor{
				sarif.NewRule("rule1").WithProperties(sarif.Properties{"security-severity": "0.0"}),
				sarif.NewRule("rule2").WithProperties(sarif.Properties{"security-severity": "3.9"}),
				sarif.NewRule("rule3").WithProperties(sarif.Properties{"security-severity": "6.9"}),
				sarif.NewRule("rule4").WithProperties(sarif.Properties{"security-severity": "6.9"}),
				sarif.NewRule("rule5").WithProperties(sarif.Properties{"security-severity": "8.9"}),
			},
		},
	}

	for _, test := range tests {
		addScoreToRunRules(test.sarifRun)
		assert.Equal(t, test.expectedOutput, test.sarifRun.Tool.Driver.Rules)
	}
}

func TestConvertToFilesExcludePatterns(t *testing.T) {
	tests := []struct {
		name            string
		excludePatterns []string
		expectedOutput  []string
	}{
		{
			excludePatterns: []string{},
			expectedOutput:  []string{},
		},
		{
			excludePatterns: []string{"*.git*", "*node_modules*", "*target*", "*venv*", "*test*"},
			expectedOutput:  []string{"**/*.git*/**", "**/*node_modules*/**", "**/*target*/**", "**/*venv*/**", "**/*test*/**"},
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, convertToFilesExcludePatterns(test.excludePatterns))
	}
}

func TestGetJasEnvVars(t *testing.T) {
	tests := []struct {
		name            string
		serverDetails   *config.ServerDetails
		validateSecrets bool
		extraEnvVars    map[string]string
		expectedOutput  map[string]string
	}{
		{
			name: "Valid server details",
			serverDetails: &config.ServerDetails{
				Url:         "url",
				User:        "user",
				Password:    "password",
				AccessToken: "token",
			},
			expectedOutput: map[string]string{
				jfPlatformUrlEnvVariable:      "url",
				jfUserEnvVariable:             "user",
				jfPasswordEnvVariable:         "password",
				jfTokenEnvVariable:            "token",
				JfSecretValidationEnvVariable: "false",
			},
		},
		{
			name: "With validate secrets",
			serverDetails: &config.ServerDetails{
				Url:         "url",
				User:        "user",
				Password:    "password",
				AccessToken: "token",
			},
			extraEnvVars:    map[string]string{"test": "testValue"},
			validateSecrets: true,
			expectedOutput: map[string]string{
				jfPlatformUrlEnvVariable:      "url",
				jfUserEnvVariable:             "user",
				jfPasswordEnvVariable:         "password",
				jfTokenEnvVariable:            "token",
				JfSecretValidationEnvVariable: "true",
				"test":                        "testValue",
			},
		},
		{
			name: "Valid server details xray only",
			serverDetails: &config.ServerDetails{
				Url:         "",
				XrayUrl:     "url/xray",
				User:        "user",
				Password:    "password",
				AccessToken: "token",
			},
			expectedOutput: map[string]string{
				jfPlatformUrlEnvVariable:     "",
				jfPlatformXrayUrlEnvVariable: "url/xray",
				jfUserEnvVariable:            "user",
				jfPasswordEnvVariable:        "password",
				jfTokenEnvVariable:           "token",
			},
		},
		{
			name: "Valid server details both url and xray",
			serverDetails: &config.ServerDetails{
				Url:         "url",
				XrayUrl:     "url/xray",
				User:        "user",
				Password:    "password",
				AccessToken: "token",
			},
			expectedOutput: map[string]string{
				jfPlatformUrlEnvVariable:     "url",
				jfPlatformXrayUrlEnvVariable: "url/xray",
				jfUserEnvVariable:            "user",
				jfPasswordEnvVariable:        "password",
				jfTokenEnvVariable:           "token",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envVars, err := getJasEnvVars(test.serverDetails, test.validateSecrets, test.extraEnvVars)
			assert.NoError(t, err)
			for expectedKey, expectedValue := range test.expectedOutput {
				assert.Equal(t, expectedValue, envVars[expectedKey])
			}
		})
	}
}

func TestGetAnalyzerManagerXscEnvVars(t *testing.T) {
	tests := []struct {
		name           string
		msi            string
		technologies   []techutils.Technology
		expectedOutput map[string]string
	}{
		{
			name:         "One valid technology",
			msi:          "msi",
			technologies: []techutils.Technology{techutils.Maven},
			expectedOutput: map[string]string{
				JfPackageManagerEnvVariable: string(techutils.Maven),
				JfLanguageEnvVariable:       string(techutils.Java),
				utils.JfMsiEnvVariable:      "msi",
			},
		},
		{
			name:           "Multiple technologies",
			msi:            "msi",
			technologies:   []techutils.Technology{techutils.Maven, techutils.Npm},
			expectedOutput: map[string]string{utils.JfMsiEnvVariable: "msi"},
		},
		{
			name:           "Zero technologies",
			msi:            "msi",
			technologies:   []techutils.Technology{},
			expectedOutput: map[string]string{utils.JfMsiEnvVariable: "msi"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedOutput, GetAnalyzerManagerXscEnvVars(test.msi, test.technologies...))
		})
	}
}

func TestCreateScannerTempDirectory(t *testing.T) {
	scanner := &JasScanner{TempDir: "path"}
	tempDir, err := CreateScannerTempDirectory(scanner, jasutils.Applicability.String())
	assert.NoError(t, err)
	assert.NotEmpty(t, tempDir)

	// Check directory exists.
	_, err = os.Stat(tempDir)
	assert.NoError(t, err)
}

func TestCreateScannerTempDirectory_baseDirIsEmpty(t *testing.T) {
	scanner := &JasScanner{TempDir: ""}
	_, err := CreateScannerTempDirectory(scanner, jasutils.Applicability.String())
	assert.Error(t, err)
}
