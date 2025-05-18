package jas

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
)

func TestReadJasScanRunsFromFile(t *testing.T) {
	dummyReport := sarif.NewReport()
	dummyReport.AddRun(sarifutils.CreateRunWithDummyResults(
		sarifutils.CreateResultWithOneLocation("file1", 0, 0, 0, 0, "snippet", "rule1", "info"),
		sarifutils.CreateResultWithOneLocation("file2", 0, 0, 0, 0, "snippet", "rule1", "info"),
	))

	tests := []struct {
		name             string
		generateVulnFile bool
		generateVioFile  bool
	}{
		{
			name:             "Expect AM to generate vulnerabilities file",
			generateVulnFile: true,
		},
		{
			name:            "Expect AM to generate violation file",
			generateVioFile: true,
		},
		{
			name:             "Expect AM to generate both files",
			generateVulnFile: true,
			generateVioFile:  true,
		},
		{
			// Expecting error if no files are generated.
			name: "AM generate none - error",
		},
	}

	for _, test := range tests {
		tempDir, cleanUp := coreTests.CreateTempDirWithCallbackAndAssert(t)
		defer cleanUp()
		fileName := filepath.Join(tempDir, "results.sarif")
		if test.generateVulnFile {
			assert.NoError(t, dummyReport.WriteFile(fileName))
		}
		if test.generateVioFile {
			assert.NoError(t, dummyReport.WriteFile(filepath.Join(tempDir, "results_violations.sarif")))
		}

		vuln, vio, err := ReadJasScanRunsFromFile(fileName, "some-working-dir-of-project", "docs URL", "")

		// Expecting error if no files are generated.
		if !test.generateVulnFile && !test.generateVioFile {
			assert.Error(t, err)
			assert.Empty(t, vuln)
			assert.Empty(t, vio)
			return
		}
		assert.NoError(t, err)
		if test.generateVulnFile {
			assert.NotEmpty(t, vuln)
		}
		if test.generateVioFile {
			assert.NotEmpty(t, vio)
		}
	}
}

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
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1").WithSuppressions([]*sarif.Suppression{sarif.NewSuppression()}),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
			expectedOutput: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
		},
		{
			sarifResults: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1").WithSuppressions([]*sarif.Suppression{sarif.NewSuppression()}),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2").WithSuppressions([]*sarif.Suppression{sarif.NewSuppression()}),
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
				sarifutils.CreateDummyRuleWithProperties("rule1", sarif.Properties{"security-severity": "6.9"}),
				sarifutils.CreateDummyRuleWithProperties("rule2", sarif.Properties{"security-severity": "6.9"}),
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
				sarifutils.CreateDummyRuleWithProperties("rule1", sarif.Properties{"security-severity": "0.0"}),
				sarifutils.CreateDummyRuleWithProperties("rule2", sarif.Properties{"security-severity": "3.9"}),
				sarifutils.CreateDummyRuleWithProperties("rule3", sarif.Properties{"security-severity": "6.9"}),
				sarifutils.CreateDummyRuleWithProperties("rule4", sarif.Properties{"security-severity": "6.9"}),
				sarifutils.CreateDummyRuleWithProperties("rule5", sarif.Properties{"security-severity": "8.9"}),
			},
		},
	}

	for _, test := range tests {
		addScoreToRunRules(test.sarifRun)
		assert.Equal(t, test.expectedOutput, test.sarifRun.Tool.Driver.Rules)
	}
}

func TestFilterUniqueAndConvertToFilesExcludePatterns(t *testing.T) {
	tests := []struct {
		name            string
		excludePatterns []string
		expectedOutput  []string
	}{
		{
			excludePatterns: []string{},
			expectedOutput:  []string(nil),
		},
		{
			excludePatterns: []string{"*.git*", "*node_modules*", "*target*", "*venv*", "*test*"},
			expectedOutput:  []string{"**/*.git*/**", "**/*node_modules*/**", "**/*target*/**", "**/*test*/**", "**/*venv*/**"},
		},
	}

	for _, test := range tests {
		filteredExcludePatterns := filterUniqueAndConvertToFilesExcludePatterns(test.excludePatterns)
		// Sort is needed since we create the response slice from a Set (unordered)
		slices.Sort(filteredExcludePatterns)
		assert.EqualValues(t, test.expectedOutput, filteredExcludePatterns)
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
		gitRepoUrl     string
		projectKey     string
		watches        []string
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
		{
			name:         "With git repo url",
			msi:          "msi",
			gitRepoUrl:   "gitRepoUrl",
			technologies: []techutils.Technology{techutils.Npm},
			expectedOutput: map[string]string{
				JfPackageManagerEnvVariable: string(techutils.Npm),
				JfLanguageEnvVariable:       string(techutils.JavaScript),
				utils.JfMsiEnvVariable:      "msi",
				gitRepoEnvVariable:          "gitRepoUrl",
			},
		},
		{
			name:         "With project key",
			msi:          "msi",
			gitRepoUrl:   "gitRepoUrl",
			projectKey:   "projectKey",
			technologies: []techutils.Technology{techutils.Npm},
			expectedOutput: map[string]string{
				JfPackageManagerEnvVariable: string(techutils.Npm),
				JfLanguageEnvVariable:       string(techutils.JavaScript),
				utils.JfMsiEnvVariable:      "msi",
				gitRepoEnvVariable:          "gitRepoUrl",
				projectEnvVariable:          "projectKey",
			},
		},
		{
			name:         "With watches",
			msi:          "msi",
			gitRepoUrl:   "gitRepoUrl",
			watches:      []string{"watch1", "watch2"},
			technologies: []techutils.Technology{techutils.Npm},
			expectedOutput: map[string]string{
				JfPackageManagerEnvVariable: string(techutils.Npm),
				JfLanguageEnvVariable:       string(techutils.JavaScript),
				utils.JfMsiEnvVariable:      "msi",
				gitRepoEnvVariable:          "gitRepoUrl",
				watchesEnvVariable:          "watch1,watch2",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedOutput, GetAnalyzerManagerXscEnvVars(test.msi, test.gitRepoUrl, test.projectKey, test.watches, test.technologies...))
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
