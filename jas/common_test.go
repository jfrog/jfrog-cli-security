package jas

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"

	jfrogAppsConfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	clientTestUtils "github.com/jfrog/jfrog-client-go/utils/tests"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

var createJFrogAppsConfigCases = []struct {
	workingDirs []string
}{
	{workingDirs: []string{}},
	{workingDirs: []string{"working-dir"}},
	{workingDirs: []string{"working-dir-1", "working-dir-2"}},
}

func TestCreateJFrogAppsConfig(t *testing.T) {
	wd, err := os.Getwd()
	assert.NoError(t, err)

	for _, testCase := range createJFrogAppsConfigCases {
		t.Run(fmt.Sprintf("%v", testCase.workingDirs), func(t *testing.T) {
			jfrogAppsConfig, err := CreateJFrogAppsConfig(testCase.workingDirs)
			assert.NoError(t, err)
			assert.NotNil(t, jfrogAppsConfig)
			if len(testCase.workingDirs) == 0 {
				assert.Len(t, jfrogAppsConfig.Modules, 1)
				assert.Equal(t, wd, jfrogAppsConfig.Modules[0].SourceRoot)
				return
			}
			assert.Len(t, jfrogAppsConfig.Modules, len(testCase.workingDirs))
			for i, workingDir := range testCase.workingDirs {
				assert.Equal(t, filepath.Join(wd, workingDir), jfrogAppsConfig.Modules[i].SourceRoot)
			}
		})
	}
}

func TestCreateJFrogAppsConfigWithConfig(t *testing.T) {
	wd, err := os.Getwd()
	assert.NoError(t, err)
	chdirCallback := clientTestUtils.ChangeDirWithCallback(t, wd, "testdata")
	defer chdirCallback()

	jfrogAppsConfig, err := CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	assert.NotNil(t, jfrogAppsConfig)
	assert.Equal(t, "1.0", jfrogAppsConfig.Version)
	assert.Len(t, jfrogAppsConfig.Modules, 1)
}

func TestShouldSkipScanner(t *testing.T) {
	module := jfrogAppsConfig.Module{}
	assert.False(t, ShouldSkipScanner(module, jasutils.IaC))

	module = jfrogAppsConfig.Module{ExcludeScanners: []string{"sast"}}
	assert.False(t, ShouldSkipScanner(module, jasutils.IaC))
	assert.True(t, ShouldSkipScanner(module, jasutils.Sast))
}

var getSourceRootsCases = []struct {
	scanner *jfrogAppsConfig.Scanner
}{
	{scanner: nil},
	{&jfrogAppsConfig.Scanner{WorkingDirs: []string{"working-dir"}}},
	{&jfrogAppsConfig.Scanner{WorkingDirs: []string{"working-dir-1", "working-dir-2"}}},
}

func TestGetSourceRoots(t *testing.T) {
	testGetSourceRoots(t, "source-root")
}

func TestGetSourceRootsEmptySourceRoot(t *testing.T) {
	testGetSourceRoots(t, "")
}

func testGetSourceRoots(t *testing.T, sourceRoot string) {
	sourceRoot, err := filepath.Abs(sourceRoot)
	assert.NoError(t, err)
	module := jfrogAppsConfig.Module{SourceRoot: sourceRoot}
	for _, testCase := range getSourceRootsCases {
		t.Run("", func(t *testing.T) {
			scanner := testCase.scanner
			actualSourceRoots, err := GetSourceRoots(module, scanner)
			assert.NoError(t, err)
			if scanner == nil {
				assert.ElementsMatch(t, []string{module.SourceRoot}, actualSourceRoots)
				return
			}
			expectedWorkingDirs := []string{}
			for _, workingDir := range scanner.WorkingDirs {
				expectedWorkingDirs = append(expectedWorkingDirs, filepath.Join(module.SourceRoot, workingDir))
			}
			assert.ElementsMatch(t, actualSourceRoots, expectedWorkingDirs)
		})
	}
}

var getExcludePatternsCases = []struct {
	scanner *jfrogAppsConfig.Scanner
}{
	{scanner: nil},
	{&jfrogAppsConfig.Scanner{WorkingDirs: []string{"exclude-dir"}}},
	{&jfrogAppsConfig.Scanner{WorkingDirs: []string{"exclude-dir-1", "exclude-dir-2"}}},
}

func TestGetExcludePatterns(t *testing.T) {
	module := jfrogAppsConfig.Module{ExcludePatterns: []string{"exclude-root"}}
	for _, testCase := range getExcludePatternsCases {
		t.Run("", func(t *testing.T) {
			scanner := testCase.scanner
			actualExcludePatterns := GetExcludePatterns(module, scanner)
			if scanner == nil {
				assert.ElementsMatch(t, module.ExcludePatterns, actualExcludePatterns)
				return
			}
			expectedExcludePatterns := module.ExcludePatterns
			expectedExcludePatterns = append(expectedExcludePatterns, scanner.ExcludePatterns...)
			assert.ElementsMatch(t, actualExcludePatterns, expectedExcludePatterns)
		})
	}
}

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
				sarifutils.CreateResultWithOneLocation("file1", 0, 0, 0, 0, "snippet", "rule1", ""),
				sarifutils.CreateResultWithOneLocation("file2", 0, 0, 0, 0, "snippet", "rule1", ""),
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
				sarifutils.CreateDummyRuleWithProperties("rule3", sarif.Properties{"security-severity": "0.0"}),
				sarifutils.CreateDummyRuleWithProperties("rule2", sarif.Properties{"security-severity": "3.9"}),
				sarifutils.CreateDummyRuleWithProperties("rule4", sarif.Properties{"security-severity": "6.9"}),
				sarifutils.CreateDummyRuleWithProperties("rule5", sarif.Properties{"security-severity": "8.9"}),
			},
		},
	}

	for _, test := range tests {
		addScoreToRunRules(test.sarifRun)
		assert.ElementsMatch(t, test.expectedOutput, test.sarifRun.Tool.Driver.Rules)
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
		diffMode        JasDiffScanEnvValue
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
		{
			name: "Valid server details with diff mode",
			serverDetails: &config.ServerDetails{
				Url:         "url",
				User:        "user",
				Password:    "password",
				AccessToken: "token",
			},
			diffMode: FirstScanDiffScanEnvValue,
			expectedOutput: map[string]string{
				jfPlatformUrlEnvVariable:      "url",
				jfUserEnvVariable:             "user",
				jfPasswordEnvVariable:         "password",
				jfTokenEnvVariable:            "token",
				JfSecretValidationEnvVariable: "false",
				DiffScanEnvVariable:           string(FirstScanDiffScanEnvValue),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envVars, err := getJasEnvVars(test.serverDetails, test.validateSecrets, test.diffMode, test.extraEnvVars)
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

func TestGetDiffScanTypeValue(t *testing.T) {
	testResults := results.NewCommandResults(utils.SourceCode)
	tests := []struct {
		name             string
		diffScan         bool
		resultsToCompare *results.SecurityCommandResults
		expectedOutput   JasDiffScanEnvValue
	}{
		{
			name:           "Not Diff scan",
			expectedOutput: NotDiffScanEnvValue,
		},
		{
			name:           "Diff scan - First scan",
			diffScan:       true,
			expectedOutput: FirstScanDiffScanEnvValue,
		},
		{
			name:             "Diff scan - Second scan",
			diffScan:         true,
			resultsToCompare: testResults,
			expectedOutput:   SecondScanDiffScanEnvValue,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedOutput, GetDiffScanTypeValue(test.diffScan, test.resultsToCompare))
		})
	}
}

func TestGetResultsToCompare(t *testing.T) {
	testCases := []struct {
		name             string
		target           string
		ResultsToCompare *results.SecurityCommandResults
		expectedTarget   *results.TargetResults
	}{
		{
			name:             "No results to compare",
			target:           filepath.Join("path", "to", "target"),
			ResultsToCompare: results.NewCommandResults(utils.SourceCode),
			expectedTarget:   nil,
		},
		{
			name:   "Results to compare - target not found",
			target: filepath.Join("path", "to", "target"),
			ResultsToCompare: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: filepath.Join("path", "to", "another", "target")}},
				},
			},
			expectedTarget: nil,
		},
		{
			name:   "Results to compare - same path",
			target: filepath.Join("path", "to", "target"),
			ResultsToCompare: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: filepath.Join("path", "to", "target")}},
					{ScanTarget: results.ScanTarget{Target: filepath.Join("path", "to", "target2")}},
				},
			},
			expectedTarget: &results.TargetResults{ScanTarget: results.ScanTarget{Target: filepath.Join("path", "to", "target")}},
		},
		{
			name:   "Results to compare - match relative path",
			target: "target2",
			ResultsToCompare: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: filepath.Join("other", "root", "to", "target")}},
					{ScanTarget: results.ScanTarget{Target: filepath.Join("other", "root", "to", "target2")}},
				},
			},
			expectedTarget: &results.TargetResults{ScanTarget: results.ScanTarget{Target: filepath.Join("other", "root", "to", "target2")}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			scanner := &JasScanner{ResultsToCompare: testCase.ResultsToCompare}
			assert.Equal(t, testCase.expectedTarget, scanner.GetResultsToCompareByRelativePath(testCase.target))
		})
	}
}
