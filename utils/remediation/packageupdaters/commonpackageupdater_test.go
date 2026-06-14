package packageupdaters

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/build-info-go/tests"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
)

type dependencyFixTest struct {
	fixDetails          *FixDetails
	fixSupported        bool
	errorExpected       bool
	specificTechVersion string
	testDirName         string
	descriptorsToCheck  []string
	testcaseInfo        string
	// For this param give the relative path from the test project root
	lockFileToVerifyItsChange string
	// Verifies descriptor content is unchanged after error (for rollback testing)
	descriptorToVerifyNoChange string
}

const (
	requirementsFile = "oslo.config>=1.12.1,<1.13\noslo.utils<5.0,>=4.0.0\nparamiko==2.7.2\npasslib<=1.7.4\nprance>=0.9.0\nprompt-toolkit~=1.0.15\npyinotify>0.9.6\nPyJWT>1.7.1\nurllib3 > 1.1.9, < 1.5.*"
)

type pipPackageRegexTest struct {
	packageName         string
	expectedRequirement string
}

func TestUpdateDependency(t *testing.T) {
	if strings.TrimSuffix(os.Getenv("JF_URL"), "/") == "" {
		t.Skipf("skipping: JF_URL is not set (package updater integration tests run in CI with platform credentials)")
	}

	testCases := [][]dependencyFixTest{
		// Go test cases
		{
			{
				fixDetails:                createFixDetails(techutils.Go, "golang.org/x/crypto", "", "0.0.0-20201216223049-8b5274cf687f", false, "go.mod"),
				fixSupported:              true,
				descriptorsToCheck:        []string{"go.mod"},
				lockFileToVerifyItsChange: "go.sum",
			},
			{
				fixDetails:                createFixDetails(techutils.Go, "github.com/google/uuid", "", "1.3.0", true, "go.mod"),
				fixSupported:              true,
				descriptorsToCheck:        []string{"go.mod"},
				lockFileToVerifyItsChange: "go.sum",
			},
			{
				testcaseInfo:  "no-location-evidence",
				fixDetails:    createFixDetails(techutils.Go, "github.com/google/uuid", "", "1.3.0", true),
				fixSupported:  true,
				errorExpected: true,
			},
		},

		// Python test cases (includes pip, pipenv, poetry)
		{
			{
				fixDetails:   createFixDetails(techutils.Pip, "urllib3", "", "1.25.9", false, ""),
				fixSupported: false,
			},
			{
				fixDetails:   createFixDetails(techutils.Poetry, "urllib3", "", "1.25.9", false, ""),
				fixSupported: false,
			},
			{
				fixDetails:   createFixDetails(techutils.Pipenv, "urllib3", "", "1.25.9", false, ""),
				fixSupported: false,
			},
			{
				fixDetails:         createFixDetails(techutils.Pip, "pyjwt", "", "2.4.0", true, ""),
				fixSupported:       true,
				descriptorsToCheck: []string{"requirements.txt"},
			},
			{
				fixDetails:         createFixDetails(techutils.Pip, "Pyjwt", "", "2.4.0", true, ""),
				fixSupported:       true,
				descriptorsToCheck: []string{"requirements.txt"},
			},
			{
				fixDetails:         createFixDetails(techutils.Poetry, "pyjwt", "", "2.4.0", true, ""),
				fixSupported:       true,
				descriptorsToCheck: []string{"pyproject.toml"},
			},
			{
				fixDetails:         createFixDetails(techutils.Pipenv, "pyjwt", "", "2.4.0", true, ""),
				fixSupported:       true,
				descriptorsToCheck: []string{"Pipfile"},
			},
		},

		// Npm test cases
		{
			{
				// Test project doesn't exist for the testcase - we just check skipping indirect dependency fix
				testcaseInfo: "test-skip-fixing-indirect",
				fixDetails:   createFixDetails(techutils.Npm, "mpath", "0.8.3", "0.8.4", false, "package-lock.json"),
				fixSupported: false,
			},
			{
				fixDetails:                createFixDetails(techutils.Npm, "minimist", "1.2.5", "1.2.6", true, "package.json", "package-lock.json"),
				fixSupported:              true,
				descriptorsToCheck:        []string{"package.json"},
				lockFileToVerifyItsChange: "package-lock.json",
			},
			{
				testcaseInfo:  "no-location-evidence",
				fixDetails:    createFixDetails(techutils.Npm, "minimist", "1.2.5", "1.2.6", true),
				fixSupported:  true,
				errorExpected: true,
			},
			{
				testcaseInfo:               "rollback-on-npm-install-failure",
				fixDetails:                 createFixDetails(techutils.Npm, "minimist", "1.2.5", "1.2.6", true, "package.json", "package-lock.json"),
				testDirName:                "npm-rollback",
				fixSupported:               true,
				errorExpected:              true,
				descriptorToVerifyNoChange: "package.json",
			},
		},

		// Maven test cases
		{
			{
				fixDetails:   createFixDetails(techutils.Maven, "org.springframework:spring-core", "", "4.3.20", false, ""),
				fixSupported: false,
			},
			{
				fixDetails:         createFixDetails(techutils.Maven, "commons-io:commons-io", "", "2.7", true, filepath.Join("multi1", "pom.xml")),
				fixSupported:       true,
				descriptorsToCheck: []string{filepath.Join("multi1", "pom.xml")},
			},
		},

		// Pnpm test cases
		{
			{
				fixDetails:   createFixDetails(techutils.Pnpm, "mpath", "", "0.8.4", false, ""),
				fixSupported: false,
				testDirName:  "npm",
			},
			{
				fixDetails:         createFixDetails(techutils.Pnpm, "minimist", "1.2.5", "1.2.6", true, "package.json", "package-lock.json"),
				fixSupported:       true,
				testDirName:        "npm",
				descriptorsToCheck: []string{"package.json"},
			},
		},
	}

	for _, testBatch := range testCases {
		for _, test := range testBatch {
			packageUpdater, _ := GetCompatiblePackageUpdater(test.fixDetails)
			t.Run(getUpdateDependencyTestcaseName(test.fixDetails.Technology.String()+test.specificTechVersion, test.fixDetails.IsDirectDependency, test.testcaseInfo),
				func(t *testing.T) {
					testDataDir := getTestDataDir(t, test.fixDetails.IsDirectDependency)
					testDirName := test.fixDetails.Technology.String()
					if test.testDirName != "" {
						testDirName = test.testDirName
					}
					cleanup := createTempDirAndChdir(t, testDataDir, testDirName+test.specificTechVersion)
					defer cleanup()

					var lockFileContentBeforeUpdate []byte
					if test.lockFileToVerifyItsChange != "" {
						var readErr error
						lockFileContentBeforeUpdate, readErr = os.ReadFile(test.lockFileToVerifyItsChange)
						assert.NoError(t, readErr, "Failed to read lock file before update")
					}

					var descriptorContentBeforeUpdate []byte
					if test.descriptorToVerifyNoChange != "" {
						var readErr error
						descriptorContentBeforeUpdate, readErr = os.ReadFile(test.descriptorToVerifyNoChange)
						assert.NoError(t, readErr, "Failed to read descriptor before update")
					}

					err := packageUpdater.UpdateDependency(test.fixDetails)
					if !test.fixSupported {
						assert.Error(t, err)
						assert.IsType(t, &ErrUnsupportedFix{}, err, "Expected unsupported fix error")
						return
					}

					if test.errorExpected {
						assert.Error(t, err)
						if test.descriptorToVerifyNoChange != "" {
							descriptorContentAfter, readErr := os.ReadFile(test.descriptorToVerifyNoChange)
							assert.NoError(t, readErr, "Failed to read descriptor after update")
							assert.Equal(t, descriptorContentBeforeUpdate, descriptorContentAfter, "Descriptor should be unchanged after rollback")
						}
						return
					}

					assert.NoError(t, err)
					verifyDependencyUpdate(t, test)

					if test.lockFileToVerifyItsChange != "" {
						lockFileContentAfter, readErr := os.ReadFile(test.lockFileToVerifyItsChange)
						assert.NoError(t, readErr, "Failed to read lock file after update")
						assert.NotEqual(t, lockFileContentBeforeUpdate, lockFileContentAfter, "Lock file should have been updated")
					}
				})
		}
	}
}

func getTestDataDir(t *testing.T, directDependency bool) string {
	var projectDir string
	if directDependency {
		projectDir = "projects"
	} else {
		projectDir = "indirect-projects"
	}
	testdataDir, err := filepath.Abs(filepath.Join("..", "testdata", projectDir))
	assert.NoError(t, err)
	return testdataDir
}

func createTempDirAndChdir(t *testing.T, testdataDir string, tech string) func() {
	// Create temp technology project
	projectPath := filepath.Join(testdataDir, tech)
	tmpProjectPath, cleanup := tests.CreateTestProject(t, projectPath)
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	assert.NoError(t, os.Chdir(tmpProjectPath))
	if tech == "go" {
		err = removeTxtSuffix("go.mod.txt")
		assert.NoError(t, err)
		err = removeTxtSuffix("go.sum.txt")
		assert.NoError(t, err)
		err = removeTxtSuffix("main.go.txt")
		assert.NoError(t, err)
	}
	return func() {
		cleanup()
		assert.NoError(t, os.Chdir(currDir))
	}
}

func removeTxtSuffix(txtFileName string) error {
	// go.sum.txt  >> go.sum
	return fileutils.MoveFile(txtFileName, strings.TrimSuffix(txtFileName, ".txt"))
}

func assertFixVersionInPackageDescriptor(t *testing.T, test dependencyFixTest, packageDescriptors []string) {
	for _, packageDescriptorToCheck := range packageDescriptors {
		file, err := os.ReadFile(packageDescriptorToCheck)
		assert.NoError(t, err)

		assert.Contains(t, string(file), test.fixDetails.SuggestedFixedVersion)
		// Verify that case-sensitive packages in python are lowered
		assert.Contains(t, string(file), strings.ToLower(test.fixDetails.ImpactedDependencyName))
	}
}

// Verifies the expected dependency update happened and extra check that are unique to selected package managers
func verifyDependencyUpdate(t *testing.T, test dependencyFixTest) {
	if len(test.descriptorsToCheck) == 0 {
		assert.Fail(t, fmt.Sprintf("Please provide descriptor files to be inspected in the 'descriptorsToCheck' for %s test cases where a fix is supported.", test.fixDetails.Technology))
	}

	currDir, err := os.Getwd()
	assert.NoError(t, err)

	var descriptorsFullPaths []string
	for _, descriptorToCheck := range test.descriptorsToCheck {
		descriptorsFullPaths = append(descriptorsFullPaths, filepath.Join(currDir, descriptorToCheck))
	}

	if test.fixDetails.Technology == techutils.Maven {
		// In Maven descriptors the dependency's artifact name and group name are split into 2 different lines, therefore we change the ImpactedDependencyName to be the dependency's artifact name only
		depArtifactAndGroup := strings.Split(test.fixDetails.ImpactedDependencyName, ":")
		assert.Equal(t, len(depArtifactAndGroup), 2)
		test.fixDetails.ImpactedDependencyName = depArtifactAndGroup[1]
	}
	assertFixVersionInPackageDescriptor(t, test, descriptorsFullPaths)
}

func TestGetFixedPackage(t *testing.T) {
	var testcases = []struct {
		impactedPackage       string
		versionOperator       string
		suggestedFixedVersion string
		expectedOutput        []string
	}{
		{
			impactedPackage:       "snappier",
			versionOperator:       " -v ",
			suggestedFixedVersion: "1.1.1",
			expectedOutput:        []string{"snappier", "-v", "1.1.1"},
		},
		{
			impactedPackage:       "json",
			versionOperator:       "@",
			suggestedFixedVersion: "10.0.0",
			expectedOutput:        []string{"json@10.0.0"},
		},
	}

	for _, test := range testcases {
		fixedPackageArgs := GetFixedPackage(test.impactedPackage, test.versionOperator, test.suggestedFixedVersion)
		assert.Equal(t, test.expectedOutput, fixedPackageArgs)
	}
}

func TestGetAllDescriptorFilesFullPaths(t *testing.T) {
	var testcases = []struct {
		testProjectRepo        string
		suffixesToSearch       []string
		expectedResultSuffixes []string
		patternsToExclude      []string
	}{
		{
			testProjectRepo:        "maven",
			suffixesToSearch:       []string{"pom.xml"},
			expectedResultSuffixes: []string{"pom.xml"},
		},
	}

	currDir, outerErr := os.Getwd()
	assert.NoError(t, outerErr)

	for _, testcase := range testcases {
		tmpDir, err := os.MkdirTemp("", "")
		assert.NoError(t, err)
		assert.NoError(t, copyDir(filepath.Join("..", "testdata", "projects", testcase.testProjectRepo), tmpDir))
		assert.NoError(t, os.Chdir(tmpDir))

		finalDirPath, err := os.Getwd()
		assert.NoError(t, err)

		var expectedResults []string
		for _, suffix := range testcase.expectedResultSuffixes {
			expectedResults = append(expectedResults, filepath.Join(finalDirPath, suffix))
		}

		var cph CommonPackageUpdater
		descriptorFilesFullPaths, err := cph.GetAllDescriptorFilesFullPaths(testcase.suffixesToSearch, testcase.patternsToExclude...)
		assert.NoError(t, err)
		assert.ElementsMatch(t, expectedResults, descriptorFilesFullPaths)

		assert.NoError(t, os.Chdir(currDir))
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
}

func TestGetVulnerabilityLocations(t *testing.T) {
	testcases := []struct {
		name          string
		fixDetails    *FixDetails
		namesFilters  []string
		ignoreFilters []string
		expectedPaths []string
	}{
		{
			name: "single component with descriptor evidence",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "/repo/package.json"}}},
				},
			},
			expectedPaths: []string{"/repo/package.json"},
		},
		{
			name: "multiple components with same evidence - deduplicated",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "/repo/package.json"}}},
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "/repo/package.json"}}},
				},
			},
			expectedPaths: []string{"/repo/package.json"},
		},
		{
			name: "multiple components with different descriptor locations",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "/repo/app1/package.json"}}},
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "/repo/app2/package.json"}}},
				},
			},
			expectedPaths: []string{"/repo/app1/package.json", "/repo/app2/package.json"},
		},
		{
			name: "component with empty evidences",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{}},
				},
			},
			expectedPaths: []string{},
		},
		{
			name: "component with empty file path in evidence",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: ""}}},
				},
			},
			expectedPaths: []string{},
		},
		{
			name: "no components",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{},
			},
			expectedPaths: []string{},
		},
		{
			name: "non-descriptor evidences are filtered out",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{
						{File: "package-lock.json"},
						{File: "package.json"},
					}},
				},
			},
			expectedPaths: []string{"package.json"},
		},
		{
			name: "filter by basename - match",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "package.json"}}},
					{Name: "lodash", Version: "4.17.0", Evidences: []formats.Location{{File: "go.mod"}}},
				},
			},
			namesFilters:  []string{"package.json"},
			expectedPaths: []string{"package.json"},
		},
		{
			name: "filter by basename - no match",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "package.json"}}},
				},
			},
			namesFilters:  []string{"go.mod"},
			expectedPaths: []string{},
		},
		{
			name: "filter by basename - full path matched by basename",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "/repo/apps/frontend/package.json"}}},
					{Name: "lodash", Version: "4.17.0", Evidences: []formats.Location{{File: "/repo/go.mod"}}},
				},
			},
			namesFilters:  []string{"package.json"},
			expectedPaths: []string{"/repo/apps/frontend/package.json"},
		},
		{
			name: "filter with multiple allowed names",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{{File: "package.json"}}},
					{Name: "lodash", Version: "4.17.0", Evidences: []formats.Location{{File: "go.mod"}}},
					{Name: "axios", Version: "0.21.0", Evidences: []formats.Location{{File: "pyproject.toml"}}},
				},
			},
			namesFilters:  []string{"package.json", "go.mod"},
			expectedPaths: []string{"package.json", "go.mod"},
		},
		{
			name: "empty filter returns all descriptor locations",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{
						{File: "package-lock.json"},
						{File: "package.json"},
					}},
				},
			},
			namesFilters:  []string{},
			expectedPaths: []string{"package.json"},
		},
		{
			name: "nil filter returns all descriptor locations",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{
						{File: "package-lock.json"},
						{File: "package.json"},
					}},
				},
			},
			namesFilters:  nil,
			expectedPaths: []string{"package.json"},
		},
		{
			name: "multiple evidences per component - descriptors collected from all",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{
						{File: "/repo/app1/package.json"},
						{File: "/repo/app1/package-lock.json"},
						{File: "/repo/app2/package.json"},
					}},
				},
			},
			expectedPaths: []string{"/repo/app1/package.json", "/repo/app2/package.json"},
		},
		{
			name: "ignoreFilters excludes paths containing pattern",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{
						{File: "package.json"},
						{File: "node_modules/minimist/package.json"},
						{File: "libs/node_modules/foo/package.json"},
					}},
				},
			},
			ignoreFilters: []string{"node_modules"},
			expectedPaths: []string{"package.json"},
		},
		{
			name: "ignoreFilters with multiple patterns",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{
						{File: "package.json"},
						{File: "node_modules/minimist/package.json"},
						{File: "vendor/something/package.json"},
					}},
				},
			},
			ignoreFilters: []string{"node_modules", "vendor"},
			expectedPaths: []string{"package.json"},
		},
		{
			name: "ignoreFilters nil does not filter",
			fixDetails: &FixDetails{
				Components: []formats.ComponentRow{
					{Name: "minimist", Version: "1.2.5", Evidences: []formats.Location{
						{File: "package.json"},
						{File: "sub/package.json"},
					}},
				},
			},
			ignoreFilters: nil,
			expectedPaths: []string{"package.json", "sub/package.json"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := GetVulnerabilityLocations(tc.fixDetails, tc.namesFilters, tc.ignoreFilters)
			assert.ElementsMatch(t, tc.expectedPaths, result)
		})
	}
}

func TestEnvWithCorepackIntegrityWorkaround(t *testing.T) {
	t.Parallel()
	base := []string{"FOO=1", "COREPACK_INTEGRITY_KEYS=old-value", "BAR=2"}
	out := EnvWithCorepackIntegrityWorkaround(base)
	var foo, bar, corepack int
	for _, e := range out {
		switch {
		case e == "FOO=1":
			foo++
		case e == "BAR=2":
			bar++
		case strings.HasPrefix(e, "COREPACK_INTEGRITY_KEYS="):
			corepack++
			assert.Equal(t, "COREPACK_INTEGRITY_KEYS=0", e)
		}
	}
	assert.Equal(t, 1, foo, "FOO should appear once")
	assert.Equal(t, 1, bar, "BAR should appear once")
	assert.Equal(t, 1, corepack, "COREPACK_INTEGRITY_KEYS should appear exactly once with value 0")
}

func TestGetVulnerabilityRegexCompiler(t *testing.T) {
	// Sample format patterns from different package managers
	const (
		npmPattern    = `\s*"%s"\s*:\s*"[~^]?%s"`
		dotnetPattern = "include=[\\\"|\\']%s[\\\"|\\']\\s*version=[\\\"|\\']%s[\\\"|\\']"
		simplePattern = `%s:%s`
	)

	testcases := []struct {
		name          string
		packageName   string
		packageVer    string
		formatPattern string
		testContent   string
		shouldMatch   bool
	}{
		// Basic matching
		{
			name:          "basic npm match",
			packageName:   "lodash",
			packageVer:    "4.17.20",
			formatPattern: npmPattern,
			testContent:   `"lodash": "4.17.20"`,
			shouldMatch:   true,
		},
		{
			name:          "npm with caret prefix",
			packageName:   "lodash",
			packageVer:    "4.17.20",
			formatPattern: npmPattern,
			testContent:   `"lodash": "^4.17.20"`,
			shouldMatch:   true,
		},
		{
			name:          "npm with tilde prefix",
			packageName:   "lodash",
			packageVer:    "4.17.20",
			formatPattern: npmPattern,
			testContent:   `"lodash": "~4.17.20"`,
			shouldMatch:   true,
		},
		{
			name:          "npm version mismatch",
			packageName:   "lodash",
			packageVer:    "4.17.20",
			formatPattern: npmPattern,
			testContent:   `"lodash": "4.17.21"`,
			shouldMatch:   false,
		},
		{
			name:          "npm name mismatch",
			packageName:   "lodash",
			packageVer:    "4.17.20",
			formatPattern: npmPattern,
			testContent:   `"underscore": "4.17.20"`,
			shouldMatch:   false,
		},

		// Case insensitivity
		{
			name:          "case insensitive package name",
			packageName:   "PyJWT",
			packageVer:    "2.4.0",
			formatPattern: simplePattern,
			testContent:   `pyjwt:2.4.0`,
			shouldMatch:   true,
		},
		{
			name:          "case insensitive mixed case",
			packageName:   "LODASH",
			packageVer:    "4.17.20",
			formatPattern: npmPattern,
			testContent:   `"lodash": "4.17.20"`,
			shouldMatch:   true,
		},

		// Scoped npm packages with @
		{
			name:          "scoped npm package",
			packageName:   "@types/node",
			packageVer:    "18.0.0",
			formatPattern: npmPattern,
			testContent:   `"@types/node": "18.0.0"`,
			shouldMatch:   true,
		},
		{
			name:          "scoped package with org",
			packageName:   "@angular/core",
			packageVer:    "15.0.0",
			formatPattern: npmPattern,
			testContent:   `"@angular/core": "^15.0.0"`,
			shouldMatch:   true,
		},

		// Regex special characters in package name - should be escaped
		{
			name:          "package name with dot",
			packageName:   "lodash.merge",
			packageVer:    "4.6.2",
			formatPattern: npmPattern,
			testContent:   `"lodash.merge": "4.6.2"`,
			shouldMatch:   true,
		},
		{
			name:          "dot should not match any character",
			packageName:   "lodash.merge",
			packageVer:    "4.6.2",
			formatPattern: npmPattern,
			testContent:   `"lodashXmerge": "4.6.2"`,
			shouldMatch:   false,
		},
		{
			name:          "package name with asterisk",
			packageName:   "test*package",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `test*package:1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "asterisk should not match multiple chars",
			packageName:   "test*package",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `testABCpackage:1.0.0`,
			shouldMatch:   false,
		},
		{
			name:          "package name with question mark",
			packageName:   "test?pkg",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `test?pkg:1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "question mark should not match single char",
			packageName:   "test?pkg",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `testXpkg:1.0.0`,
			shouldMatch:   false,
		},
		{
			name:          "package name with brackets",
			packageName:   "test[pkg]",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `test[pkg]:1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "package name with parentheses",
			packageName:   "test(pkg)",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `test(pkg):1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "package name with curly braces",
			packageName:   "test{pkg}",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `test{pkg}:1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "package name with pipe",
			packageName:   "test|pkg",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `test|pkg:1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "pipe should not match as OR",
			packageName:   "test|pkg",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `test:1.0.0`,
			shouldMatch:   false,
		},
		{
			name:          "package name with caret and dollar",
			packageName:   "^test$",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `^test$:1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "package name with backslash",
			packageName:   `test\pkg`,
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `test\pkg:1.0.0`,
			shouldMatch:   true,
		},

		// Version with special characters
		{
			name:          "version with plus (build metadata)",
			packageName:   "mypackage",
			packageVer:    "1.0.0+build123",
			formatPattern: simplePattern,
			testContent:   `mypackage:1.0.0+build123`,
			shouldMatch:   true,
		},
		{
			name:          "plus in version should not match one-or-more",
			packageName:   "mypackage",
			packageVer:    "1.0.0+",
			formatPattern: simplePattern,
			testContent:   `mypackage:1.0.00000`,
			shouldMatch:   false,
		},
		{
			name:          "version with dots should match literally",
			packageName:   "pkg",
			packageVer:    "1.2.3",
			formatPattern: simplePattern,
			testContent:   `pkg:1.2.3`,
			shouldMatch:   true,
		},
		{
			name:          "dots should not match any char",
			packageName:   "pkg",
			packageVer:    "1.2.3",
			formatPattern: simplePattern,
			testContent:   `pkg:1X2Y3`,
			shouldMatch:   false,
		},

		// Empty name and version edge cases
		{
			name:          "empty package name matches empty",
			packageName:   "",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `:1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "empty version matches empty",
			packageName:   "pkg",
			packageVer:    "",
			formatPattern: simplePattern,
			testContent:   `pkg:`,
			shouldMatch:   true,
		},
		{
			name:          "both empty",
			packageName:   "",
			packageVer:    "",
			formatPattern: simplePattern,
			testContent:   `:`,
			shouldMatch:   true,
		},

		// Complex realistic scenarios
		{
			name:          "dotnet pattern match",
			packageName:   "Newtonsoft.Json",
			packageVer:    "13.0.1",
			formatPattern: dotnetPattern,
			testContent:   `Include="Newtonsoft.Json" Version="13.0.1"`,
			shouldMatch:   true,
		},
		{
			name:          "dotnet single quotes",
			packageName:   "Newtonsoft.Json",
			packageVer:    "13.0.1",
			formatPattern: dotnetPattern,
			testContent:   `Include='Newtonsoft.Json' Version='13.0.1'`,
			shouldMatch:   true,
		},

		// Whitespace handling
		{
			name:          "npm with extra whitespace",
			packageName:   "lodash",
			packageVer:    "4.17.20",
			formatPattern: npmPattern,
			testContent:   `  "lodash"  :  "4.17.20"`,
			shouldMatch:   true,
		},
		{
			name:          "npm with tabs",
			packageName:   "lodash",
			packageVer:    "4.17.20",
			formatPattern: npmPattern,
			testContent:   "\t\"lodash\"\t:\t\"4.17.20\"",
			shouldMatch:   true,
		},

		// Unicode characters (less common but possible)
		{
			name:          "package name with unicode",
			packageName:   "пакет",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `пакет:1.0.0`,
			shouldMatch:   true,
		},

		// Long package names and versions
		{
			name:          "very long package name",
			packageName:   "this-is-a-very-long-package-name-that-might-exist-in-real-world",
			packageVer:    "1.0.0",
			formatPattern: simplePattern,
			testContent:   `this-is-a-very-long-package-name-that-might-exist-in-real-world:1.0.0`,
			shouldMatch:   true,
		},
		{
			name:          "prerelease version",
			packageName:   "pkg",
			packageVer:    "1.0.0-alpha.1",
			formatPattern: simplePattern,
			testContent:   `pkg:1.0.0-alpha.1`,
			shouldMatch:   true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			regex := BuildPackageWithVersionRegex(tc.packageName, tc.packageVer, tc.formatPattern)
			matches := regex.MatchString(strings.ToLower(tc.testContent))
			assert.Equal(t, tc.shouldMatch, matches, "Pattern: %s, Content: %s", regex.String(), tc.testContent)
		})
	}
}

func getUpdateDependencyTestcaseName(technology string, isDirect bool, extraTestInfo string) string {
	testName := technology
	if isDirect {
		testName += "-direct-dep"
	} else {
		testName += "-indirect-dep"
	}
	if extraTestInfo != "" {
		testName += "_(" + extraTestInfo + ")"
	}
	return testName
}

func createFixDetails(technology techutils.Technology, packageName, packageVersion, fixedVersion string, isDirectDependency bool, evidencePaths ...string) *FixDetails {
	var evidences []formats.Location
	for _, path := range evidencePaths {
		if path != "" {
			evidences = append(evidences, formats.Location{File: path})
		}
	}
	return &FixDetails{
		SuggestedFixedVersion:     fixedVersion,
		IsDirectDependency:        isDirectDependency,
		Technology:                technology,
		ImpactedDependencyName:    packageName,
		ImpactedDependencyVersion: packageVersion,
		Components: []formats.ComponentRow{
			{
				Name:      packageName,
				Version:   packageVersion,
				Evidences: evidences,
			},
		},
	}
}

// copyDir is a simple helper to copy a directory tree for tests.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, data, info.Mode())
	})
}

// TestGetCompatiblePackageUpdater verifies the factory routes every supported technology
// to the correct updater type and returns (nil, false) for unsupported ones.
func TestGetCompatiblePackageUpdater(t *testing.T) {
	tests := []struct {
		tech      techutils.Technology
		supported bool
		updater   PackageUpdater
	}{
		{techutils.Npm, true, &NpmPackageUpdater{}},
		{techutils.Pnpm, true, &PnpmPackageUpdater{}},
		{techutils.Maven, true, &MavenPackageUpdater{}},
		{techutils.Go, true, &GoPackageUpdater{}},
		{techutils.Pip, true, &PythonPackageUpdater{}},
		{techutils.Poetry, true, &PythonPackageUpdater{}},
		{techutils.Pipenv, true, &PythonPackageUpdater{}},
		{techutils.Yarn, false, nil},
		{techutils.Gradle, false, nil},
		{techutils.Nuget, false, nil},
		{techutils.Conan, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.tech.String(), func(t *testing.T) {
			updater, supported := GetCompatiblePackageUpdater(&FixDetails{Technology: tt.tech})
			assert.Equal(t, tt.supported, supported)
			if tt.supported {
				assert.IsType(t, tt.updater, updater)
			} else {
				assert.Nil(t, updater)
			}
		})
	}
}
