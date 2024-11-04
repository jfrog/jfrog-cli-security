package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils/commandsummary"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	coreUtils "github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/stretchr/testify/assert"
)

var (
	summaryExpectedContentDir = filepath.Join("..", "..", "..", "tests", "testdata", "output", "jobSummary")

	securityScaResults = formats.ResultSummary{
		"Critical": map[string]int{jasutils.Applicable.String(): 2, jasutils.NotApplicable.String(): 2, jasutils.NotCovered.String(): 3, jasutils.ApplicabilityUndetermined.String(): 1},
		"High":     map[string]int{jasutils.Applicable.String(): 2, jasutils.ApplicabilityUndetermined.String(): 3},
		"Low":      map[string]int{jasutils.NotApplicable.String(): 3},
		"Unknown":  map[string]int{jasutils.NotCovered.String(): 1},
	}
	violationResults = formats.ScanResultSummary{
		ScaResults: &formats.ScaScanResultSummary{
			ScanIds:         []string{validations.TestScaScanId},
			MoreInfoUrls:    []string{validations.TestMoreInfoUrl},
			Security:        securityScaResults,
			License:         formats.ResultSummary{"High": map[string]int{formats.NoStatus: 1}},
			OperationalRisk: formats.ResultSummary{"Low": map[string]int{formats.NoStatus: 2}},
		},
		SecretsResults: &formats.ResultSummary{"Medium": map[string]int{formats.NoStatus: 3}},
	}
)

func TestSaveSarifOutputOnlyForJasEntitled(t *testing.T) {
	testCases := []struct {
		name          string
		isJasEntitled bool
	}{
		{
			name:          "JAS not entitled",
			isJasEntitled: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tempDir, cleanUpDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
			defer cleanUpDir()
			cleanUp := clientTests.SetEnvWithCallbackAndAssert(t, coreUtils.SummaryOutputDirPathEnv, tempDir)
			defer cleanUp()

			assert.NoError(t, RecordSarifOutput(createDummyJasResult(testCase.isJasEntitled), &config.ServerDetails{Url: "https://url.com"}, true, true, utils.GetAllSupportedScans()...))
			assert.Equal(t, testCase.isJasEntitled, hasFilesInDir(t, filepath.Join(tempDir, commandsummary.OutputDirName, "security", string(commandsummary.SarifReport))))
		})
	}
}

func createDummyJasResult(entitled bool) *results.SecurityCommandResults {
	return &results.SecurityCommandResults{EntitledForJas: entitled}
}

func hasFilesInDir(t *testing.T, dir string) bool {
	exists, err := fileutils.IsDirExists(dir, false)
	assert.NoError(t, err)
	if !exists {
		return false
	}
	files, err := os.ReadDir(dir)
	assert.NoError(t, err)
	return len(files) > 0
}

func TestSaveLoadData(t *testing.T) {
	testDockerScanSummary := ScanCommandResultSummary{
		ResultType: utils.DockerImage,
		Args: &ResultSummaryArgs{
			BaseJfrogUrl: validations.TestPlatformUrl,
			DockerImage:  "dockerImage:version",
		},
		Summary: formats.ResultsSummary{
			Scans: []formats.ScanSummary{
				{
					Target: filepath.Join("path", "to", "image.tar"),
					Vulnerabilities: &formats.ScanResultSummary{
						ScaResults: &formats.ScaScanResultSummary{
							ScanIds:      []string{validations.TestScaScanId},
							MoreInfoUrls: []string{validations.TestMoreInfoUrl},
							Security:     securityScaResults,
						},
					},
					Violations: &formats.ScanViolationsSummary{
						Watches:           []string{"watch1"},
						ScanResultSummary: violationResults,
					},
				},
			},
		},
	}
	testBinaryScanSummary := ScanCommandResultSummary{
		ResultType: utils.Binary,
		Args: &ResultSummaryArgs{
			BaseJfrogUrl: validations.TestPlatformUrl,
		},
		Summary: formats.ResultsSummary{
			Scans: []formats.ScanSummary{
				{
					Target: filepath.Join("path", "to", "binary"),
					Vulnerabilities: &formats.ScanResultSummary{
						ScaResults: &formats.ScaScanResultSummary{
							ScanIds:  []string{"scan-id-1"},
							Security: formats.ResultSummary{"Critical": map[string]int{formats.NoStatus: 33}, "Low": map[string]int{formats.NoStatus: 11}},
						},
					},
				},
				{
					Target: filepath.Join("path", "to", "binary2"),
					Vulnerabilities: &formats.ScanResultSummary{
						ScaResults: &formats.ScaScanResultSummary{
							ScanIds: []string{"scan-id-2"},
						},
					},
				},
			},
		},
	}
	testBuildScanSummary := ScanCommandResultSummary{
		ResultType: utils.Build,
		Args: &ResultSummaryArgs{
			BaseJfrogUrl: validations.TestPlatformUrl,
			BuildName:    "build-name",
			BuildNumbers: []string{"build-number"},
		},
		Summary: formats.ResultsSummary{
			Scans: []formats.ScanSummary{
				{
					Target: "build-name (build-number)",
					Violations: &formats.ScanViolationsSummary{
						Watches:           []string{"watch"},
						ScanResultSummary: violationResults,
					},
				},
			},
		},
	}
	testCurationSummary := ScanCommandResultSummary{
		ResultType: utils.Curation,
		Summary: formats.ResultsSummary{
			Scans: []formats.ScanSummary{
				{
					Target: filepath.Join("path", "to", "application"),
					CuratedPackages: &formats.CuratedPackages{
						PackageCount: 6,
						Blocked: []formats.BlockedPackages{
							{
								Policy:    "Malicious",
								Condition: "Malicious package",
								Packages:  map[string]int{"npm://lodash:1.0.0": 1},
							},
						},
					},
				},
			},
		},
	}

	testCases := []struct {
		name            string
		content         []ScanCommandResultSummary
		filterSections  []utils.CommandType
		expectedArgs    ResultSummaryArgs
		expectedContent []formats.ResultsSummary
	}{
		{
			name:            "Single scan",
			content:         []ScanCommandResultSummary{testDockerScanSummary},
			expectedArgs:    *testDockerScanSummary.Args,
			expectedContent: []formats.ResultsSummary{testDockerScanSummary.Summary},
		},
		{
			name:    "Multiple scans",
			content: []ScanCommandResultSummary{testDockerScanSummary, testBinaryScanSummary, testBuildScanSummary},
			expectedArgs: ResultSummaryArgs{
				BaseJfrogUrl: validations.TestPlatformUrl,
				DockerImage:  "dockerImage:version",
				BuildName:    "build-name",
				BuildNumbers: []string{"build-number"},
			},
			expectedContent: []formats.ResultsSummary{testDockerScanSummary.Summary, testBinaryScanSummary.Summary, testBuildScanSummary.Summary},
		},
		{
			name:            "Multiple scans with filter",
			filterSections:  []utils.CommandType{utils.Curation},
			content:         []ScanCommandResultSummary{testDockerScanSummary, testBinaryScanSummary, testBuildScanSummary, testCurationSummary},
			expectedContent: []formats.ResultsSummary{testCurationSummary.Summary},
		},
	}
	tempDir, cleanUp := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUp()
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dataFilePaths := []string{}
			// Save the data
			for i := range testCase.content {
				updateSummaryNamesToRelativePath(&testCase.content[i].Summary, tempDir)
				data, err := utils.GetAsJsonBytes(&testCase.content[i], false, false)
				assert.NoError(t, err)
				dataFilePath := filepath.Join(tempDir, fmt.Sprintf("data_%s_%d.json", testCase.name, i))
				assert.NoError(t, os.WriteFile(dataFilePath, data, 0644))
				dataFilePaths = append(dataFilePaths, dataFilePath)
			}
			// Load the data
			loadedData, loadedArgs, err := loadContent(dataFilePaths, testCase.filterSections...)
			assert.NoError(t, err)
			assert.ElementsMatch(t, testCase.expectedContent, loadedData)
			assert.Equal(t, testCase.expectedArgs, loadedArgs)
		})
	}
}

func TestGenerateJobSummaryMarkdown(t *testing.T) {
	wd, err := os.Getwd()
	assert.NoError(t, err)
	testCases := []struct {
		name                string
		index               commandsummary.Index
		args                *ResultSummaryArgs
		violations          bool
		content             []formats.ResultsSummary
		NoExtendedView      bool
		expectedContentPath string
	}{
		{
			name:                "Security Section (Curation)",
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "security_section.md"),
			content: []formats.ResultsSummary{
				{
					Scans: []formats.ScanSummary{
						{
							Target: filepath.Join(wd, "application1"),
							CuratedPackages: &formats.CuratedPackages{
								PackageCount: 6,
								Blocked: []formats.BlockedPackages{
									{
										Policy:    "Malicious",
										Condition: "Malicious package",
										Packages:  map[string]int{"npm://lodash:1.0.0": 1},
									},
									{
										Policy:    "cvss_score",
										Condition: "cvss score higher than 4.0",
										Packages:  map[string]int{"npm://underscore:1.0.0": 1, "npm://test:2.0.0": 1},
									},
								},
							},
						},
						{
							Target:          filepath.Join(wd, "application2"),
							CuratedPackages: &formats.CuratedPackages{PackageCount: 3},
						},
					},
				},
				{
					Scans: []formats.ScanSummary{{
						Target: filepath.Join(wd, "application3"),
						CuratedPackages: &formats.CuratedPackages{
							PackageCount: 5,
							Blocked: []formats.BlockedPackages{{
								Policy:    "Aged",
								Condition: "Package is aged",
								Packages:  map[string]int{"npm://test:1.0.0": 1},
							}},
						},
					}},
				},
			},
		},
		{
			name:                "No vulnerabilities",
			index:               commandsummary.BinariesScan,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "no_vulnerabilities.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target:          filepath.Join(wd, "binary-name"),
					Vulnerabilities: &formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{ScanIds: []string{validations.TestScaScanId}, MoreInfoUrls: []string{validations.TestMoreInfoUrl}}},
				}},
			}},
		},
		{
			name:                "Violations - Not defined",
			index:               commandsummary.BinariesScan,
			violations:          true,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "violations_not_defined.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target:          filepath.Join(wd, "binary-name"),
					Vulnerabilities: &formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{ScanIds: []string{validations.TestScaScanId}}},
				}},
			}},
		},
		{
			name:                "No violations",
			index:               commandsummary.BinariesScan,
			violations:          true,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "no_violations.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "other-binary-name"),
					Violations: &formats.ScanViolationsSummary{
						Watches:           []string{},
						ScanResultSummary: formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{ScanIds: []string{validations.TestScaScanId}, MoreInfoUrls: []string{validations.TestMoreInfoUrl}}},
					},
				}},
			}},
		},
		{
			name:                "Build Scan Vulnerabilities",
			index:               commandsummary.BuildScan,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "build_scan_vulnerabilities.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl, BuildName: "build-name", BuildNumbers: []string{"build-number"}},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: "build-name (build-number)",
					Vulnerabilities: &formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{
						ScanIds:      []string{validations.TestScaScanId},
						MoreInfoUrls: []string{validations.TestMoreInfoUrl},
						Security:     formats.ResultSummary{"High": map[string]int{formats.NoStatus: 3}, "Medium": map[string]int{formats.NoStatus: 1}, "Unknown": map[string]int{formats.NoStatus: 20}},
					}},
				}},
			}},
		},
		{
			name:                "Binary Scan Vulnerabilities",
			index:               commandsummary.BinariesScan,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "binary_vulnerabilities.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "binary-with-issues"),
					Vulnerabilities: &formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{
						ScanIds:      []string{validations.TestScaScanId, "scan-id-2"},
						MoreInfoUrls: []string{""},
						Security:     formats.ResultSummary{"Critical": map[string]int{formats.NoStatus: 33}, "Low": map[string]int{formats.NoStatus: 11}},
					}},
				}},
			}},
		},
		{
			name:                "Docker Scan Vulnerabilities",
			index:               commandsummary.DockerScan,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "docker_vulnerabilities.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl, DockerImage: "dockerImage:version"},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "image.tar"),
					Vulnerabilities: &formats.ScanResultSummary{
						ScaResults: &formats.ScaScanResultSummary{
							ScanIds:      []string{validations.TestScaScanId},
							MoreInfoUrls: []string{""},
							Security:     securityScaResults,
						},
						SecretsResults: &formats.ResultSummary{
							"Medium": map[string]int{formats.NoStatus: 3},
						},
					},
				}},
			}},
		},
		{
			name:                "Violations",
			index:               commandsummary.DockerScan,
			violations:          true,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "violations.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl, DockerImage: "dockerImage:version"},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "image.tar"),
					Violations: &formats.ScanViolationsSummary{
						Watches:           []string{"watch1", "watch2", "watch3", "watch4", "watch5"},
						ScanResultSummary: violationResults,
					},
				}},
			}},
		},
		{
			name:                "Violations - Not extendedView",
			index:               commandsummary.DockerScan,
			violations:          true,
			NoExtendedView:      true,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "violations_not_extended_view.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl, DockerImage: "dockerImage:version"},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "image.tar"),
					Violations: &formats.ScanViolationsSummary{
						Watches:           []string{"watch1"},
						ScanResultSummary: violationResults,
					},
				}},
			}},
		},
		{
			name:  "Vulnerability not requested",
			index: commandsummary.DockerScan,
			args:  &ResultSummaryArgs{BaseJfrogUrl: validations.TestPlatformUrl, DockerImage: "dockerImage:version"},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "image.tar"),
				}},
			}},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Read expected content from file (or empty string expected if no file is provided)
			expectedContent := ""
			if testCase.expectedContentPath != "" {
				expectedContent = getOutputFromFile(t, testCase.expectedContentPath)
			}
			for i := range testCase.content {
				updateSummaryNamesToRelativePath(&testCase.content[i], wd)
			}
			var summary string
			var err error
			// Generate the summary
			if testCase.index == "" {
				summary, err = GenerateSecuritySectionMarkdown(testCase.content)
				// Replace all backslashes with forward slashes for Windows compatibility in tests
				summary = strings.ReplaceAll(summary, string(filepath.Separator), "/")
			} else {
				assert.NotNil(t, testCase.args)
				summary, err = createDummyDynamicMarkdown(testCase.content, testCase.index, *testCase.args, testCase.violations, !testCase.NoExtendedView)
			}
			assert.NoError(t, err)
			assert.Equal(t, expectedContent, summary)
		})
	}
}

func createDummyDynamicMarkdown(content []formats.ResultsSummary, index commandsummary.Index, args ResultSummaryArgs, violations, extendedView bool) (markdown string, err error) {
	securityJobSummary := &SecurityJobSummary{}
	var generator DynamicMarkdownGenerator
	switch index {
	case commandsummary.BuildScan:
		generator, err = securityJobSummary.BuildScan([]string{})
	case commandsummary.DockerScan:
		generator, err = securityJobSummary.DockerScan([]string{})
	case commandsummary.BinariesScan:
		generator, err = securityJobSummary.BinaryScan([]string{})
	}
	if err != nil {
		return
	}
	generator.extendedView = extendedView
	generator.args = args
	generator.content = content
	if violations {
		markdown = generator.GetViolations()
	} else {
		markdown = generator.GetVulnerabilities()
	}
	return
}

func getOutputFromFile(t *testing.T, path string) string {
	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	return strings.ReplaceAll(string(content), "\r\n", "\n")
}
