package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils/commandsummary"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/stretchr/testify/assert"
)

var (
	summaryExpectedContentDir = filepath.Join("..", "tests", "testdata", "other", "jobSummary")
)

func TestGenerateJobSummaryMarkdown(t *testing.T) {
	wd, err := os.Getwd()
	assert.NoError(t, err)
	testPlatformUrl := "https://test-platform-url/"
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
			args:                &ResultSummaryArgs{BaseJfrogUrl: testPlatformUrl},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target:          filepath.Join(wd, "binary-name"),
					Vulnerabilities: &formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{ScanIds: []string{TestScaScanId}, MoreInfoUrls: []string{"https://test-url"}}},
				}},
			}},
		},
		{
			name:                "Violations - Not defined",
			index:               commandsummary.BinariesScan,
			violations:          true,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "violations_not_defined.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: testPlatformUrl},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target:          filepath.Join(wd, "binary-name"),
					Vulnerabilities: &formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{ScanIds: []string{TestScaScanId}}},
				}},
			}},
		},
		{
			name:                "No violations",
			index:               commandsummary.BinariesScan,
			violations:          true,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "no_violations.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: testPlatformUrl},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "other-binary-name"),
					Violations: &formats.ScanViolationsSummary{
						Watches:           []string{},
						ScanResultSummary: formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{ScanIds: []string{TestScaScanId}, MoreInfoUrls: []string{"https://test-url"}}},
					},
				}},
			}},
		},
		{
			name:                "Build Scan Vulnerabilities",
			index:               commandsummary.BuildScan,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "build_scan_vulnerabilities.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: testPlatformUrl, BuildName: "build-name", BuildNumbers: []string{"build-number"}},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: "build-name (build-number)",
					Vulnerabilities: &formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{
						ScanIds:      []string{TestScaScanId},
						MoreInfoUrls: []string{"https://test-url"},
						Security:     formats.ResultSummary{"High": map[string]int{formats.NoStatus: 3}, "Medium": map[string]int{formats.NoStatus: 1}, "Unknown": map[string]int{formats.NoStatus: 20}},
					}},
				}},
			}},
		},
		{
			name:                "Binary Scan Vulnerabilities",
			index:               commandsummary.BinariesScan,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "binary_vulnerabilities.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: testPlatformUrl},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "binary-with-issues"),
					Vulnerabilities: &formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{
						ScanIds:  []string{TestScaScanId, "scan-id-2"},
						Security: formats.ResultSummary{"Critical": map[string]int{formats.NoStatus: 33}, "Low": map[string]int{formats.NoStatus: 11}},
					}},
				}},
			}},
		},
		{
			name:                "Docker Scan Vulnerabilities",
			index:               commandsummary.DockerScan,
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "docker_vulnerabilities.md"),
			args:                &ResultSummaryArgs{BaseJfrogUrl: testPlatformUrl, DockerImage: "dockerImage:version"},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "image.tar"),
					Vulnerabilities: &formats.ScanResultSummary{
						ScaResults: &formats.ScaScanResultSummary{
							ScanIds: []string{TestScaScanId},
							Security: formats.ResultSummary{
								"Critical": map[string]int{jasutils.Applicable.String(): 2, jasutils.NotApplicable.String(): 2, jasutils.NotCovered.String(): 3, jasutils.ApplicabilityUndetermined.String(): 1},
								"High":     map[string]int{jasutils.Applicable.String(): 2, jasutils.ApplicabilityUndetermined.String(): 3},
								"Low":      map[string]int{jasutils.NotApplicable.String(): 3},
								"Unknown":  map[string]int{jasutils.NotCovered.String(): 1},
							},
						},
						SecretsResults: &formats.ResultSummary{
							"Medium": map[string]int{formats.NoStatus: 3},
						},
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
			args:                &ResultSummaryArgs{BaseJfrogUrl: testPlatformUrl, DockerImage: "dockerImage:version"},
			content: []formats.ResultsSummary{{
				Scans: []formats.ScanSummary{{
					Target: filepath.Join(wd, "image.tar"),
					Violations: &formats.ScanViolationsSummary{
						Watches: []string{"watch1"},
						ScanResultSummary: formats.ScanResultSummary{
							ScaResults: &formats.ScaScanResultSummary{
								ScanIds:      []string{TestScaScanId},
								MoreInfoUrls: []string{"https://test-url"},
								Security: formats.ResultSummary{
									"Critical": map[string]int{jasutils.Applicable.String(): 2, jasutils.NotApplicable.String(): 2, jasutils.NotCovered.String(): 3, jasutils.ApplicabilityUndetermined.String(): 1},
									"High":     map[string]int{jasutils.Applicable.String(): 2, jasutils.ApplicabilityUndetermined.String(): 3},
									"Low":      map[string]int{jasutils.NotApplicable.String(): 3},
									"Unknown":  map[string]int{jasutils.NotCovered.String(): 1},
								},
								License:         formats.ResultSummary{"High": map[string]int{formats.NoStatus: 1}},
								OperationalRisk: formats.ResultSummary{"Low": map[string]int{formats.NoStatus: 2}},
							},
							SecretsResults: &formats.ResultSummary{"Medium": map[string]int{formats.NoStatus: 3}},
						},
					},
				}},
			}},
		},
		{
			name:  "Vulnerability not requested",
			index: commandsummary.DockerScan,
			args:  &ResultSummaryArgs{BaseJfrogUrl: testPlatformUrl, DockerImage: "dockerImage:version"},
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
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(content), "\r\n", "\n"), "/", string(filepath.Separator)), "<"+string(filepath.Separator), "</")
}
