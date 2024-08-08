package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/stretchr/testify/assert"
)

var (
	summaryExpectedContentDir = filepath.Join("..", "tests", "testdata", "other", "jobSummary")
)

func TestConvertSummaryToString(t *testing.T) {
	wd, err := os.Getwd()
	assert.NoError(t, err)

	testCases := []struct {
		name                string
		summary             SecurityCommandsSummary
		expectedContentPath string
	}{
		{
			name: "One Section - No Issues",
			summary: getDummySecurityCommandsSummary(
				ScanCommandSummaryResult{
					Section:          BinarySection,
					WorkingDirectory: wd,
					Results:          formats.SummaryResults{Scans: []formats.ScanSummaryResult{{Target: filepath.Join(wd, "binary-name")}}},
				},
			),
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "single_no_issue.md"),
		},
		{
			name: "One Section - With Issues",
			summary: getDummySecurityCommandsSummary(
				ScanCommandSummaryResult{
					Section: BuildSection,
					Results: formats.SummaryResults{Scans: []formats.ScanSummaryResult{{
						Target:          "build-name (build-number)",
						Violations:      formats.TwoLevelSummaryCount{formats.ViolationTypeLicense.String(): formats.SummaryCount{"High": 1}},
						Vulnerabilities: &formats.ScanVulnerabilitiesSummary{SecretsScanResults: &formats.SummaryCount{"Low": 1, "High": 2}},
					}}},
				},
			),
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "single_issue.md"),
		},
		{
			name: "Multiple Sections",
			summary: getDummySecurityCommandsSummary(
				ScanCommandSummaryResult{
					Section: BuildSection,
					Results: formats.SummaryResults{Scans: []formats.ScanSummaryResult{{Target: "build-name (build-number)"}}},
				},
				ScanCommandSummaryResult{
					Section: BuildSection,
					Results: formats.SummaryResults{Scans: []formats.ScanSummaryResult{{
						Target: "build-name (build-number)",
						Violations: formats.TwoLevelSummaryCount{
							formats.ViolationTypeSecurity.String():        formats.SummaryCount{"High": 1, "Medium": 1},
							formats.ViolationTypeLicense.String():         formats.SummaryCount{"Medium": 1},
							formats.ViolationTypeOperationalRisk.String(): formats.SummaryCount{"Low": 1},
						},
					}}},
				},
				ScanCommandSummaryResult{
					Section:          BinarySection,
					WorkingDirectory: wd,
					Results: formats.SummaryResults{Scans: []formats.ScanSummaryResult{
						{
							Target: filepath.Join(wd, "binary-name"),
							Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
								SecretsScanResults: &formats.SummaryCount{"Low": 1, "High": 2},
							},
						},
						{
							Target:          filepath.Join("other-root", "dir", "binary-name2"),
							Vulnerabilities: &formats.ScanVulnerabilitiesSummary{},
						},
					}},
				},
				ScanCommandSummaryResult{
					Section:          ModulesSection,
					WorkingDirectory: wd,
					Results: formats.SummaryResults{Scans: []formats.ScanSummaryResult{
						{
							Target: filepath.Join(wd, "application1"),
							Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
								SastScanResults: &formats.SummaryCount{"Low": 1},
								IacScanResults:  &formats.SummaryCount{"Medium": 5},
								ScaScanResults: &formats.ScanScaResult{
									SummaryCount: formats.TwoLevelSummaryCount{
										"Critical": formats.SummaryCount{"Undetermined": 1, "Not Applicable": 2},
										"High":     formats.SummaryCount{"Applicable": 1, "Not Applicable": 1, "Not Covered": 2},
										"Low":      formats.SummaryCount{"Undetermined": 1},
									},
									UniqueFindings: 6,
								},
							},
						},
						{
							Target:     filepath.Join(wd, "application2"),
							Violations: formats.TwoLevelSummaryCount{formats.ViolationTypeSecurity.String(): formats.SummaryCount{"High": 1}},
							Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
								ScaScanResults: &formats.ScanScaResult{
									SummaryCount:   formats.TwoLevelSummaryCount{"High": formats.SummaryCount{"Not Applicable": 1}},
									UniqueFindings: 1,
								},
							},
						},
						{
							Target: filepath.Join(wd, "dir", "application3"),
						},
					}},
				},
				ScanCommandSummaryResult{
					Section:          CurationSection,
					WorkingDirectory: wd,
					Results: formats.SummaryResults{Scans: []formats.ScanSummaryResult{
						{
							Target: filepath.Join(wd, "application1"),
							CuratedPackages: &formats.CuratedPackages{
								Blocked: formats.TwoLevelSummaryCount{
									"Policy: Malicious, Condition: Malicious package":          formats.SummaryCount{"npm://lodash:1.0.0": 1},
									"Policy: cvss_score, Condition:cvss score higher than 4.0": formats.SummaryCount{"npm://underscore:1.0.0": 1},
								},
								Approved: 4,
							},
						},
						{
							Target: filepath.Join(wd, "application2"),
							CuratedPackages: &formats.CuratedPackages{
								Blocked: formats.TwoLevelSummaryCount{
									"Policy: License, Condition: GPL":          formats.SummaryCount{"npm://test:1.0.0": 1},
									"Policy: Aged, Condition: Package is aged": formats.SummaryCount{"npm://test2:1.0.0": 1},
								},
								Approved: 4,
							},
						},
					},
					},
				},
			),
			expectedContentPath: filepath.Join(summaryExpectedContentDir, "multi_command_job.md"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Read expected content from file
			expectedContent := getOutputFromFile(t, testCase.expectedContentPath)
			summary, err := ConvertSummaryToString(testCase.summary)
			assert.NoError(t, err)
			assert.Equal(t, expectedContent, summary)
		})
	}
}

func getOutputFromFile(t *testing.T, path string) string {
	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(content), "\r\n", "\n"), "/", string(filepath.Separator)), "<"+string(filepath.Separator), "</")
}

func getDummySecurityCommandsSummary(cmdResults ...ScanCommandSummaryResult) SecurityCommandsSummary {
	summary := SecurityCommandsSummary{
		BuildScanCommands: []formats.SummaryResults{},
		ScanCommands:      []formats.SummaryResults{},
		AuditCommands:     []formats.SummaryResults{},
	}
	for _, cmdResult := range cmdResults {
		results := cmdResult.Results
		// Update the working directory
		updateSummaryNamesToRelativePath(&results, cmdResult.WorkingDirectory)
		switch cmdResult.Section {
		case BuildSection:
			summary.BuildScanCommands = append(summary.BuildScanCommands, cmdResult.Results)
		case BinarySection:
			summary.ScanCommands = append(summary.ScanCommands, cmdResult.Results)
		case ModulesSection:
			summary.AuditCommands = append(summary.AuditCommands, cmdResult.Results)
		case CurationSection:
			summary.CurationCommands = append(summary.CurationCommands, cmdResult.Results)
		}
	}
	return summary
}
