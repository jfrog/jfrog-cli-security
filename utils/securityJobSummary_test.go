package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
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
					Section:          Binary,
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
					Section: Build,
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
					Section: Build,
					Results: formats.SummaryResults{Scans: []formats.ScanSummaryResult{{Target: "build-name (build-number)"}}},
				},
				ScanCommandSummaryResult{
					Section: Build,
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
					Section:          Binary,
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
					Section:          Modules,
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
		case Build:
			summary.BuildScanCommands = append(summary.BuildScanCommands, cmdResult.Results)
		case Binary:
			summary.ScanCommands = append(summary.ScanCommands, cmdResult.Results)
		case Modules:
			summary.AuditCommands = append(summary.AuditCommands, cmdResult.Results)
		}
	}
	return summary
}
