package summaryformat

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/stretchr/testify/assert"
)

func TestGetCveIds(t *testing.T) {
	testCases := []struct {
		name     string
		cves     []formats.CveRow
		issueId  string
		expected []string
	}{
		{
			name:     "No cves",
			cves:     []formats.CveRow{},
			issueId:  "issueId",
			expected: []string{"issueId"},
		},
		{
			name:     "One cve",
			cves:     []formats.CveRow{{Id: "CVE-1"}},
			issueId:  "issueId",
			expected: []string{"CVE-1"},
		},
		{
			name:     "Multiple cves",
			cves:     []formats.CveRow{{Id: "CVE-1"}, {Id: "CVE-2"}},
			issueId:  "issueId",
			expected: []string{"CVE-1", "CVE-2"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := getCveIds(testCase.cves, testCase.issueId)
			assert.Equal(t, testCase.expected, result)
		})
	}
}

// func TestGetSummary(t *testing.T) {
// 	dummyExtendedScanResults := &ExtendedScanResults{
// 		ApplicabilityScanResults: []*sarif.Run{
// 			sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyPassingResult("applic_CVE-2")).WithInvocations([]*sarif.Invocation{
// 				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
// 			}),
// 		},
// 		SecretsScanResults: []*sarif.Run{
// 			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target1/file", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
// 				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
// 			}),
// 			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target2/file", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
// 				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target2")),
// 			}),
// 		},
// 		SastScanResults: []*sarif.Run{
// 			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target1/file2", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
// 				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
// 			}),
// 		},
// 	}

// 	testCases := []struct {
// 		name         string
// 		cmdResults   results.ScanCommandResults
// 		expected     formats.SummaryResults
// 		findingCount int
// 		issueCount   int
// 	}{
// 		{
// 			name:         "Empty results",
// 			cmdResults:   results.ScanCommandResults{ScaResults: []ScaScanResult{}},
// 			expected:     formats.SummaryResults{Scans: []formats.ScanSummaryResult{{}}},
// 			findingCount: 0,
// 			issueCount:   0,
// 		},
// 		{
// 			name: "One module result",
// 			cmdResults: results.ScanCommandResults{
// 				ScaResults: []ScaScanResult{{
// 					Target:      "target1",
// 					XrayResults: getDummyScaTestResults(true, false),
// 				}},
// 				ExtendedScanResults: dummyExtendedScanResults,
// 			},
// 			expected: formats.SummaryResults{
// 				Scans: []formats.ScanSummaryResult{
// 					{
// 						Target: "target1",
// 						Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
// 							ScaScanResults: &formats.ScanScaResult{
// 								SummaryCount: formats.TwoLevelSummaryCount{
// 									"Critical": formats.SummaryCount{"Undetermined": 1},
// 									"High":     formats.SummaryCount{"Not Applicable": 1},
// 								},
// 								UniqueFindings: 2,
// 							},
// 							SecretsScanResults: &formats.SummaryCount{"Low": 2},
// 							SastScanResults:    &formats.SummaryCount{"Low": 1},
// 						},
// 						Violations: formats.TwoLevelSummaryCount{},
// 					},
// 				},
// 			},
// 			findingCount: 5,
// 			issueCount:   5,
// 		},
// 		{
// 			name: "Multiple module results",
// 			cmdResults: results.ScanCommandResults{
// 				ScaResults: []ScaScanResult{
// 					{
// 						Target:      "target1",
// 						XrayResults: getDummyScaTestResults(false, true),
// 					},
// 					{
// 						Target:      "target2",
// 						XrayResults: getDummyScaTestResults(true, true),
// 					},
// 				},
// 				ExtendedScanResults: dummyExtendedScanResults,
// 			},
// 			expected: formats.SummaryResults{
// 				Scans: []formats.ScanSummaryResult{
// 					{
// 						Target: "target1",
// 						Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
// 							ScaScanResults:     &formats.ScanScaResult{SummaryCount: formats.TwoLevelSummaryCount{}},
// 							SecretsScanResults: &formats.SummaryCount{"Low": 1},
// 							SastScanResults:    &formats.SummaryCount{"Low": 1},
// 						},
// 						Violations: formats.TwoLevelSummaryCount{
// 							formats.ViolationTypeSecurity.String(): formats.SummaryCount{"Critical": 1, "High": 1},
// 							formats.ViolationTypeLicense.String():  formats.SummaryCount{"High": 1},
// 						},
// 					},
// 					{
// 						Target: "target2",
// 						Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
// 							ScaScanResults: &formats.ScanScaResult{
// 								SummaryCount:   formats.TwoLevelSummaryCount{"Critical": formats.SummaryCount{"": 1}},
// 								UniqueFindings: 1,
// 							},
// 							SecretsScanResults: &formats.SummaryCount{"Low": 1},
// 						},
// 						Violations: formats.TwoLevelSummaryCount{formats.ViolationTypeSecurity.String(): formats.SummaryCount{"High": 1}},
// 					},
// 				},
// 			},
// 			findingCount: 7,
// 			issueCount:   8,
// 		},
// 	}
// 	for _, testCase := range testCases {
// 		t.Run(testCase.name, func(t *testing.T) {
// 			result := testCase.cmdResults.GetSummary()
// 			assert.Equal(t, testCase.expected, result)
// 			assert.Equal(t, testCase.findingCount, testCase.cmdResults.CountScanResultsFindings())
// 			assert.Equal(t, testCase.issueCount, testCase.cmdResults.GetSummary().GetTotalIssueCount())
// 		})
// 	}
// }
