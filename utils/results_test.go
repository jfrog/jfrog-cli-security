package utils

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

func TestGetScaScanResultByTarget(t *testing.T) {
	target1 := &ScaScanResult{Target: "target1"}
	target2 := &ScaScanResult{Target: "target2"}
	testCases := []struct {
		name     string
		results  Results
		target   string
		expected *ScaScanResult
	}{
		{
			name: "Sca scan result by target",
			results: Results{
				ScaResults: []*ScaScanResult{
					target1,
					target2,
				},
			},
			target:   "target1",
			expected: target1,
		},
		{
			name: "Sca scan result by target not found",
			results: Results{
				ScaResults: []*ScaScanResult{
					target1,
					target2,
				},
			},
			target:   "target3",
			expected: nil,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.results.getScaScanResultByTarget(testCase.target)
			assert.Equal(t, testCase.expected, result)
		})
	}
}

func TestGetSummary(t *testing.T) {
	dummyExtendedScanResults := &ExtendedScanResults{
		ApplicabilityScanResults: []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyPassingResult("applic_CVE-2")).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
		},
		SecretsScanResults: []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target1/file", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target2/file", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target2")),
			}),
		},
		SastScanResults: []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target1/file2", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
		},
	}

	testCases := []struct {
		name         string
		results      Results
		expected     formats.SummaryResults
		findingCount int
		issueCount   int
	}{
		{
			name:         "Empty results",
			results:      Results{ScaResults: []*ScaScanResult{}},
			expected:     formats.SummaryResults{Scans: []formats.ScanSummaryResult{{}}},
			findingCount: 0,
			issueCount:   0,
		},
		{
			name: "One module result",
			results: Results{
				ScaResults: []*ScaScanResult{{
					Target:      "target1",
					XrayResults: getDummyScaTestResults(true, false),
				}},
				ExtendedScanResults: dummyExtendedScanResults,
			},
			expected: formats.SummaryResults{
				Scans: []formats.ScanSummaryResult{
					{
						Target: "target1",
						Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
							ScaScanResults: &formats.ScanScaResult{
								SummaryCount: formats.TwoLevelSummaryCount{
									"Critical": formats.SummaryCount{"Undetermined": 1},
									"High":     formats.SummaryCount{"Not Applicable": 1},
								},
								UniqueFindings: 2,
							},
							SecretsScanResults: &formats.SummaryCount{"Low": 2},
							SastScanResults:    &formats.SummaryCount{"Low": 1},
						},
						Violations: formats.TwoLevelSummaryCount{},
					},
				},
			},
			findingCount: 5,
			issueCount:   5,
		},
		{
			name: "Multiple module results",
			results: Results{
				ScaResults: []*ScaScanResult{
					{
						Target:      "target1",
						XrayResults: getDummyScaTestResults(false, true),
					},
					{
						Target:      "target2",
						XrayResults: getDummyScaTestResults(true, true),
					},
				},
				ExtendedScanResults: dummyExtendedScanResults,
			},
			expected: formats.SummaryResults{
				Scans: []formats.ScanSummaryResult{
					{
						Target: "target1",
						Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
							ScaScanResults:     &formats.ScanScaResult{SummaryCount: formats.TwoLevelSummaryCount{}},
							SecretsScanResults: &formats.SummaryCount{"Low": 1},
							SastScanResults:    &formats.SummaryCount{"Low": 1},
						},
						Violations: formats.TwoLevelSummaryCount{
							formats.ViolationTypeSecurity.String(): formats.SummaryCount{"Critical": 1, "High": 1},
							formats.ViolationTypeLicense.String():  formats.SummaryCount{"High": 1},
						},
					},
					{
						Target: "target2",
						Vulnerabilities: &formats.ScanVulnerabilitiesSummary{
							ScaScanResults: &formats.ScanScaResult{
								SummaryCount:   formats.TwoLevelSummaryCount{"Critical": formats.SummaryCount{"": 1}},
								UniqueFindings: 1,
							},
							SecretsScanResults: &formats.SummaryCount{"Low": 1},
						},
						Violations: formats.TwoLevelSummaryCount{formats.ViolationTypeSecurity.String(): formats.SummaryCount{"High": 1}},
					},
				},
			},
			findingCount: 7,
			issueCount:   8,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.results.GetSummary()
			assert.Equal(t, testCase.expected, result)
			assert.Equal(t, testCase.findingCount, testCase.results.CountScanResultsFindings())
			assert.Equal(t, testCase.issueCount, testCase.results.GetSummary().GetTotalIssueCount())
		})
	}
}

func getDummyScaTestResults(vulnerability, violation bool) (responses []services.ScanResponse) {
	response := services.ScanResponse{}
	switch {
	case vulnerability && violation:
		// Mix
		response.Vulnerabilities = []services.Vulnerability{
			{IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
		response.Violations = []services.Violation{
			{ViolationType: formats.ViolationTypeSecurity.String(), WatchName: "test-watch-name", IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
	case vulnerability:
		// only vulnerability
		response.Vulnerabilities = []services.Vulnerability{
			{IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
	case violation:
		// only violation
		response.Violations = []services.Violation{
			{ViolationType: formats.ViolationTypeSecurity.String(), WatchName: "test-watch-name", IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{ViolationType: formats.ViolationTypeSecurity.String(), WatchName: "test-watch-name", IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{ViolationType: formats.ViolationTypeLicense.String(), WatchName: "test-watch-name", IssueId: "MIT", Severity: "High", LicenseKey: "MIT", Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
	}
	responses = append(responses, response)
	return
}
