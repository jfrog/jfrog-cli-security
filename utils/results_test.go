package utils

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/formats"
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
				ScaResults: []ScaScanResult{
					*target1,
					*target2,
				},
			},
			target:   "target1",
			expected: target1,
		},
		{
			name: "Sca scan result by target not found",
			results: Results{
				ScaResults: []ScaScanResult{
					*target1,
					*target2,
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
	dummyScaVulnerabilities := []services.Vulnerability{
		{IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		{IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
	}
	dummyExtendedScanResults := &ExtendedScanResults{
		ApplicabilityScanResults: []*sarif.Run{
			CreateRunWithDummyResults(CreateDummyPassingResult("applic_CVE-2")).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
		},
		SecretsScanResults: []*sarif.Run{
			CreateRunWithDummyResults(CreateResultWithLocations("", "", "note", CreateLocation("target1/file", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
			CreateRunWithDummyResults(CreateResultWithLocations("", "", "note", CreateLocation("target2/file", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target2")),
			}),
		},
		SastScanResults: []*sarif.Run{
			CreateRunWithDummyResults(CreateResultWithLocations("", "", "note", CreateLocation("target1/file2", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
		},
	}

	testCases := []struct {
		name         string
		results      Results
		expected     formats.SummaryResults
		findingCount int
	}{
		{
			name:         "Empty results",
			results:      Results{ScaResults: []ScaScanResult{}},
			expected:     formats.SummaryResults{Scans: []formats.ScanSummaryResult{{}}},
			findingCount: 0,
		},
		{
			name: "One module result",
			results: Results{
				ScaResults: []ScaScanResult{{
					Target:      "target1",
					XrayResults: []services.ScanResponse{{Vulnerabilities: dummyScaVulnerabilities}},
				}},
				ExtendedScanResults: dummyExtendedScanResults,
			},
			expected: formats.SummaryResults{
				Scans: []formats.ScanSummaryResult{
					{
						Target: "target1",
						ScaScanResults: &formats.ScaScanSummaryResult{
							VulnerabilitiesSummary: formats.ScaSummaryCount{
								"Critical": formats.SummaryCount{"Undetermined": 1},
								"High":     formats.SummaryCount{"Not Applicable": 1},
							},
						},
						SecretsScanResults: &formats.SummaryCount{"Low": 2},
						SastScanResults:    &formats.SummaryCount{"Low": 1},
					},
				},
			},
			findingCount: 5,
		},
		{
			name: "Multiple module results",
			results: Results{
				ScaResults: []ScaScanResult{
					{
						Target:      "target1",
						XrayResults: []services.ScanResponse{{Vulnerabilities: dummyScaVulnerabilities}},
					},
					{
						Target:      "target2",
						XrayResults: []services.ScanResponse{{Vulnerabilities: dummyScaVulnerabilities}},
					},
				},
				ExtendedScanResults: dummyExtendedScanResults,
			},
			expected: formats.SummaryResults{
				Scans: []formats.ScanSummaryResult{
					{
						Target: "target1",
						ScaScanResults: &formats.ScaScanSummaryResult{
							ViolationSummary: formats.ScaSummaryCount{
								"Critical": formats.SummaryCount{"Undetermined": 1},
								"High":     formats.SummaryCount{"Not Applicable": 1},
							},
						},
						SecretsScanResults: &formats.SummaryCount{"Low": 1},
						SastScanResults:    &formats.SummaryCount{"Low": 1},
					},
					{
						Target: "target2",
						ScaScanResults: &formats.ScaScanSummaryResult{
							VulnerabilitiesSummary: formats.ScaSummaryCount{
								"Critical": formats.SummaryCount{"": 1},
							},
							ViolationSummary: formats.ScaSummaryCount{
								"High": formats.SummaryCount{"": 1},
							},
						},
						SecretsScanResults: &formats.SummaryCount{"Low": 1},
					},
				},
			},
			findingCount: 5,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.results.GetSummary()
			assert.Equal(t, testCase.expected, result)
			assert.Equal(t, testCase.findingCount, testCase.results.CountScanResultsFindings())
		})
	}
}
