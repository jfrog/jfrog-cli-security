package formats

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSummaryCount(t *testing.T) {
	testCases := []struct {
		name     string
		count    SummaryCount
		expected int
	}{
		{"Empty", SummaryCount{}, 0},
		{"Single", SummaryCount{"High": 1}, 1},
		{"Multiple", SummaryCount{"High": 1, "Medium": 2, "Low": 3}, 6},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, testCase.count.GetTotal())
		})
	}
}

func TestTwoLevelSummaryCount(t *testing.T) {
	testCases := []struct {
		name                                string
		count                               TwoLevelSummaryCount
		expected                            int
		expectedSeverityCountsWithoutStatus SummaryCount
	}{
		{"Empty", TwoLevelSummaryCount{}, 0, SummaryCount{}},
		{"Single-NoStatus", TwoLevelSummaryCount{"High": SummaryCount{"": 1}}, 1, SummaryCount{"High": 1}},
		{"Single-Status", TwoLevelSummaryCount{"High": SummaryCount{"Applicable": 1}}, 1, SummaryCount{"High": 1}},
		{
			"Multiple-NoStatus",
			TwoLevelSummaryCount{"High": SummaryCount{"": 1}, "Medium": SummaryCount{"": 2}, "Low": SummaryCount{"": 3}},
			6,
			SummaryCount{"High": 1, "Medium": 2, "Low": 3},
		},
		{
			"Multiple-Status",
			TwoLevelSummaryCount{"High": SummaryCount{"Applicable": 1}, "Medium": SummaryCount{"": 2}, "Low": SummaryCount{"Applicable": 3, "Not Applicable": 3}},
			9,
			SummaryCount{"High": 1, "Medium": 2, "Low": 6},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, testCase.count.GetTotal())
			assert.Equal(t, testCase.expectedSeverityCountsWithoutStatus, testCase.count.GetCombinedLowerLevel())
		})
	}
}

func TestScanVulnerabilitiesSummary(t *testing.T) {
	testCases := []struct {
		name                          string
		summary                       *ScanVulnerabilitiesSummary
		expectedTotalIssueCount       int
		expectedTotalUniqueIssueCount int
		expectedSubScansWithIssues    []SummarySubScanType
		expectedSubScansIssuesCount   map[SummarySubScanType]int
	}{
		{
			"Empty",
			&ScanVulnerabilitiesSummary{},
			0, 0,
			[]SummarySubScanType{},
			map[SummarySubScanType]int{},
		},
		{
			"Single",
			&ScanVulnerabilitiesSummary{
				ScaScanResults: &ScanScaResult{
					SummaryCount:   TwoLevelSummaryCount{"High": SummaryCount{"Applicable": 1}},
					UniqueFindings: 1,
				},
			},
			1, 1,
			[]SummarySubScanType{ScaScan},
			map[SummarySubScanType]int{ScaScan: 1},
		},
		{
			"Multiple",
			&ScanVulnerabilitiesSummary{
				ScaScanResults: &ScanScaResult{
					SummaryCount:   TwoLevelSummaryCount{"High": SummaryCount{"Applicable": 2}},
					UniqueFindings: 1,
				},
				SastScanResults: &SummaryCount{"High": 1},
			},
			3, 2,
			[]SummarySubScanType{SastScan, ScaScan},
			map[SummarySubScanType]int{SastScan: 1, ScaScan: 2},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validateScanVulnerabilitiesSummary(t, testCase.summary, testCase.expectedTotalIssueCount, testCase.expectedTotalUniqueIssueCount, testCase.expectedSubScansWithIssues, testCase.expectedSubScansIssuesCount)
		})
	}
}

func validateScanVulnerabilitiesSummary(t *testing.T, summary *ScanVulnerabilitiesSummary, expectedTotalIssueCount, expectedTotalUniqueIssueCount int, expectedSubScansWithIssues []SummarySubScanType, expectedSubScansIssuesCount map[SummarySubScanType]int) {
	assert.Equal(t, expectedTotalIssueCount, summary.GetTotalIssueCount())
	assert.Equal(t, expectedTotalUniqueIssueCount, summary.GetTotalUniqueIssueCount())
	if assert.Equal(t, expectedSubScansWithIssues, summary.GetSubScansWithIssues()) {
		for subScan, expectedCount := range expectedSubScansIssuesCount {
			assert.Equal(t, expectedCount, summary.GetSubScanTotalIssueCount(subScan))
		}
	}
}

func validateViolationSummary(t *testing.T, summary TwoLevelSummaryCount, expectedTotalIssueCount int, expectedViolationTypeCount map[ViolationIssueType]int) {
	assert.Equal(t, expectedTotalIssueCount, summary.GetTotal())
	for violationType, expectedCount := range expectedViolationTypeCount {
		assert.Equal(t, expectedCount, summary[violationType.String()].GetTotal())
	}
}

func TestScanSummaryResult(t *testing.T) {
	testCases := []struct {
		name   string
		result *ScanSummaryResult

		expectedTotalIssueCount         int
		expectedTotalVulnerabilityCount int
		expectedTotalViolationCount     int

		expectedSubScansWithIssues  []SummarySubScanType
		expectedSubScansIssuesCount map[SummarySubScanType]int
		expectedViolationTypeCount  map[ViolationIssueType]int
	}{
		{
			"Empty",
			&ScanSummaryResult{},
			0, 0, 0,
			[]SummarySubScanType{},
			map[SummarySubScanType]int{},
			map[ViolationIssueType]int{},
		},
		{
			"Single",
			&ScanSummaryResult{
				Vulnerabilities: &ScanVulnerabilitiesSummary{
					ScaScanResults: &ScanScaResult{
						SummaryCount:   TwoLevelSummaryCount{"High": SummaryCount{"Applicable": 1}},
						UniqueFindings: 1,
					},
				},
			},
			1, 1, 0,
			[]SummarySubScanType{ScaScan},
			map[SummarySubScanType]int{ScaScan: 1},
			map[ViolationIssueType]int{},
		},
		{
			"Multiple",
			&ScanSummaryResult{
				Vulnerabilities: &ScanVulnerabilitiesSummary{
					ScaScanResults: &ScanScaResult{
						SummaryCount:   TwoLevelSummaryCount{"High": SummaryCount{"Applicable": 1}},
						UniqueFindings: 1,
					},
					SastScanResults: &SummaryCount{"High": 1},
				},
				Violations: TwoLevelSummaryCount{
					ViolationTypeSecurity.String():        {"High": 1},
					ViolationTypeLicense.String():         {"High": 1},
					ViolationTypeOperationalRisk.String(): {"High": 1},
				},
			},
			5, 2, 3,
			[]SummarySubScanType{SastScan, ScaScan},
			map[SummarySubScanType]int{SastScan: 1, ScaScan: 1},
			map[ViolationIssueType]int{ViolationTypeSecurity: 1, ViolationTypeLicense: 1, ViolationTypeOperationalRisk: 1},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// validate general
			assert.Equal(t, testCase.expectedTotalIssueCount > 0, testCase.result.HasIssues())
			assert.Equal(t, testCase.expectedTotalIssueCount, testCase.result.GetTotalIssueCount())
			assert.Equal(t, testCase.expectedTotalViolationCount > 0, testCase.result.HasViolations())
			assert.Equal(t, testCase.expectedTotalViolationCount, testCase.result.GetTotalViolationCount())

			assert.Equal(t, testCase.expectedTotalVulnerabilityCount > 0, testCase.result.HasSecurityVulnerabilities())

			// validate content
			if testCase.result.Vulnerabilities != nil {
				validateScanVulnerabilitiesSummary(t, testCase.result.Vulnerabilities, testCase.expectedTotalVulnerabilityCount, testCase.expectedTotalVulnerabilityCount, testCase.expectedSubScansWithIssues, testCase.expectedSubScansIssuesCount)
			}
			validateViolationSummary(t, testCase.result.Violations, testCase.expectedTotalViolationCount, testCase.expectedViolationTypeCount)
		})
	}

}
