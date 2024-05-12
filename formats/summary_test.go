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

func TestScaSummaryCount(t *testing.T) {
	testCases := []struct {
		name                                string
		count                               ScaSummaryCount
		expected                            int
		expectedSeverityCountsWithoutStatus SummaryCount
	}{
		{"Empty", ScaSummaryCount{}, 0, SummaryCount{}},
		{"Single-NoStatus", ScaSummaryCount{"High": SummaryCount{"": 1}}, 1, SummaryCount{"High": 1}},
		{"Single-Status", ScaSummaryCount{"High": SummaryCount{"Applicable": 1}}, 1, SummaryCount{"High": 1}},
		{
			"Multiple-NoStatus",
			ScaSummaryCount{"High": SummaryCount{"": 1}, "Medium": SummaryCount{"": 2}, "Low": SummaryCount{"": 3}},
			6,
			SummaryCount{"High": 1, "Medium": 2, "Low": 3},
		},
		{
			"Multiple-Status",
			ScaSummaryCount{"High": SummaryCount{"Applicable": 1}, "Medium": SummaryCount{"": 2}, "Low": SummaryCount{"Applicable": 3, "Not Applicable": 3}},
			9,
			SummaryCount{"High": 1, "Medium": 2, "Low": 6},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, testCase.count.GetTotal())
			assert.Equal(t, testCase.expectedSeverityCountsWithoutStatus, testCase.count.GetSeverityCountsWithoutStatus())
		})
	}
}

func TestScanSummaryResult(t *testing.T) {
	testCases := []struct {
		name                        string
		result                      *ScanSummaryResult
		expectedTotalIssueCount     int
		expectedSubScansWithIssues  []SummarySubScanType
		expectedSubScansIssuesCount map[SummarySubScanType]int
	}{
		{
			"Empty",
			&ScanSummaryResult{},
			0,
			[]SummarySubScanType{},
			map[SummarySubScanType]int{},
		},
		{
			"Single",
			&ScanSummaryResult{
				ScaScanResults: &ScaSummaryCount{"High": SummaryCount{"Applicable": 1}},
			},
			1,
			[]SummarySubScanType{ScaScan},
			map[SummarySubScanType]int{ScaScan: 1},
		},
		{
			"Multiple",
			&ScanSummaryResult{
				ScaScanResults:  &ScaSummaryCount{"High": SummaryCount{"Applicable": 1}},
				SastScanResults: &SummaryCount{"High": 1},
			},
			2,
			[]SummarySubScanType{SastScan, ScaScan},
			map[SummarySubScanType]int{SastScan: 1, ScaScan: 1},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedTotalIssueCount > 0, testCase.result.HasIssues())
			assert.Equal(t, testCase.expectedTotalIssueCount, testCase.result.GetTotalIssueCount())
			if assert.Equal(t, testCase.expectedSubScansWithIssues, testCase.result.GetSubScansWithIssues()) {
				for subScan, expectedCount := range testCase.expectedSubScansIssuesCount {
					assert.Equal(t, expectedCount, testCase.result.GetSubScanTotalIssueCount(subScan))
				}
			}
		})
	}

}
