package summaryparser

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
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

func TestScaSecurityHandler(t *testing.T) {
	testCases := []struct {
		name                    string
		severityCountsToProcess []map[severityutils.Severity]map[jasutils.ApplicabilityStatus]int
		expected                formats.ScaScanResultSummary
	}{
		{
			name:                    "No results",
			severityCountsToProcess: []map[severityutils.Severity]map[jasutils.ApplicabilityStatus]int{},
			expected:                formats.ScaScanResultSummary{Security: formats.ResultSummary{}},
		},
		{
			name: "One result",
			severityCountsToProcess: []map[severityutils.Severity]map[jasutils.ApplicabilityStatus]int{
				{
					severityutils.Critical: {jasutils.Applicable: 1},
				},
			},
			expected: formats.ScaScanResultSummary{Security: formats.ResultSummary{"Critical": map[string]int{"Applicable": 1}}},
		},
		{
			name: "Multiple results",
			severityCountsToProcess: []map[severityutils.Severity]map[jasutils.ApplicabilityStatus]int{
				{
					severityutils.Critical: {jasutils.Applicable: 1, jasutils.NotApplicable: 1},
				},
				{
					severityutils.High:   {jasutils.Applicable: 1},
					severityutils.Medium: {jasutils.NotScanned: 1},
				},
				{
					severityutils.Low:  {jasutils.NotCovered: 1},
					severityutils.High: {jasutils.Applicable: 1},
				},
				{
					severityutils.Critical: {jasutils.Applicable: 1, jasutils.NotApplicable: 2},
					severityutils.Low:      {jasutils.Applicable: 1},
				},
			},
			expected: formats.ScaScanResultSummary{Security: formats.ResultSummary{
				"Critical": {jasutils.Applicable.String(): 2, jasutils.NotApplicable.String(): 3},
				"High":     {jasutils.Applicable.String(): 2},
				"Medium":   {jasutils.NotScanned.String(): 1},
				"Low":      {jasutils.Applicable.String(): 1, jasutils.NotCovered.String(): 1},
			}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			scaSummaryResults := &formats.ScaScanResultSummary{Security: formats.ResultSummary{}}
			assert.NotNil(t, scaSummaryResults)
			for _, severityCounts := range testCase.severityCountsToProcess {
				for severity, statusCounts := range severityCounts {
					for status, count := range statusCounts {
						for i := 0; i < count; i++ {
							scaSecurityHandler(scaSummaryResults, severity, status)
						}
					}
				}
			}
			assert.Equal(t, testCase.expected, *scaSummaryResults)
		})
	}
}
