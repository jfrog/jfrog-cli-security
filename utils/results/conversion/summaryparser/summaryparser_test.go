package summaryparser

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
