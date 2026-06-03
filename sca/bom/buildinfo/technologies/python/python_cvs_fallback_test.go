package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCvsFailedPackages(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []pinnedRequirement
	}{
		{
			name:   "no matching distribution",
			output: "ERROR: No matching distribution found for deepagents==0.5.5",
			want:   []pinnedRequirement{{Name: "deepagents", Version: "0.5.5"}},
		},
		{
			name:   "could not find a version",
			output: "ERROR: Could not find a version that satisfies the requirement langchain-core==1.4.0 (from versions: 1.0.0)",
			want:   []pinnedRequirement{{Name: "langchain-core", Version: "1.4.0"}},
		},
		{
			name:   "name is normalized",
			output: "ERROR: No matching distribution found for Langchain_Core==1.4.0",
			want:   []pinnedRequirement{{Name: "langchain-core", Version: "1.4.0"}},
		},
		{
			name:   "range specifiers are not captured",
			output: "ERROR: Could not find a version that satisfies the requirement langchain-core<2.0.0,>=1.3.2 (from deepagents)",
			want:   nil,
		},
		{
			name:   "deduplicates repeated lines",
			output: "ERROR: No matching distribution found for deepagents==0.5.5\nERROR: No matching distribution found for deepagents==0.5.5",
			want:   []pinnedRequirement{{Name: "deepagents", Version: "0.5.5"}},
		},
		{
			name:   "unrelated pip error yields nothing",
			output: "ERROR: 403 Forbidden",
			want:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseCvsFailedPackages(tc.output))
		})
	}
}

func TestIsCvsVersionFilteredOutput(t *testing.T) {
	cases := map[string]bool{
		"ERROR: No matching distribution found for deepagents==0.5.5":                                 true,
		"ERROR: Could not find a version that satisfies the requirement langchain-core<2.0.0,>=1.3.2": true,
		"ERROR: 403 Forbidden": false,
	}
	for output, want := range cases {
		t.Run(output, func(t *testing.T) {
			assert.Equal(t, want, isCvsVersionFilteredOutput(output))
		})
	}
}

func TestFormatCvsBlockedRequirementsMessage(t *testing.T) {
	msg := formatCvsBlockedRequirementsMessage(
		[]pinnedRequirement{{Name: "deepagents", Version: "0.5.5"}})

	assert.Contains(t, msg, "Curation audit failed")
	assert.Contains(t, msg, "could not be evaluated")
	assert.Contains(t, msg, "Affected package(s):")
	assert.Contains(t, msg, " - deepagents==0.5.5")
}
