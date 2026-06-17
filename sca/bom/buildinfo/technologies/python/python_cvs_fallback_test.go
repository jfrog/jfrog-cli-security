package python

import (
	"testing"

	"github.com/jfrog/gofrog/version"
	"github.com/stretchr/testify/assert"
)

func TestParseCvsFailedPackages(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []PinnedRequirement
	}{
		{
			name:   "no matching distribution",
			output: "ERROR: No matching distribution found for deepagents==0.5.5",
			want:   []PinnedRequirement{{Name: "deepagents", Version: "0.5.5", ParentName: "deepagents", ParentVersion: "0.5.5"}},
		},
		{
			name:   "could not find a version",
			output: "ERROR: Could not find a version that satisfies the requirement langchain-core==1.4.0 (from versions: 1.0.0)",
			want:   []PinnedRequirement{{Name: "langchain-core", Version: "1.4.0", ParentName: "langchain-core", ParentVersion: "1.4.0"}},
		},
		{
			name:   "name is normalized",
			output: "ERROR: No matching distribution found for Langchain_Core==1.4.0",
			want:   []PinnedRequirement{{Name: "langchain-core", Version: "1.4.0", ParentName: "langchain-core", ParentVersion: "1.4.0"}},
		},
		{
			name:   "deduplicates repeated lines",
			output: "ERROR: No matching distribution found for deepagents==0.5.5\nERROR: No matching distribution found for deepagents==0.5.5",
			want: []PinnedRequirement{
				{Name: "deepagents", Version: "0.5.5", ParentName: "deepagents", ParentVersion: "0.5.5"},
			},
		},
		{
			name:   "range spec without parent",
			output: "ERROR: No matching distribution found for langchain-core>=1.4.0,<2.0.0",
			want: []PinnedRequirement{
				{Name: "langchain-core", VersionRange: ">=1.4.0,<2.0.0", ParentName: "langchain-core"},
			},
		},
		{
			name:   "range spec with parent",
			output: "ERROR: Could not find a version that satisfies the requirement langchain-core>=1.4.0 (from deepagents==0.6.8)",
			want: []PinnedRequirement{
				{Name: "langchain-core", VersionRange: ">=1.4.0", ParentName: "deepagents", ParentVersion: "0.6.8"},
			},
		},
		{
			// pip omits the version in "(from deepagents)"; recovered from the "Collecting" line.
			name: "transitive range, parent version recovered from Collecting line",
			output: "Collecting deepagents==0.6.8 (from -r requirements.txt (line 1))\n" +
				"ERROR: Could not find a version that satisfies the requirement langchain-core<2.0.0,>=1.4.0 (from deepagents) (from versions: 1.3.3, 1.4.0a1)\n" +
				"ERROR: No matching distribution found for langchain-core<2.0.0,>=1.4.0",
			want: []PinnedRequirement{
				{Name: "langchain-core", VersionRange: "<2.0.0,>=1.4.0", ParentName: "deepagents", ParentVersion: "0.6.8"},
			},
		},
		{
			// Package list must not spill past the blank line into the "To fix this" instruction text.
			name: "ResolutionImpossible attributes blocker to direct dep",
			output: "Collecting deepagents==0.6.9 (from -r requirements.txt (line 1))\n" +
				"  Downloading deepagents-0.6.9-py3-none-any.whl (221 kB)\n" +
				"ERROR: Cannot install langchain because these package versions have conflicting dependencies.\n" +
				"The conflict is caused by:\n" +
				"    langgraph 1.2.5 depends on langgraph-sdk<0.5.0 and >=0.4.2\n" +
				"Additionally, some packages in these conflicts have no matching distributions available for your environment:\n" +
				"    langgraph-sdk\n" +
				"\n" +
				"To fix this you could try to:\n" +
				"1. loosen the range of package versions you've specified\n" +
				"ERROR: ResolutionImpossible: for help visit ...\n",
			want: []PinnedRequirement{
				{Name: "langgraph-sdk", ParentName: "deepagents", ParentVersion: "0.6.9"},
			},
		},
		{
			// Multiple direct deps → ambiguous attribution, blocker stays self-attributed.
			name: "ResolutionImpossible with multiple stripped deps",
			output: "no matching distributions available for your environment:\n" +
				"    langgraph-sdk\n" +
				"    another-pkg\n" +
				"\n" +
				"To fix this you could try to:\n",
			want: []PinnedRequirement{
				{Name: "langgraph-sdk", ParentName: "langgraph-sdk"},
				{Name: "another-pkg", ParentName: "another-pkg"},
			},
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
	resolutionImpossible := "ERROR: ResolutionImpossible\n" +
		"Additionally, some packages in these conflicts have no matching distributions available for your environment:\n" +
		"    langgraph-sdk"
	cases := map[string]bool{
		"ERROR: No matching distribution found for deepagents==0.5.5":                                 true,
		"ERROR: Could not find a version that satisfies the requirement langchain-core<2.0.0,>=1.3.2": true,
		resolutionImpossible:                               true,
		"ERROR: 403 Forbidden":                             false,
		"ERROR: ResolutionImpossible: some other conflict": false, // no "no matching distributions" line
	}
	for output, want := range cases {
		t.Run(output, func(t *testing.T) {
			assert.Equal(t, want, isCvsVersionFilteredOutput(output))
		})
	}
}

func TestFormatCvsBlockedRequirementsMessage(t *testing.T) {
	msg := formatCvsBlockedRequirementsMessage(
		[]PinnedRequirement{{Name: "deepagents", Version: "0.5.5", ParentName: "deepagents", ParentVersion: "0.5.5"}})

	assert.Contains(t, msg, "Curation audit failed")
	assert.Contains(t, msg, "could not be evaluated")
	assert.Contains(t, msg, "Affected package(s):")
	assert.Contains(t, msg, " - deepagents==0.5.5")
}

func TestFormatCvsBlockedRequirementsMessageRange(t *testing.T) {
	msg := formatCvsBlockedRequirementsMessage(
		[]PinnedRequirement{{Name: "langchain-core", VersionRange: ">=1.4.0,<2.0.0", ParentName: "deepagents"}})

	assert.Contains(t, msg, " - langchain-core>=1.4.0,<2.0.0")
}

func TestFormatCvsBlockedRequirementsMessageResolutionImpossible(t *testing.T) {
	// ResolutionImpossible entries have no Version and no VersionRange — must not emit a trailing "==".
	msg := formatCvsBlockedRequirementsMessage(
		[]PinnedRequirement{{Name: "langgraph-sdk", ParentName: "langgraph-sdk"}})

	assert.Contains(t, msg, " - langgraph-sdk (version unknown)")
	assert.NotContains(t, msg, "langgraph-sdk==")
}

func TestCvsBlockedError(t *testing.T) {
	pins := []PinnedRequirement{{Name: "deepagents", Version: "0.6.8", ParentName: "deepagents", ParentVersion: "0.6.8"}}
	cause := assert.AnError
	err := &CvsBlockedError{Packages: pins, Cause: cause}

	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "deepagents==0.6.8")
	assert.Contains(t, err.Error(), "Curation audit failed")
}

func TestResolveVersionRange(t *testing.T) {
	cases := []struct {
		name       string
		rangeSpec  string
		candidates []string
		want       string
	}{
		{
			name:       "picks newest in range",
			rangeSpec:  ">=1.4.0,<2.0.0",
			candidates: []string{"1.0.0", "1.4.0", "1.5.0", "1.9.9", "2.0.0", "2.1.0"},
			want:       "1.9.9",
		},
		{
			name:       "no candidate satisfies range",
			rangeSpec:  ">=3.0.0",
			candidates: []string{"1.0.0", "2.0.0"},
			want:       "",
		},
		{
			name:       "exact pin via == in range",
			rangeSpec:  "==1.4.0",
			candidates: []string{"1.3.0", "1.4.0", "1.5.0"},
			want:       "1.4.0",
		},
		{
			name:       "greater than strictly",
			rangeSpec:  ">1.4.0",
			candidates: []string{"1.4.0", "1.4.1", "1.5.0"},
			want:       "1.5.0",
		},
		{
			name:       "not equal excludes version",
			rangeSpec:  "!=1.5.0,>=1.4.0",
			candidates: []string{"1.4.0", "1.5.0", "1.6.0"},
			want:       "1.6.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResolveVersionRange(tc.rangeSpec, tc.candidates))
		})
	}
}

func TestVersionMatchesRange(t *testing.T) {
	cases := []struct {
		v         string
		rangeSpec string
		want      bool
	}{
		{"1.5.0", ">=1.4.0,<2.0.0", true},
		{"1.4.0", ">=1.4.0,<2.0.0", true},
		{"2.0.0", ">=1.4.0,<2.0.0", false},
		{"1.3.9", ">=1.4.0", false},
		{"1.4.0", "!=1.4.0", false},
		{"1.4.1", "!=1.4.0", true},
	}
	for _, tc := range cases {
		t.Run(tc.v+"_"+tc.rangeSpec, func(t *testing.T) {
			assert.Equal(t, tc.want, versionMatchesRange(tc.v, tc.rangeSpec))
		})
	}
}

func TestVersionMatchesConstraintCompatibleRelease(t *testing.T) {
	cases := []struct {
		v          string
		constraint string
		want       bool
	}{
		// ~= 1.4 means >= 1.4 AND < 2.0
		{"1.4.0", "~=1.4", true},
		{"1.9.9", "~=1.4", true},
		{"2.0.0", "~=1.4", false},
		{"3.0.0", "~=1.4", false},
		{"1.3.9", "~=1.4", false},
		// ~= 1.4.2 means >= 1.4.2 AND < 1.5.0
		{"1.4.2", "~=1.4.2", true},
		{"1.4.9", "~=1.4.2", true},
		{"1.5.0", "~=1.4.2", false},
		{"1.4.1", "~=1.4.2", false},
		// unrecognized operator should not match
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "===1.0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.v+"_"+tc.constraint, func(t *testing.T) {
			assert.Equal(t, tc.want, versionMatchesConstraint(version.NewVersion(tc.v), tc.constraint))
		})
	}
}

