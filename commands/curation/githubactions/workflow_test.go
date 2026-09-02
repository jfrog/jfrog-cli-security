package githubactions

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseWorkflowUses(t *testing.T) {
	workflowPath := filepath.Join(fixturesRoot, "curation-project", ".github", "workflows", "ci.yml")

	uses, err := ParseWorkflowUses(workflowPath)
	assert.NoError(t, err)

	sort.Slice(uses, func(i, j int) bool { return uses[i].Owner+uses[i].Repo < uses[j].Owner+uses[j].Repo })

	if assert.Len(t, uses, 2) {
		assert.Equal(t, WorkflowUse{Owner: "actions", Repo: "checkout", Ref: "v4", Raw: "actions/checkout@v4"}, uses[0])
		assert.Equal(t, WorkflowUse{Owner: "github", Repo: "codeql-action", Subpath: "analyze", Ref: "v3", Raw: "github/codeql-action/analyze@v3"}, uses[1])
	}
}

func TestParseUsesString(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want WorkflowUse
		ok   bool
	}{
		{"simple", "actions/checkout@v4", WorkflowUse{Owner: "actions", Repo: "checkout", Ref: "v4", Raw: "actions/checkout@v4"}, true},
		{"subpath", "github/codeql-action/analyze@v3", WorkflowUse{Owner: "github", Repo: "codeql-action", Subpath: "analyze", Ref: "v3", Raw: "github/codeql-action/analyze@v3"}, true},
		{"nested subpath", "a/b/c/d@v1", WorkflowUse{Owner: "a", Repo: "b", Subpath: "c/d", Ref: "v1", Raw: "a/b/c/d@v1"}, true},
		{"local action skipped", "./.github/actions/build-prep", WorkflowUse{}, false},
		{"docker uri skipped", "docker://alpine:3", WorkflowUse{}, false},
		{"no ref skipped", "actions/checkout", WorkflowUse{}, false},
		{"empty skipped", "", WorkflowUse{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseUsesString(tt.raw)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestCrossReference_DirectMatchSetsSubpath(t *testing.T) {
	discovered := []ActionRef{{Owner: "actions", Repo: "checkout", Ref: "v4", Path: "/tmp/nonexistent"}}
	used := []WorkflowUse{{Owner: "actions", Repo: "checkout", Ref: "v4", Subpath: ""}}

	got := CrossReference(discovered, used)

	assert.Empty(t, got[0].Subpath)
	assert.Empty(t, got[0].Parent)
}

func TestCrossReference_UnmatchedWithoutParentStaysEmpty(t *testing.T) {
	discovered := []ActionRef{{Owner: "some-org", Repo: "mystery-action", Ref: "v1", Path: "/tmp/nonexistent"}}

	got := CrossReference(discovered, nil)

	assert.Empty(t, got[0].Subpath)
	assert.Empty(t, got[0].Parent, "an unmatched entry with no attributable parent must never be guessed")
}

func TestCrossReference_TransitiveParentAttributedFromCompositeActionYml(t *testing.T) {
	actionsDir := filepath.Join(fixturesRoot, "curation-project", "_work", "_actions")
	discovered, err := DiscoverActionCache(actionsDir)
	assert.NoError(t, err)

	workflowPath := filepath.Join(fixturesRoot, "curation-project", ".github", "workflows", "ci.yml")
	used, err := ParseWorkflowUses(workflowPath)
	assert.NoError(t, err)

	got := CrossReference(discovered, used)

	byRepo := map[string]ActionRef{}
	for _, ref := range got {
		byRepo[ref.Repo] = ref
	}

	assert.Empty(t, byRepo["checkout"].Parent, "directly-used, non-composite action must have no parent")
	assert.Equal(t, "analyze", byRepo["codeql-action"].Subpath)
	assert.Empty(t, byRepo["codeql-action"].Parent, "the top-level composite action itself has no parent")
	assert.Equal(t, "github/codeql-action@v3", byRepo["transitive-action"].Parent, "pulled in only via codeql-action's own action.yml")
}
