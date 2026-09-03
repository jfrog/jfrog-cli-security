package githubactions

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"real monorepo action, another subpath of the same repo", "github/codeql-action/init@v3", WorkflowUse{Owner: "github", Repo: "codeql-action", Subpath: "init", Ref: "v3", Raw: "github/codeql-action/init@v3"}, true},
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

	assert.Empty(t, got[0].Subpaths)
	assert.Empty(t, got[0].Parent)
}

func TestCrossReference_UnmatchedWithoutParentStaysEmpty(t *testing.T) {
	discovered := []ActionRef{{Owner: "some-org", Repo: "mystery-action", Ref: "v1", Path: "/tmp/nonexistent"}}

	got := CrossReference(discovered, nil)

	assert.Empty(t, got[0].Subpaths)
	assert.Empty(t, got[0].Parent, "an unmatched entry with no attributable parent must never be guessed")
}

// writeCompositeAction writes a composite action.yml at dir referencing usesRaw (empty for a
// non-composite leaf action), for building multi-level transitive chains in tests.
func writeCompositeAction(t *testing.T, dir, usesRaw string) {
	t.Helper()
	if usesRaw == "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte("runs:\n  using: node20\n"), 0600))
		return
	}
	content := "runs:\n  using: composite\n  steps:\n    - uses: " + usesRaw + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte(content), 0600))
}

// buildChain writes n composite actions (org/action1@v1 -> org/action2@v1 -> ... -> org/actionN@v1,
// the last one non-composite) into fresh temp dirs and returns the []ActionRef for all of them.
func buildChain(t *testing.T, n int) []ActionRef {
	t.Helper()
	discovered := make([]ActionRef, n)
	for i := 1; i <= n; i++ {
		dir := t.TempDir()
		discovered[i-1] = ActionRef{Owner: "org", Repo: fmt.Sprintf("action%d", i), Ref: "v1", Path: dir}
		if i < n {
			writeCompositeAction(t, dir, fmt.Sprintf("org/action%d@v1", i+1))
		} else {
			writeCompositeAction(t, dir, "")
		}
	}
	return discovered
}

func TestCrossReference_LongChainFullyAttributedWithNoFixedDepthLimit(t *testing.T) {
	// A 6-node chain: action1 (direct) -> action2 -> ... -> action6, each composite referencing
	// the next. There is no fixed depth constant to satisfy here - the walk's bound scales with
	// len(discovered), so every hop must be attributed regardless of chain length.
	const n = 6
	discovered := buildChain(t, n)
	used := []WorkflowUse{{Owner: "org", Repo: "action1", Ref: "v1"}}

	got := CrossReference(discovered, used)

	byRepo := map[string]ActionRef{}
	for _, ref := range got {
		byRepo[ref.Repo] = ref
	}
	assert.Empty(t, byRepo["action1"].Parent)
	for i := 2; i <= n; i++ {
		assert.Equal(t, fmt.Sprintf("org/action%d@v1", i-1), byRepo[fmt.Sprintf("action%d", i)].Parent, "hop %d must be attributed", i-1)
	}
}

func TestCrossReference_CycleDoesNotHang(t *testing.T) {
	// action1 (direct) -> action2 -> action1: a cycle back to an already-direct entry.
	// visited/attributed dedup must stop this from looping forever, independent of the
	// len(discovered)-based round bound.
	path1, path2 := t.TempDir(), t.TempDir()
	writeCompositeAction(t, path1, "org/action2@v1")
	writeCompositeAction(t, path2, "org/action1@v1")

	discovered := []ActionRef{
		{Owner: "org", Repo: "action1", Ref: "v1", Path: path1},
		{Owner: "org", Repo: "action2", Ref: "v1", Path: path2},
	}
	used := []WorkflowUse{{Owner: "org", Repo: "action1", Ref: "v1"}}

	done := make(chan []ActionRef, 1)
	go func() { done <- CrossReference(discovered, used) }()
	select {
	case got := <-done:
		byRepo := map[string]ActionRef{}
		for _, ref := range got {
			byRepo[ref.Repo] = ref
		}
		assert.Empty(t, byRepo["action1"].Parent, "action1 is direct - the cycle must not overwrite that")
		assert.Equal(t, "org/action1@v1", byRepo["action2"].Parent)
	case <-time.After(5 * time.Second):
		t.Fatal("CrossReference did not return - cycle handling regressed")
	}
}

func TestCrossReference_TransitiveMonorepoReferenceKeepsItsSubpath(t *testing.T) {
	// A composite action's own action.yml can itself reference a monorepo-style action (e.g.
	// github/codeql-action/analyze@v3) - that transitive reference's subpath must survive
	// CrossReference, not just its Parent.
	parentPath := t.TempDir()
	require := assert.New(t)
	require.NoError(os.WriteFile(filepath.Join(parentPath, "action.yml"), []byte(""+
		"runs:\n"+
		"  using: composite\n"+
		"  steps:\n"+
		"    - uses: github/codeql-action/analyze@v3\n"), 0600))

	discovered := []ActionRef{
		{Owner: "my-org", Repo: "wrapper-action", Ref: "v1", Path: parentPath},
		{Owner: "github", Repo: "codeql-action", Ref: "v3", Path: "/tmp/nonexistent"},
	}
	used := []WorkflowUse{{Owner: "my-org", Repo: "wrapper-action", Ref: "v1"}}

	got := CrossReference(discovered, used)

	byRepo := map[string]ActionRef{}
	for _, ref := range got {
		byRepo[ref.Repo] = ref
	}
	assert.Equal(t, "my-org/wrapper-action@v1", byRepo["codeql-action"].Parent)
	assert.Equal(t, []string{"analyze"}, byRepo["codeql-action"].Subpaths, "the transitive reference's own subpath must not be dropped")
}

func TestCrossReference_MonorepoActionInvokedViaMultipleSubpathsCollectsAll(t *testing.T) {
	// github/codeql-action is commonly invoked twice in the same job - init@v3 then analyze@v3 -
	// both resolving to the same single _actions/github/codeql-action/v3/ directory entry.
	discovered := []ActionRef{{Owner: "github", Repo: "codeql-action", Ref: "v3", Path: "/tmp/nonexistent"}}
	used := []WorkflowUse{
		{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "init"},
		{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "analyze"},
	}

	got := CrossReference(discovered, used)

	assert.ElementsMatch(t, []string{"init", "analyze"}, got[0].Subpaths, "neither subpath invocation should be silently dropped")
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
	assert.Equal(t, []string{"analyze"}, byRepo["codeql-action"].Subpaths)
	assert.Empty(t, byRepo["codeql-action"].Parent, "the top-level composite action itself has no parent")
	assert.Equal(t, "github/codeql-action@v3", byRepo["transitive-action"].Parent, "pulled in only via codeql-action's own action.yml")
}
