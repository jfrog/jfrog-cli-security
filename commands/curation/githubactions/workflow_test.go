package githubactions

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWorkflowUses(t *testing.T) {
	workflowPath := filepath.Join(fixturesRoot, "curation-project", ".github", "workflows", "ci.yml")

	uses, err := ParseWorkflowUses(workflowPath, "build")
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
		{"verify when the reference is owner repo and ref then it parses", "actions/checkout@v4", WorkflowUse{Owner: "actions", Repo: "checkout", Ref: "v4", Raw: "actions/checkout@v4"}, true},
		{"verify when the reference carries a subpath then the subpath is captured", "github/codeql-action/analyze@v3", WorkflowUse{Owner: "github", Repo: "codeql-action", Subpath: "analyze", Ref: "v3", Raw: "github/codeql-action/analyze@v3"}, true},
		{"verify when another subpath of the same repo is used then it parses independently", "github/codeql-action/init@v3", WorkflowUse{Owner: "github", Repo: "codeql-action", Subpath: "init", Ref: "v3", Raw: "github/codeql-action/init@v3"}, true},
		{"verify when the subpath is nested then the whole remainder is captured", "a/b/c/d@v1", WorkflowUse{Owner: "a", Repo: "b", Subpath: "c/d", Ref: "v1", Raw: "a/b/c/d@v1"}, true},
		{"verify when the reference is a local action then it is skipped", "./.github/actions/build-prep", WorkflowUse{}, false},
		{"verify when the reference is a docker uri then it is skipped", "docker://alpine:3", WorkflowUse{}, false},
		{"verify when the reference has no ref then it is skipped", "actions/checkout", WorkflowUse{}, false},
		{"verify when the reference is empty then it is skipped", "", WorkflowUse{}, false},
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

// discoveredAction is one entry in a cross-reference case's action cache: the triple the walk
// would have found, plus the action.yml bodies to plant under it keyed by subpath ("" for the
// cache root). Expressing the fixture this way keeps the cases data rather than per-row setup.
type discoveredAction struct {
	key   string            // "owner/repo@ref"
	yamls map[string]string // subpath -> action.yml body
}

// compositeYAML is an action.yml for a composite action whose single step references uses.
func compositeYAML(uses string) string {
	return "runs:\n  using: composite\n  steps:\n    - uses: " + uses + "\n"
}

// unreadableYAML is accepted by GitHub's runner but rejected by yaml.v3 (duplicate mapping keys).
const unreadableYAML = "name: w\nname: w\nruns:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v4\n"

// buildDiscovered materializes each action into its own directory and returns the []ActionRef
// CrossReference would have been handed.
func buildDiscovered(t *testing.T, actions []discoveredAction) []ActionRef {
	t.Helper()
	refs := make([]ActionRef, 0, len(actions))
	for _, a := range actions {
		owner, rest, _ := strings.Cut(a.key, "/")
		repo, ref, _ := strings.Cut(rest, "@")
		dir := t.TempDir()
		for subpath, body := range a.yamls {
			target := filepath.Join(dir, filepath.FromSlash(subpath))
			require.NoError(t, os.MkdirAll(target, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(target, "action.yml"), []byte(body), 0600))
		}
		refs = append(refs, ActionRef{Owner: owner, Repo: repo, Ref: ref, Path: dir})
	}
	return refs
}

func TestCrossReference(t *testing.T) {
	tests := []struct {
		name         string
		discovered   []discoveredAction
		used         []WorkflowUse
		wantRepos    []string            // every entry that must survive; attribution is additive
		wantParents  map[string]string   // repo -> Parent ("" means none may be guessed)
		wantSubpaths map[string][]string // repo -> Subpaths
	}{
		{
			name:         "verify when an entry is used directly then it gets no parent and no unused subpath",
			discovered:   []discoveredAction{{key: "actions/checkout@v4"}},
			used:         []WorkflowUse{{Owner: "actions", Repo: "checkout", Ref: "v4"}},
			wantRepos:    []string{"checkout"},
			wantParents:  map[string]string{"checkout": ""},
			wantSubpaths: map[string][]string{"checkout": nil},
		},
		{
			name:         "verify when no workflow explains an entry then its parent stays empty rather than guessed",
			discovered:   []discoveredAction{{key: "some-org/mystery-action@v1"}},
			wantRepos:    []string{"mystery-action"},
			wantParents:  map[string]string{"mystery-action": ""},
			wantSubpaths: map[string][]string{"mystery-action": nil},
		},
		{
			name: "verify when an entry cannot be attributed then it is still not dropped",
			discovered: []discoveredAction{
				{key: "actions/checkout@v4"},
				{key: "some-other-org/unexplained@v9"},
			},
			used:        []WorkflowUse{{Owner: "actions", Repo: "checkout", Ref: "v4"}},
			wantRepos:   []string{"checkout", "unexplained"},
			wantParents: map[string]string{"unexplained": ""},
		},
		{
			// codeql-action is commonly invoked twice in one job, init@v3 then analyze@v3.
			name:       "verify when a monorepo action is invoked via several subpaths then all of them are collected",
			discovered: []discoveredAction{{key: "github/codeql-action@v3"}},
			used: []WorkflowUse{
				{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "init"},
				{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "analyze"},
			},
			wantRepos:    []string{"codeql-action"},
			wantSubpaths: map[string][]string{"codeql-action": {"init", "analyze"}},
		},
		{
			name: "verify when a transitive reference carries a subpath then the subpath survives",
			discovered: []discoveredAction{
				{key: "my-org/wrapper-action@v1", yamls: map[string]string{"": compositeYAML("github/codeql-action/analyze@v3")}},
				{key: "github/codeql-action@v3"},
			},
			used:         []WorkflowUse{{Owner: "my-org", Repo: "wrapper-action", Ref: "v1"}},
			wantRepos:    []string{"wrapper-action", "codeql-action"},
			wantParents:  map[string]string{"codeql-action": "my-org/wrapper-action@v1"},
			wantSubpaths: map[string][]string{"codeql-action": {"analyze"}},
		},
		{
			// The cache root is deliberately non-composite, so falling back to it would leave both
			// transitive entries unattributed.
			name: "verify when subpaths have their own metadata then each is read rather than the cache root",
			discovered: []discoveredAction{
				{key: "github/codeql-action@v3", yamls: map[string]string{
					"":        "runs:\n  using: node20\n",
					"init":    compositeYAML("org/from-init@v1"),
					"analyze": compositeYAML("org/from-analyze@v1"),
				}},
				{key: "org/from-init@v1"},
				{key: "org/from-analyze@v1"},
			},
			used: []WorkflowUse{
				{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "init"},
				{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "analyze"},
			},
			wantRepos: []string{"codeql-action", "from-init", "from-analyze"},
			wantParents: map[string]string{
				"from-init":    "github/codeql-action@v3",
				"from-analyze": "github/codeql-action@v3",
			},
		},
		{
			name: "verify when a composite action.yml cannot be read then its child survives unattributed",
			discovered: []discoveredAction{
				{key: "some-org/wrapper@v1", yamls: map[string]string{"": unreadableYAML}},
				{key: "actions/setup-node@v4"},
			},
			used:        []WorkflowUse{{Owner: "some-org", Repo: "wrapper", Ref: "v1"}},
			wantRepos:   []string{"wrapper", "setup-node"},
			wantParents: map[string]string{"setup-node": ""},
		},
		{
			name:      "verify when nothing was discovered then nothing is returned",
			wantRepos: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CrossReference(buildDiscovered(t, tt.discovered), tt.used)

			byRepo := make(map[string]ActionRef, len(got))
			repos := make([]string, len(got))
			for i, ref := range got {
				byRepo[ref.Repo] = ref
				repos[i] = ref.Repo
			}
			assert.ElementsMatch(t, tt.wantRepos, repos, "attribution is additive - it may never drop an entry")
			for repo, wantParent := range tt.wantParents {
				assert.Equal(t, wantParent, byRepo[repo].Parent, "parent of %s", repo)
			}
			for repo, wantSubpaths := range tt.wantSubpaths {
				assert.Equal(t, wantSubpaths, byRepo[repo].Subpaths, "subpaths of %s", repo)
			}
		})
	}
}

func TestParseCompositeActionUses(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		why  string
	}{
		{
			name: "verify when the action.yml cannot be parsed then nothing is attributed and the run continues",
			yaml: unreadableYAML,
			why:  "a file this parser cannot read attributes nothing, and is not a failure of the run",
		},
		{
			name: "verify when the action is not composite then nothing is referenced",
			yaml: "runs:\n  using: node20\n",
			why:  "only composite actions declare uses: steps of their own",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte(tt.yaml), 0600))

			assert.Empty(t, parseCompositeActionUses(dir), tt.why)
		})
	}
}

func TestParseWorkflowUses_JobMustBeIdentified(t *testing.T) {
	// Attribution needs to know which job it is describing. Every other job in the file ran on
	// its own runner with its own cache, so attributing from them is worse than not attributing:
	// it would label an entry with a parent that never pulled it in.
	workflowPath := filepath.Join(writeWorkflows(t, map[string]string{
		"ci.yml": "jobs:\n" +
			jobWithUses("build", "actions/checkout@v4") +
			jobWithUses("publish", "actions/upload-artifact@v4"),
	}), "ci.yml")

	tests := []struct {
		name string
		// jobID is the job to attribute against; "" is the local-invocation case, since a runner
		// always sets GITHUB_JOB.
		jobID string
		// wantErrContains names what the message must surface so the mismatch is diagnosable
		// from the log alone.
		wantErrContains []string
	}{
		{
			name:            "verify when the file does not declare the job then the error names it and the jobs that exist",
			jobID:           "a-job-declared-somewhere-else",
			wantErrContains: []string{"a-job-declared-somewhere-else", "build", "publish"},
		},
		{
			name:  "verify when no job id is given then attribution is refused",
			jobID: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uses, err := ParseWorkflowUses(workflowPath, tt.jobID)

			assert.ErrorIs(t, err, ErrJobUnknown)
			assert.Empty(t, uses, "no uses: may be returned from jobs that ran on other runners")
			for _, want := range tt.wantErrContains {
				assert.ErrorContains(t, err, want)
			}
		})
	}
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

func TestCrossReference_SharedChildParentFollowsWorkflowOrder(t *testing.T) {
	pathA, pathB, pathChild := t.TempDir(), t.TempDir(), t.TempDir()
	writeCompositeAction(t, pathA, "org/shared-child@v1")
	writeCompositeAction(t, pathB, "org/shared-child@v1")

	seen := map[string]bool{}
	for range 200 {
		got := CrossReference(
			[]ActionRef{
				{Owner: "org", Repo: "parent-a", Ref: "v1", Path: pathA},
				{Owner: "org", Repo: "parent-b", Ref: "v1", Path: pathB},
				{Owner: "org", Repo: "shared-child", Ref: "v1", Path: pathChild},
			},
			[]WorkflowUse{
				{Owner: "org", Repo: "parent-a", Ref: "v1"},
				{Owner: "org", Repo: "parent-b", Ref: "v1"},
			})
		for _, ref := range got {
			if ref.Repo == "shared-child" {
				seen[ref.Parent] = true
			}
		}
	}

	assert.Equal(t, map[string]bool{"org/parent-a@v1": true}, seen,
		"when two parents pull in the same child, the first in the file's order must win, every run")
}

// Two refs of one monorepo, each invoked through a different subpath - github/codeql-action
// init@v2 and analyze@v3. Subpaths are keyed on owner/repo@ref, so this has its own test rather
// than a table row: TestCrossReference keys its expectations by repo alone, which cannot tell the
// two apart.
func TestCrossReference_SubpathsDoNotBleedBetweenRefsOfOneRepo(t *testing.T) {
	discovered := buildDiscovered(t, []discoveredAction{
		{key: "github/codeql-action@v2"},
		{key: "github/codeql-action@v3"},
	})

	got := CrossReference(discovered, []WorkflowUse{
		{Owner: "github", Repo: "codeql-action", Ref: "v2", Subpath: "init"},
		{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "analyze"},
	})

	byRef := map[string][]string{}
	for _, ref := range got {
		byRef[ref.Ref] = ref.Subpaths
	}
	assert.Equal(t, map[string][]string{"v2": {"init"}, "v3": {"analyze"}}, byRef,
		"each ref must carry only the subpath it was invoked through")
}

func TestCrossReference_TransitiveParentAttributedFromCompositeActionYml(t *testing.T) {
	actionsDir := filepath.Join(fixturesRoot, "curation-project", "_work", "_actions")
	scan, err := DiscoverActionCache(actionsDir)
	assert.NoError(t, err)
	require.Empty(t, scan.Unaccounted)
	discovered := scan.Refs

	workflowPath := filepath.Join(fixturesRoot, "curation-project", ".github", "workflows", "ci.yml")
	used, err := ParseWorkflowUses(workflowPath, "build")
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

func TestCrossReference_RootAndSubpathBothUsed_BothMetadataLocationsAreRead(t *testing.T) {
	// github/codeql-action is invoked once at its root and once through a subpath in the same
	// job. Both locations carry their own action.yml with a different transitive child, so both
	// must be read - not just the subpath, which is what collectSubpaths' root-drop bug left out.
	discovered := buildDiscovered(t, []discoveredAction{
		{key: "github/codeql-action@v3", yamls: map[string]string{
			"":     compositeYAML("org/from-root@v1"),
			"init": compositeYAML("org/from-init@v1"),
		}},
		{key: "org/from-root@v1"},
		{key: "org/from-init@v1"},
	})

	got := CrossReference(discovered, []WorkflowUse{
		{Owner: "github", Repo: "codeql-action", Ref: "v3"},
		{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "init"},
	})

	byRepo := map[string]ActionRef{}
	for _, ref := range got {
		byRepo[ref.Repo] = ref
	}
	assert.Equal(t, []string{"init"}, byRepo["codeql-action"].Subpaths, "the root use itself is not a subpath")
	assert.Equal(t, "github/codeql-action@v3", byRepo["from-root"].Parent, "the root's own action.yml must be read, not skipped")
	assert.Equal(t, "github/codeql-action@v3", byRepo["from-init"].Parent)
}

func TestCrossReference_ChildReferencedByTwoParentsAtDifferentSubpaths_BothAreScanned(t *testing.T) {
	// parent-a references shared-child@v1 directly (root), parent-b references it via a subpath.
	// The first parent in file order wins Parent, but shared-child's own subpath metadata (pulled
	// in only through parent-b's reference) must still be scanned rather than dropped once
	// shared-child is already attributed via parent-a.
	discovered := buildDiscovered(t, []discoveredAction{
		{key: "org/parent-a@v1", yamls: map[string]string{"": compositeYAML("org/shared-child@v1")}},
		{key: "org/parent-b@v1", yamls: map[string]string{"": compositeYAML("org/shared-child/sub@v1")}},
		{key: "org/shared-child@v1", yamls: map[string]string{"sub": compositeYAML("org/from-sub@v1")}},
		{key: "org/from-sub@v1"},
	})

	got := CrossReference(discovered, []WorkflowUse{
		{Owner: "org", Repo: "parent-a", Ref: "v1"},
		{Owner: "org", Repo: "parent-b", Ref: "v1"},
	})

	byRepo := map[string]ActionRef{}
	for _, ref := range got {
		byRepo[ref.Repo] = ref
	}
	assert.Equal(t, "org/parent-a@v1", byRepo["shared-child"].Parent, "first parent in file order still wins")
	assert.Equal(t, []string{"sub"}, byRepo["shared-child"].Subpaths, "parent-b's subpath reference must still be merged in")
	assert.Equal(t, "org/shared-child@v1", byRepo["from-sub"].Parent, "shared-child/sub's own metadata must still be scanned")
}

// writeWorkflows writes each name->content pair as a file in a fresh temp dir and returns it.
func writeWorkflows(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0600))
	}
	return dir
}

// jobWithUses renders a minimal workflow job declaring one uses: step per ref.
func jobWithUses(jobID string, refs ...string) string {
	job := "  " + jobID + ":\n    steps:\n"
	for _, ref := range refs {
		job += "      - uses: " + ref + "\n"
	}
	return job
}

func TestParseWorkflowUses_ScopesToTheRunningJob(t *testing.T) {
	// The command curates the job it runs in. An action referenced only by a sibling job in
	// the same workflow file is not part of this job's dependency graph.
	dir := writeWorkflows(t, map[string]string{
		"ci.yml": "jobs:\n" +
			jobWithUses("build", "actions/checkout@v4") +
			jobWithUses("publish", "actions/upload-artifact@v4"),
	})
	workflowPath := filepath.Join(dir, "ci.yml")

	tests := []struct {
		name      string
		jobID     string
		wantRepos []string
	}{
		{"verify when the job is build then only its own uses are returned", "build", []string{"checkout"}},
		{"verify when the job is publish then only its own uses are returned", "publish", []string{"upload-artifact"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uses, err := ParseWorkflowUses(workflowPath, tt.jobID)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantRepos, repoNames(uses))
		})
	}
}

func TestParseWorkflowUses_SubpathOrderIsStable(t *testing.T) {
	// A monorepo action invoked twice in the same job collapses to one cache entry carrying both
	// subpaths, and that order is rendered into the report's Action cell. Steps are a slice, so
	// the order is the file's - this pins that nothing downstream reintroduces map iteration.
	workflowPath := filepath.Join(writeWorkflows(t, map[string]string{
		"ci.yml": "jobs:\n" + jobWithUses("build",
			"github/codeql-action/init@v3", "github/codeql-action/analyze@v3"),
	}), "ci.yml")

	seen := map[string]bool{}
	for range 200 {
		used, err := ParseWorkflowUses(workflowPath, "build")
		require.NoError(t, err)
		got := CrossReference([]ActionRef{{Owner: "github", Repo: "codeql-action", Ref: "v3", Path: "/nonexistent"}}, used)
		seen[NewActionReportRow(got[0], ActionCurationResult{Status: ActionApproved}).Action] = true
	}
	assert.Equal(t, map[string]bool{"github/codeql-action (init, analyze)": true}, seen,
		"the rendered report cell must follow the file's step order, every run")
}

func repoNames(uses []WorkflowUse) []string {
	if len(uses) == 0 {
		return nil
	}
	repos := make([]string, len(uses))
	for i, u := range uses {
		repos[i] = u.Repo
	}
	return repos
}
