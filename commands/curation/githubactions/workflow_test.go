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

	remote := uses.Remote
	sort.Slice(remote, func(i, j int) bool { return remote[i].Owner+remote[i].Repo < remote[j].Owner+remote[j].Repo })

	if assert.Len(t, remote, 2) {
		assert.Equal(t, WorkflowUse{Owner: "actions", Repo: "checkout", Ref: "v4", Raw: "actions/checkout@v4"}, remote[0])
		assert.Equal(t, WorkflowUse{Owner: "github", Repo: "codeql-action", Subpath: "analyze", Ref: "v3", Raw: "github/codeql-action/analyze@v3"}, remote[1])
	}
	// The local step is not a reference to curate, but it is the reason the cache is not the
	// whole story - it has to survive parsing for the report to be able to say so.
	assert.Equal(t, []LocalUse{{Raw: "./.github/actions/build-prep"}}, uses.Local,
		"the job's own workflow declares it, so there is no declaring action to attribute it to")
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
			got, _ := CrossReference(buildDiscovered(t, tt.discovered), JobUses{Remote: tt.used})

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

			got := parseCompositeActionUses(dir, "org/declarer@v1")

			assert.Empty(t, got.Remote, tt.why)
			assert.Empty(t, got.Local, "and no local step either - "+tt.why)
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
			assert.Empty(t, uses.Remote, "no uses: may be returned from jobs that ran on other runners")
			assert.Empty(t, uses.Local, "nor may a local step, for the same reason")
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
	used := JobUses{Remote: []WorkflowUse{{Owner: "org", Repo: "action1", Ref: "v1"}}}

	got, _ := CrossReference(discovered, used)

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
	used := JobUses{Remote: []WorkflowUse{{Owner: "org", Repo: "action1", Ref: "v1"}}}

	done := make(chan []ActionRef, 1)
	go func() {
		got, _ := CrossReference(discovered, used)
		done <- got
	}()
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
		got, _ := CrossReference(
			[]ActionRef{
				{Owner: "org", Repo: "parent-a", Ref: "v1", Path: pathA},
				{Owner: "org", Repo: "parent-b", Ref: "v1", Path: pathB},
				{Owner: "org", Repo: "shared-child", Ref: "v1", Path: pathChild},
			},
			JobUses{Remote: []WorkflowUse{
				{Owner: "org", Repo: "parent-a", Ref: "v1"},
				{Owner: "org", Repo: "parent-b", Ref: "v1"},
			}})
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

	got, _ := CrossReference(discovered, JobUses{Remote: []WorkflowUse{
		{Owner: "github", Repo: "codeql-action", Ref: "v2", Subpath: "init"},
		{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "analyze"},
	}})

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

	got, _ := CrossReference(discovered, used)

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

	got, _ := CrossReference(discovered, JobUses{Remote: []WorkflowUse{
		{Owner: "github", Repo: "codeql-action", Ref: "v3"},
		{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "init"},
	}})

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

	got, _ := CrossReference(discovered, JobUses{Remote: []WorkflowUse{
		{Owner: "org", Repo: "parent-a", Ref: "v1"},
		{Owner: "org", Repo: "parent-b", Ref: "v1"},
	}})

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
			assert.ElementsMatch(t, tt.wantRepos, repoNames(uses.Remote))
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
		got, _ := CrossReference([]ActionRef{{Owner: "github", Repo: "codeql-action", Ref: "v3", Path: "/nonexistent"}}, used)
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

// compositeYAMLWithSteps is an action.yml for a composite action with several uses: steps, for
// mixing remote references and local ones in a single action.
func compositeYAMLWithSteps(uses ...string) string {
	yaml := "runs:\n  using: composite\n  steps:\n"
	for _, use := range uses {
		yaml += "    - uses: " + use + "\n"
	}
	return yaml
}

func TestCrossReference_LocalStepsDeclaredByCompositeActionsAreCollected(t *testing.T) {
	// A relative uses: inside a composite action names a path in the CALLER's repository, so the
	// runner resolves it from the workspace when that step runs rather than into the action cache
	// this command read. It is the same coverage gap as a local step in the workflow, one level
	// down, and only this walk can see it - so it has to come back out of here.
	tests := []struct {
		name       string
		discovered []discoveredAction
		used       JobUses
		want       []LocalUse
	}{
		{
			name: "verify when a composite action declares a local step then it is reported against that action",
			discovered: []discoveredAction{
				{key: "some-org/wrapper@v1", yamls: map[string]string{"": compositeYAML("./scripts/build")}},
			},
			used: JobUses{Remote: []WorkflowUse{{Owner: "some-org", Repo: "wrapper", Ref: "v1"}}},
			want: []LocalUse{{Raw: "./scripts/build", DeclaredBy: "some-org/wrapper@v1"}},
		},
		{
			name: "verify when the local step sits several hops out then the walk still reaches it",
			discovered: []discoveredAction{
				{key: "org/outer@v1", yamls: map[string]string{"": compositeYAML("org/inner@v1")}},
				{key: "org/inner@v1", yamls: map[string]string{"": compositeYAML("./deep/local")}},
			},
			used: JobUses{Remote: []WorkflowUse{{Owner: "org", Repo: "outer", Ref: "v1"}}},
			want: []LocalUse{{Raw: "./deep/local", DeclaredBy: "org/inner@v1"}},
		},
		{
			name: "verify when a composite mixes remote and local steps then only the local one is reported uncovered",
			discovered: []discoveredAction{
				{key: "org/wrapper@v1", yamls: map[string]string{
					"": compositeYAMLWithSteps("actions/setup-node@v4", "./scripts/build"),
				}},
				{key: "actions/setup-node@v4"},
			},
			used: JobUses{Remote: []WorkflowUse{{Owner: "org", Repo: "wrapper", Ref: "v1"}}},
			want: []LocalUse{{Raw: "./scripts/build", DeclaredBy: "org/wrapper@v1"}},
		},
		{
			name: "verify when the metadata lives at a subpath then the local step under it is still found",
			// The root action.yml is not the one invoked, so a local step declared only by the
			// subpath's metadata is exactly the one a root-only read would miss.
			discovered: []discoveredAction{
				{key: "github/codeql-action@v3", yamls: map[string]string{
					"":        compositeYAML("org/from-root@v1"),
					"analyze": compositeYAML("./scripts/analyze"),
				}},
				{key: "org/from-root@v1"},
			},
			used: JobUses{Remote: []WorkflowUse{
				{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "analyze"},
			}},
			want: []LocalUse{{Raw: "./scripts/analyze", DeclaredBy: "github/codeql-action@v3"}},
		},
		{
			name: "verify when the job and a composite both declare local steps then the job's comes first",
			// Order is the report's reading order: what the workflow itself declares is what a
			// reader can act on directly, so it should not be buried under transitive findings.
			discovered: []discoveredAction{
				{key: "org/wrapper@v1", yamls: map[string]string{"": compositeYAML("./from-composite")}},
			},
			used: JobUses{
				Remote: []WorkflowUse{{Owner: "org", Repo: "wrapper", Ref: "v1"}},
				Local:  []LocalUse{{Raw: "./from-workflow"}},
			},
			want: []LocalUse{
				{Raw: "./from-workflow"},
				{Raw: "./from-composite", DeclaredBy: "org/wrapper@v1"},
			},
		},
		{
			name: "verify when two composites declare the same path then both declarers are reported",
			// "./x" resolves against the workspace either way, so it is one action reached two
			// ways - but a reader chasing it needs to know both places it is referenced from.
			discovered: []discoveredAction{
				{key: "org/parent-a@v1", yamls: map[string]string{"": compositeYAML("./shared")}},
				{key: "org/parent-b@v1", yamls: map[string]string{"": compositeYAML("./shared")}},
			},
			used: JobUses{Remote: []WorkflowUse{
				{Owner: "org", Repo: "parent-a", Ref: "v1"},
				{Owner: "org", Repo: "parent-b", Ref: "v1"},
			}},
			want: []LocalUse{
				{Raw: "./shared", DeclaredBy: "org/parent-a@v1"},
				{Raw: "./shared", DeclaredBy: "org/parent-b@v1"},
			},
		},
		{
			name: "verify when one composite declares the same local step twice then it is reported once",
			discovered: []discoveredAction{
				{key: "org/wrapper@v1", yamls: map[string]string{
					"": compositeYAMLWithSteps("./scripts/build", "./scripts/build"),
				}},
			},
			used: JobUses{Remote: []WorkflowUse{{Owner: "org", Repo: "wrapper", Ref: "v1"}}},
			want: []LocalUse{{Raw: "./scripts/build", DeclaredBy: "org/wrapper@v1"}},
		},
		{
			name: "verify when an action.yml cannot be parsed then no local step is invented from it",
			discovered: []discoveredAction{
				{key: "org/wrapper@v1", yamls: map[string]string{"": unreadableYAML}},
			},
			used: JobUses{Remote: []WorkflowUse{{Owner: "org", Repo: "wrapper", Ref: "v1"}}},
			want: nil,
		},
		{
			name: "verify when no composite declares a local step then nothing is reported uncovered",
			discovered: []discoveredAction{
				{key: "org/wrapper@v1", yamls: map[string]string{"": compositeYAML("actions/setup-node@v4")}},
				{key: "actions/setup-node@v4"},
			},
			used: JobUses{Remote: []WorkflowUse{{Owner: "org", Repo: "wrapper", Ref: "v1"}}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := CrossReference(buildDiscovered(t, tt.discovered), tt.used)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCrossReference_LocalStepsDoNotDisturbAttribution(t *testing.T) {
	// The local steps are collected on the same walk that attributes Parent. A composite whose
	// steps are part local, part remote must still attribute the remote ones.
	discovered := buildDiscovered(t, []discoveredAction{
		{key: "org/wrapper@v1", yamls: map[string]string{
			"": compositeYAMLWithSteps("./scripts/build", "org/child@v1"),
		}},
		{key: "org/child@v1"},
	})

	got, localUses := CrossReference(discovered, JobUses{
		Remote: []WorkflowUse{{Owner: "org", Repo: "wrapper", Ref: "v1"}},
	})

	byRepo := map[string]ActionRef{}
	for _, ref := range got {
		byRepo[ref.Repo] = ref
	}
	assert.Equal(t, "org/wrapper@v1", byRepo["child"].Parent, "a local sibling step must not cost the remote one its parent")
	assert.Equal(t, []LocalUse{{Raw: "./scripts/build", DeclaredBy: "org/wrapper@v1"}}, localUses)
}

func TestCrossReference_SubpathChainLongerThanTheCacheIsFullyWalked(t *testing.T) {
	// ONE cache entry reached through a chain of its own subpaths: every hop is a new (key,
	// location) pair on the same key, so the walk needs more rounds than the cache has entries.
	// Any bound derived from the entry count truncates this, and does it invisibly - the
	// unscanned subpath is still listed in Subpaths, so the Action cell reads as complete while
	// the local step that subpath's metadata declares is never collected.
	tests := []struct {
		name          string
		yamls         map[string]string
		wantSubpaths  []string
		wantLocalUses []LocalUse
	}{
		{
			name: "verify when the chain is two subpaths deep then the last one's metadata is read",
			yamls: map[string]string{
				"":   compositeYAML("org/mono/s1@v1"),
				"s1": compositeYAML("org/mono/s2@v1"),
				"s2": compositeYAML("./local-at-s2"),
			},
			wantSubpaths:  []string{"s1", "s2"},
			wantLocalUses: []LocalUse{{Raw: "./local-at-s2", DeclaredBy: "org/mono@v1"}},
		},
		{
			name: "verify when the chain is four subpaths deep then the walk still reaches the end",
			yamls: map[string]string{
				"":   compositeYAML("org/mono/s1@v1"),
				"s1": compositeYAML("org/mono/s2@v1"),
				"s2": compositeYAML("org/mono/s3@v1"),
				"s3": compositeYAML("org/mono/s4@v1"),
				"s4": compositeYAML("./local-at-s4"),
			},
			wantSubpaths:  []string{"s1", "s2", "s3", "s4"},
			wantLocalUses: []LocalUse{{Raw: "./local-at-s4", DeclaredBy: "org/mono@v1"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discovered := buildDiscovered(t, []discoveredAction{{key: "org/mono@v1", yamls: tt.yamls}})

			got, localUses := CrossReference(discovered, JobUses{
				Remote: []WorkflowUse{{Owner: "org", Repo: "mono", Ref: "v1"}},
			})

			assert.Equal(t, tt.wantSubpaths, got[0].Subpaths)
			assert.Equal(t, tt.wantLocalUses, localUses,
				"a subpath listed in the report must have had its metadata read, or the report overstates coverage")
		})
	}
}

func TestCrossReference_ChainLongerThanTheCacheAttributesEveryHop(t *testing.T) {
	// The Parent half of the same shape: two cache entries, but the chain to the second runs
	// through three subpath locations, so attribution needs more rounds than there are entries.
	discovered := buildDiscovered(t, []discoveredAction{
		{key: "org/mono@v1", yamls: map[string]string{
			"":   compositeYAML("org/mono/s1@v1"),
			"s1": compositeYAML("org/mono/s2@v1"),
			"s2": compositeYAML("org/mono/s3@v1"),
			"s3": compositeYAML("org/leaf@v1"),
		}},
		{key: "org/leaf@v1"},
	})

	got, _ := CrossReference(discovered, JobUses{
		Remote: []WorkflowUse{{Owner: "org", Repo: "mono", Ref: "v1"}},
	})

	byRepo := map[string]ActionRef{}
	for _, ref := range got {
		byRepo[ref.Repo] = ref
	}
	assert.Equal(t, "org/mono@v1", byRepo["leaf"].Parent, "every hop must be attributed, however long the chain")
}

func TestCrossReference_SubpathCycleDoesNotHang(t *testing.T) {
	// Termination rests entirely on markLocation. A cycle through SUBPATHS of one key is the
	// hardest case for it: every hop is a new location on a key that is already attributed, so
	// nothing but the location dedup stops the walk.
	discovered := buildDiscovered(t, []discoveredAction{
		{key: "org/mono@v1", yamls: map[string]string{
			"":   compositeYAML("org/mono/s1@v1"),
			"s1": compositeYAML("org/mono/s2@v1"),
			"s2": compositeYAML("org/mono/s1@v1"), // back to s1
		}},
	})
	used := JobUses{Remote: []WorkflowUse{{Owner: "org", Repo: "mono", Ref: "v1"}}}

	done := make(chan []string, 1)
	go func() {
		got, _ := CrossReference(discovered, used)
		done <- got[0].Subpaths
	}()
	select {
	case subpaths := <-done:
		assert.Equal(t, []string{"s1", "s2"}, subpaths, "each location is scanned once, and the cycle adds nothing new")
	case <-time.After(5 * time.Second):
		t.Fatal("CrossReference did not return - a subpath cycle must terminate on markLocation alone")
	}
}
