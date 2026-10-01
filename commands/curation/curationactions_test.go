package curation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/commands/curation/githubactions"
)

const (
	curationActionsFixture = "../../tests/testdata/projects/githubactions/curation-project"
	testGithubRepo         = "my-org/my-repo"
	// derivedWorkflowRef is the shape GITHUB_WORKFLOW_REF carries on a runner; its path component
	// is repo-relative, so it resolves against the working directory.
	derivedWorkflowRef = "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main"
)

// fixtureCacheEntries is what the curation-project fixture's _actions tree holds.
var fixtureCacheEntries = []string{"actions/checkout@v4", "github/codeql-action@v3", "some-org/transitive-action@v1"}

// scriptedDecider stands in for the real decision service. It fails to decide the keys in
// undecidable, rejects the keys in rejected, approves everything else, and records what it was
// asked so a test can assert on curation SCOPE rather than only on the command's exit status.
// Keys are "owner/repo@ref". undecidable wins over rejected: no decision is not a decision.
//
// Run decides actions concurrently, so the recording is locked, and the order of asked is the
// order decisions happened to start in - assert it as a set, not a sequence.
type scriptedDecider struct {
	rejected    []string
	undecidable []string
	// silentlyUndetermined actions come back Undetermined with no error - a decider that gives up
	// without saying why.
	silentlyUndetermined []string

	mu    sync.Mutex
	asked []string
	// vcsRepos records the Artifactory VCS repository each decision was made under, so tests can
	// prove the resolved value actually reached the decider rather than being computed and dropped.
	vcsRepos []string
}

func (d *scriptedDecider) Decide(_ context.Context, artifactoryVcsRepo string, ref githubactions.ActionRef) (githubactions.ActionCurationResult, error) {
	key := ref.Owner + "/" + ref.Repo + "@" + ref.Ref
	d.mu.Lock()
	d.asked = append(d.asked, key)
	d.vcsRepos = append(d.vcsRepos, artifactoryVcsRepo)
	d.mu.Unlock()
	if slices.Contains(d.undecidable, key) {
		return githubactions.ActionCurationResult{}, errors.New("decision service unavailable")
	}
	if slices.Contains(d.silentlyUndetermined, key) {
		return githubactions.ActionCurationResult{Status: githubactions.ActionUndetermined}, nil
	}
	if slices.Contains(d.rejected, key) {
		return githubactions.ActionCurationResult{Status: githubactions.ActionRejected, Notes: "rejected in test"}, nil
	}
	return githubactions.ActionCurationResult{Status: githubactions.ActionApproved}, nil
}

// fixedResolver returns a known key, or err when the mapping API is meant to be unreachable,
// and records what it was asked about.
type fixedResolver struct {
	repo       string
	err        error
	askedAbout []string
}

func (f *fixedResolver) Resolve(_ context.Context, githubRepo string) (string, error) {
	f.askedAbout = append(f.askedAbout, githubRepo)
	if f.err != nil {
		return "", f.err
	}
	return f.repo, nil
}

// pinRunnerEnv fixes every GitHub environment variable the command reads, so a test's result
// never depends on whether it happens to be running inside GitHub Actions - where all of them
// are set, and would otherwise leak into these tests. Pass "" to represent unset.
func pinRunnerEnv(t *testing.T, githubRepo, workflowRef, jobID string) {
	t.Helper()
	t.Setenv(githubactions.GithubRepoEnvVar, githubRepo)
	t.Setenv(githubactions.WorkflowRefEnvVar, workflowRef)
	t.Setenv(githubactions.JobIDEnvVar, jobID)
}

// workflowFileMode selects what SetWorkflowFile points at, if anything.
type workflowFileMode int

const (
	noWorkflowFile       workflowFileMode = iota // omit the flag; resolution falls to the environment
	writtenWorkflowFile                          // the ci.yml runnerSpec wrote into the working directory
	fixtureWorkflowFile                          // the curation-project fixture's own ci.yml
	missingWorkflowFile                          // a path that does not exist
	relativeWorkflowFile                         // a relative path - SetWorkflowFile must be absolute
)

// runnerSpec describes the runner state a test starts from, as data rather than as setup code:
// what sits in the action cache, and what the workspace holds at .github/workflows/ci.yml.
type runnerSpec struct {
	// fixtureCache seeds the cache from the curation-project fixture's _actions tree.
	fixtureCache bool
	// cacheDirs are "owner/repo/ref" entries to create on top of that. Each is an action root, so
	// build writes the <ref>.completed watermark a runner would leave beside it - without one,
	// discovery cannot read a ref from the entry and refuses to curate the cache.
	cacheDirs []string
	// cacheFiles are files to write inside the cache, keyed by "owner/repo/ref/name".
	cacheFiles map[string]string
	// workflowYAML, when set, is written to <workingDir>/.github/workflows/ci.yml - the path
	// derivedWorkflowRef resolves to.
	workflowYAML string
	// unreadableWorkflow strips read permission from that file, for the case where the path
	// resolves and opening it still fails.
	unreadableWorkflow bool
}

func (s runnerSpec) build(t *testing.T) (workingDir, actionsCacheDir string) {
	t.Helper()
	workingDir = t.TempDir()
	actionsCacheDir = filepath.Join(t.TempDir(), "_actions")
	require.NoError(t, os.MkdirAll(actionsCacheDir, 0755))
	if s.fixtureCache {
		require.NoError(t, os.CopyFS(actionsCacheDir, os.DirFS(filepath.Join(curationActionsFixture, "_work", "_actions"))))
	}
	for _, dir := range s.cacheDirs {
		path := filepath.Join(actionsCacheDir, filepath.FromSlash(dir))
		require.NoError(t, os.MkdirAll(path, 0755))
		require.NoError(t, os.WriteFile(path+".completed", []byte("ts"), 0600))
	}
	for name, content := range s.cacheFiles {
		path := filepath.Join(actionsCacheDir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	}
	if s.workflowYAML != "" {
		workflowsDir := filepath.Join(workingDir, ".github", "workflows")
		require.NoError(t, os.MkdirAll(workflowsDir, 0755))
		workflowPath := filepath.Join(workflowsDir, "ci.yml")
		require.NoError(t, os.WriteFile(workflowPath, []byte(s.workflowYAML), 0600))
		if s.unreadableWorkflow {
			require.NoError(t, os.Chmod(workflowPath, 0000))
			// Restored so the temp dir can be cleaned up on platforms that need read access.
			t.Cleanup(func() { _ = os.Chmod(workflowPath, 0600) })
		}
	}
	return workingDir, actionsCacheDir
}

// newCommand builds the command every Run test exercises, wiring SetWorkflowFile per mode.
func (s runnerSpec) newCommand(t *testing.T, mode workflowFileMode, jobID string, decider githubactions.ActionCurationDecider) *CurationActionsCommand {
	t.Helper()
	workingDir, actionsCacheDir := s.build(t)
	cmd := NewCurationActionsCommand().
		SetWorkingDir(workingDir).
		SetActionsCacheDir(actionsCacheDir).
		SetDecider(decider)
	switch mode {
	case writtenWorkflowFile:
		cmd.SetWorkflowFile(filepath.Join(workingDir, ".github", "workflows", "ci.yml"))
	case fixtureWorkflowFile:
		// Absolute on purpose: a relative SetWorkflowFile resolves against the working directory,
		// which here is a temp dir, not the package the fixture path is written relative to.
		abs, err := filepath.Abs(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml"))
		require.NoError(t, err)
		cmd.SetWorkflowFile(abs)
	case missingWorkflowFile:
		cmd.SetWorkflowFile(filepath.Join(workingDir, "no-such-workflow.yml"))
	case relativeWorkflowFile:
		cmd.SetWorkflowFile(filepath.Join(".github", "workflows", "ci.yml"))
	case noWorkflowFile:
	}
	if jobID != "" {
		cmd.SetJobID(jobID)
	}
	return cmd
}

func TestCurationActionsCommand_Run_CurationScope(t *testing.T) {
	// What actually gets decided, per resolution path. The invariant across every row: the
	// runner's cache IS this job's action list, so every entry in it is decided regardless of
	// what the workflow file does or does not explain.
	const twoJobs = "jobs:\n" +
		"  build:\n    steps:\n      - uses: actions/checkout@v4\n" +
		"  publish:\n    steps:\n      - uses: some-other-org/publisher@v9\n"

	tests := []struct {
		name        string
		spec        runnerSpec
		mode        workflowFileMode
		jobID       string
		envWorkflow string
		wantAsked   []string
	}{
		{
			name:      "verify when no workflow file is identified then every cache entry is still decided",
			spec:      runnerSpec{fixtureCache: true},
			wantAsked: fixtureCacheEntries,
		},
		{
			name:      "verify when an entry appears in no workflow file then it is still decided",
			spec:      runnerSpec{cacheDirs: []string{"some-org/unreferenced/v9"}},
			wantAsked: []string{"some-org/unreferenced@v9"},
		},
		{
			name: "verify when only GITHUB_WORKFLOW_REF identifies the workflow then attribution still runs",
			spec: runnerSpec{fixtureCache: true, workflowYAML: "jobs:\n  build:\n    steps:\n" +
				"      - uses: actions/checkout@v4\n      - uses: github/codeql-action/analyze@v3\n"},
			jobID:       "build",
			envWorkflow: derivedWorkflowRef,
			wantAsked:   fixtureCacheEntries,
		},
		{
			name:        "verify when a sibling job declares an action then it is decided but not attributed",
			spec:        runnerSpec{cacheDirs: []string{"actions/checkout/v4", "some-other-org/publisher/v9"}, workflowYAML: twoJobs},
			jobID:       "build",
			envWorkflow: derivedWorkflowRef,
			wantAsked:   []string{"actions/checkout@v4", "some-other-org/publisher@v9"},
		},
		{
			name: "verify when the cache holds the action delivering this check then it is curated too",
			spec: runnerSpec{
				cacheDirs:    []string{"jfrog/setup-jfrog-cli/v4", "actions/checkout/v4"},
				workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: jfrog/setup-jfrog-cli@v4\n      - uses: actions/checkout@v4\n",
			},
			mode:      writtenWorkflowFile,
			jobID:     "build",
			wantAsked: []string{"actions/checkout@v4", "jfrog/setup-jfrog-cli@v4"},
		},
		{
			// The reusable-workflow case. Attributing from the file's other jobs once curated an
			// action only they declared, and dropped one this job really used.
			name: "verify when the workflow does not declare this job then this cache is curated and other jobs ignored",
			spec: runnerSpec{
				cacheDirs:    []string{"actions/checkout/v4", "actions/setup-node/v4"},
				workflowYAML: "jobs:\n  some-other-job:\n    steps:\n      - uses: actions/checkout@v4\n",
			},
			mode:      writtenWorkflowFile,
			jobID:     "the-job-this-command-runs-in",
			wantAsked: []string{"actions/checkout@v4", "actions/setup-node@v4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, tt.envWorkflow, "")
			decider := &scriptedDecider{}

			require.NoError(t, tt.spec.newCommand(t, tt.mode, tt.jobID, decider).Run())

			assert.ElementsMatch(t, tt.wantAsked, decider.asked,
				"every entry the runner resolved into this job's cache must be decided")
		})
	}
}

func TestCurationActionsCommand_Run_ExitStatus(t *testing.T) {
	// The job either continues or it does not. A Rejected action must fail it, whether or not
	// attribution could explain why that action is in the cache.
	tests := []struct {
		name     string
		spec     runnerSpec
		mode     workflowFileMode
		jobID    string
		rejected []string
		wantErr  bool
	}{
		{
			// SetJobID is what puts this in ATTRIBUTED mode - a workflow file alone is not enough,
			// since attribution also needs to know which job it is describing.
			name:  "verify when every action is approved then the command succeeds",
			spec:  runnerSpec{fixtureCache: true},
			mode:  fixtureWorkflowFile,
			jobID: "build",
		},
		{
			name:     "verify when an action is rejected then the command fails",
			spec:     runnerSpec{fixtureCache: true},
			mode:     fixtureWorkflowFile,
			rejected: []string{"some-org/transitive-action@v1"},
			wantErr:  true,
		},
		{
			// It will execute, so failing to explain why it is there is no grounds for skipping it.
			name:     "verify when an entry no workflow explains is rejected then the command fails",
			spec:     runnerSpec{fixtureCache: true, cacheDirs: []string{"some-other-org/unexplained-action/v9"}},
			mode:     fixtureWorkflowFile,
			jobID:    "build",
			rejected: []string{"some-other-org/unexplained-action@v9"},
			wantErr:  true,
		},
		{
			// Not "nothing to curate": the command is invoked by an action, which is itself a cache
			// entry, so an empty cache means the wrong directory was read. Passing off it would be
			// indistinguishable from a real pass.
			name:    "verify when the cache is empty then the command fails rather than reporting a pass",
			spec:    runnerSpec{},
			mode:    fixtureWorkflowFile,
			wantErr: true,
		},
		{
			// No action is rejected here: the cache holds an entry the walk cannot resolve to an
			// identity, and curating the rest would report a clean run over an action whose status
			// was never established. feature/my-branch carries no watermark while v4 does.
			name: "verify when a cache entry cannot be accounted for then the command fails without deciding",
			spec: runnerSpec{
				cacheDirs: []string{"actions/checkout/v4"},
				// Written through cacheFiles so the directory exists with no watermark beside it.
				cacheFiles: map[string]string{"actions/checkout/feature/my-branch/action.yml": "runs:\n  using: node20\n"},
			},
			mode:    noWorkflowFile,
			wantErr: true,
		},
		{
			// Dropping the unattributable entry once turned a Rejected action into a green build.
			name: "verify when the workflow parses to no action reference then a rejected cache entry still fails",
			spec: runnerSpec{
				cacheDirs:    []string{"evil-org/backdoor/v1"},
				workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: ./.github/actions/setup\n",
			},
			mode:     writtenWorkflowFile,
			jobID:    "build",
			rejected: []string{"evil-org/backdoor@v1"},
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")
			decider := &scriptedDecider{rejected: tt.rejected}

			err := tt.spec.newCommand(t, tt.mode, tt.jobID, decider).Run()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestCurationActionsCommand_Run_UndecidableActions(t *testing.T) {
	twoActions := runnerSpec{cacheDirs: []string{"actions/checkout/v4", "actions/setup-node/v4"}}

	tests := []struct {
		name               string
		spec               runnerSpec
		mode               workflowFileMode
		undecidable        []string
		wantErrContains    []string
		wantErrNotContains []string
		wantApprovedRows   int
	}{
		{
			name:            "verify when a decision fails then the error names the action and the cause",
			spec:            runnerSpec{fixtureCache: true},
			mode:            fixtureWorkflowFile,
			undecidable:     fixtureCacheEntries,
			wantErrContains: []string{"deciding curation status for", "decision service unavailable"},
		},
		{
			name:            "verify when several decisions fail then the error names every one of them",
			spec:            twoActions,
			undecidable:     []string{"actions/checkout@v4", "actions/setup-node@v4"},
			wantErrContains: []string{"actions/checkout@v4", "actions/setup-node@v4"},
		},
		{
			name:               "verify when only one decision fails then the error names it alone and the other is still reported",
			spec:               twoActions,
			undecidable:        []string{"actions/setup-node@v4"},
			wantErrContains:    []string{"actions/setup-node@v4"},
			wantErrNotContains: []string{"actions/checkout@v4"},
			wantApprovedRows:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")
			// Recording is a no-op unless this is set.
			summaryDir := t.TempDir()
			t.Setenv(coreutils.SummaryOutputDirPathEnv, summaryDir)
			decider := &scriptedDecider{undecidable: tt.undecidable}

			report, err := captureReport(t, tt.spec.newCommand(t, tt.mode, "", decider))

			require.Error(t, err)
			for _, want := range tt.wantErrContains {
				assert.ErrorContains(t, err, want)
			}
			for _, notWant := range tt.wantErrNotContains {
				assert.NotContains(t, err.Error(), notWant)
			}
			assert.Equal(t, len(tt.undecidable), strings.Count(report, "| Undetermined |"),
				"every undecidable action must be a row, not omitted:\n%s", report)
			assert.Equal(t, tt.wantApprovedRows, strings.Count(report, "| Approved |"),
				"the actions that were decided must still be reported:\n%s", report)
			assert.Contains(t, report, "decision service unavailable", "an Undetermined row must carry its cause")
			entries, readErr := os.ReadDir(summaryDir)
			require.NoError(t, readErr)
			assert.NotEmpty(t, entries, "the job summary must be recorded even when an action could not be decided")
		})
	}
}

func TestCurationActionsCommand_Run_AttributedAndStructureOnlyCurateTheSameSet(t *testing.T) {
	// The two modes differ in report detail, never in coverage. Same cache, same job: both must
	// decide every entry, including one no workflow references.
	spec := runnerSpec{fixtureCache: true, cacheDirs: []string{"some-org/unreferenced/v9"}}
	wantAsked := append(slices.Clone(fixtureCacheEntries), "some-org/unreferenced@v9")

	tests := []struct {
		name  string
		mode  workflowFileMode
		jobID string
	}{
		{name: "verify when a workflow file is supplied then every cache entry is decided", mode: fixtureWorkflowFile, jobID: "build"},
		{name: "verify when no workflow file is supplied then the same entries are decided", mode: noWorkflowFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")
			decider := &scriptedDecider{}

			require.NoError(t, spec.newCommand(t, tt.mode, tt.jobID, decider).Run())

			assert.ElementsMatch(t, wantAsked, decider.asked)
		})
	}
}

func TestCurationActionsCommand_Run_WorkflowFileResolution(t *testing.T) {
	// The branches of parseWorkflowUses, exercised through Run in the shape a real runner
	// produces: _actions populated, workspace empty because checkout has not run.
	oneAction := []string{"actions/checkout/v4"}

	tests := []struct {
		name            string
		spec            runnerSpec
		mode            workflowFileMode
		workflowRef     string
		wantAsked       []string
		wantErrContains string
	}{
		{
			// GITHUB_WORKFLOW_REF is always set on a runner, so without this fallback every job
			// that did not pass SetWorkflowFile would fail here.
			name:        "verify when the derived workflow path is absent then curation falls back to structure-only",
			spec:        runnerSpec{cacheDirs: oneAction},
			workflowRef: derivedWorkflowRef,
			wantAsked:   []string{"actions/checkout@v4"},
		},
		{
			name:      "verify when an explicit workflow path is absent then curation falls back to structure-only",
			spec:      runnerSpec{cacheDirs: oneAction},
			mode:      missingWorkflowFile,
			wantAsked: []string{"actions/checkout@v4"},
		},
		{
			// The one thing that still fails: a malformed flag, rejected before anything is read.
			// SetWorkflowFile is an explicit, single-file assertion; only the derived path
			// (GITHUB_WORKFLOW_REF) resolves against the working directory.
			name:            "verify when an explicit workflow path is relative then the command fails",
			spec:            runnerSpec{cacheDirs: oneAction},
			mode:            relativeWorkflowFile,
			wantErrContains: "must be an absolute path",
		},
		{
			// A workflow this parser cannot read costs attribution and nothing else, so the cache
			// is still curated in full.
			name:        "verify when the derived workflow file is malformed then curation falls back to structure-only",
			spec:        runnerSpec{cacheDirs: oneAction, workflowYAML: "jobs:\n\t- this is not valid yaml\n"},
			workflowRef: derivedWorkflowRef,
			wantAsked:   []string{"actions/checkout@v4"},
		},
		{
			// Naming the file asserts it exists, not that this parser can read it - so the same
			// divergence degrades the same way whichever route resolved the path.
			name:      "verify when an explicit workflow file is malformed then curation falls back to structure-only",
			spec:      runnerSpec{cacheDirs: oneAction, workflowYAML: "jobs:\n\t- this is not valid yaml\n"},
			mode:      writtenWorkflowFile,
			wantAsked: []string{"actions/checkout@v4"},
		},
		{
			name:        "verify when the derived workflow file is valid then attribution runs normally",
			spec:        runnerSpec{cacheDirs: oneAction, workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"},
			workflowRef: derivedWorkflowRef,
			wantAsked:   []string{"actions/checkout@v4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, tt.workflowRef, "build")
			decider := &scriptedDecider{}

			err := tt.spec.newCommand(t, tt.mode, "", decider).Run()

			if tt.wantErrContains != "" {
				assert.ErrorContains(t, err, tt.wantErrContains)
				assert.Empty(t, decider.asked)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantAsked, decider.asked,
				"every entry in the cache must be curated, whichever branch resolution took")
		})
	}
}

func TestCurationActionsCommand_Run_ArtifactoryVcsRepoResolution(t *testing.T) {
	spec := runnerSpec{cacheDirs: []string{"actions/checkout/v4", "actions/setup-node/v4"}}

	tests := []struct {
		name         string
		envRepo      string
		flagRepo     string
		resolverRepo string
		resolverErr  error
		// wantAskedAbout is what the mapping API was called with - once per run, never per action.
		wantAskedAbout []string
		// wantVcsRepos is the repository that reached each decision, so a resolved value that is
		// computed and then dropped fails here rather than passing silently.
		wantVcsRepos    []string
		wantErrContains []string
	}{
		{
			name:           "verify when GITHUB_REPOSITORY is set then the resolved repository reaches every decision",
			envRepo:        testGithubRepo,
			resolverRepo:   "my-org-github-remote",
			wantAskedAbout: []string{testGithubRepo},
			wantVcsRepos:   []string{"my-org-github-remote", "my-org-github-remote"},
		},
		{
			name:           "verify when the repository is set explicitly then it overrides the environment",
			envRepo:        testGithubRepo,
			flagRepo:       "flag-org/flag-repo",
			resolverRepo:   "resolved",
			wantAskedAbout: []string{"flag-org/flag-repo"},
			wantVcsRepos:   []string{"resolved", "resolved"},
		},
		{
			name:            "verify when repository resolution fails then the command fails and nothing is decided",
			envRepo:         testGithubRepo,
			resolverErr:     errors.New("mapping service unavailable"),
			wantAskedAbout:  []string{testGithubRepo},
			wantErrContains: []string{"resolving the Artifactory VCS repository governing", "mapping service unavailable"},
		},
		{
			name:            "verify when no GitHub repository is known then the error names the variable that supplies it",
			envRepo:         "", // GITHUB_REPOSITORY unset, e.g. a local run
			wantErrContains: []string{githubactions.GithubRepoEnvVar},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, tt.envRepo, "", "")
			resolver := &fixedResolver{repo: tt.resolverRepo, err: tt.resolverErr}
			decider := &scriptedDecider{}
			cmd := spec.newCommand(t, noWorkflowFile, "", decider).SetVcsRepoResolver(resolver)
			if tt.flagRepo != "" {
				cmd.SetGithubRepo(tt.flagRepo)
			}

			err := cmd.Run()

			assert.Equal(t, tt.wantAskedAbout, resolver.askedAbout, "resolution happens once per run, not once per action")
			if len(tt.wantErrContains) > 0 {
				for _, want := range tt.wantErrContains {
					assert.ErrorContains(t, err, want)
				}
				assert.Empty(t, decider.asked, "nothing may be decided when the governing repository is unknown")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantVcsRepos, decider.vcsRepos, "the resolved repository must reach every decision")
		})
	}
}

func TestCurationActionsCommand_Run_EmptyCacheFailsBeforeResolving(t *testing.T) {
	pinRunnerEnv(t, testGithubRepo, "", "")
	resolver := &fixedResolver{repo: "unused"}

	err := runnerSpec{}.newCommand(t, noWorkflowFile, "", &scriptedDecider{}).
		SetVcsRepoResolver(resolver).Run()

	assert.ErrorContains(t, err, githubactions.RunnerWorkspaceEnvVar,
		"the failure must name the variable the cache location comes from")
	assert.Empty(t, resolver.askedAbout, "a cache that cannot be read must fail before any mapping call")
}

func TestCurationActionsCommand_Run_ActionsAttributionCannotExplainAreStillCurated(t *testing.T) {
	// The two ways the runner's cache can hold an entry this command cannot trace back to a
	// uses: line. Both once caused the entry to be dropped, so the job passed with an action
	// that executes having never been decided.
	tests := []struct {
		name string
		spec runnerSpec
	}{
		{
			name: "verify when a local composite action's child is already in the cache then it is still decided",
			// uses: ./... is read from the workspace, so there is nothing to walk outward from -
			// the entry is unattributable, and must still be curated. This covers only the case
			// where the runner had already resolved the child by the time this command ran; the
			// case where it has not is TestCurationActionsCommand_Run_LocalCompositeActionIsDeclaredUncovered.
			spec: runnerSpec{
				cacheDirs:    []string{"actions/setup-node/v4"},
				workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: ./.github/actions/setup\n",
			},
		},
		{
			name: "verify when a composite action.yml cannot be parsed then its child is still decided",
			// Duplicate mapping keys: accepted by GitHub's runner, rejected by yaml.v3.
			spec: runnerSpec{
				cacheDirs: []string{"actions/setup-node/v4", "some-org/wrapper/v1"},
				cacheFiles: map[string]string{
					"some-org/wrapper/v1/action.yml": "name: w\nname: w\nruns:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v4\n",
				},
				workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: some-org/wrapper@v1\n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")
			decider := &scriptedDecider{}

			require.NoError(t, tt.spec.newCommand(t, writtenWorkflowFile, "build", decider).Run())

			assert.Contains(t, decider.asked, "actions/setup-node@v4",
				"an action the runner resolved will execute, so it must be decided even when it cannot be attributed")
		})
	}
}

// captureReport runs cmd with the logger redirected, and returns everything it wrote. The
// report and its caveat only exist as log output, so that is where a test has to read them.
func captureReport(t *testing.T, cmd *CurationActionsCommand) (report string, err error) {
	t.Helper()
	var buf bytes.Buffer
	original := log.Logger
	log.SetLogger(log.NewLogger(log.INFO, &buf))
	defer log.SetLogger(original)
	err = cmd.Run()
	return buf.String(), err
}

func TestCurationActionsCommand_Run_LocalCompositeActionIsDeclaredUncovered(t *testing.T) {
	// The gap this caveat exists for, in the shape that actually bites: the job declares a local
	// composite action, and the action it pulls in is NOT in the cache, because the runner cannot
	// resolve a local action's own references until the workspace is checked out - it downloads
	// them when that step runs, after this command has read the cache.
	//
	// Nothing here can be decided, so the command is right to pass. What it must not do is let an
	// all-Approved table stand as the whole account of what the job will execute.
	pinRunnerEnv(t, testGithubRepo, "", "")
	decider := &scriptedDecider{}
	spec := runnerSpec{
		cacheDirs: []string{"actions/checkout/v4"},
		workflowYAML: "jobs:\n  build:\n    steps:\n" +
			"      - uses: actions/checkout@v4\n" +
			"      - uses: ./.github/actions/setup\n",
	}

	report, err := captureReport(t, spec.newCommand(t, writtenWorkflowFile, "build", decider))

	require.NoError(t, err, "nothing was rejected, so the gate is right to open - the caveat is what keeps that honest")
	assert.Equal(t, []string{"actions/checkout@v4"}, decider.asked,
		"the local action's own references are not in the cache yet, so there is nothing more to decide")
	assert.Contains(t, report, "./.github/actions/setup",
		"the report must name the local step whose references it never saw")
	assert.Contains(t, report, "not curated here")
}

func TestCurationActionsCommand_Run_LocalStepInsideACompositeActionIsDeclaredUncovered(t *testing.T) {
	// One level down from the workflow: a third-party composite action in the cache declares
	// "uses: ./...". That path resolves against this repository's checkout, not the action's own
	// directory, so the runner fetches whatever it references when the step runs - after this
	// command read the cache. The composite itself is curated; what it reaches that way is not.
	pinRunnerEnv(t, testGithubRepo, "", "")
	decider := &scriptedDecider{}
	spec := runnerSpec{
		cacheDirs: []string{"some-org/wrapper/v1"},
		cacheFiles: map[string]string{
			"some-org/wrapper/v1/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/build\n",
		},
		workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: some-org/wrapper@v1\n",
	}

	report, err := captureReport(t, spec.newCommand(t, writtenWorkflowFile, "build", decider))

	require.NoError(t, err)
	assert.Equal(t, []string{"some-org/wrapper@v1"}, decider.asked, "the composite action itself is still curated")
	assert.Contains(t, report, "./.github/actions/build")
	assert.Contains(t, report, "declared by some-org/wrapper@v1",
		"the path names a directory in this repository, so the report has to say which action reached it")
}

func TestCurationActionsCommand_Run_CoverageCaveatPerResolutionPath(t *testing.T) {
	// The caveat has to track what was actually knowable on each path, not merely appear.
	tests := []struct {
		name            string
		spec            runnerSpec
		mode            workflowFileMode
		jobID           string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "verify when the workflow declares no local action then the report claims full coverage",
			spec: runnerSpec{
				cacheDirs:    []string{"actions/checkout/v4"},
				workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
			},
			mode:            writtenWorkflowFile,
			jobID:           "build",
			wantNotContains: []string{"Not covered"},
		},
		{
			name: "verify when no workflow file is available then the caveat is unconditional",
			// The ordinary case on a runner: the check runs before the checkout, so the file is
			// not on disk and the command cannot tell whether a local action is declared.
			spec:         runnerSpec{cacheDirs: []string{"actions/checkout/v4"}},
			mode:         noWorkflowFile,
			wantContains: []string{"Not covered", "no workflow file was available"},
		},
		{
			name: "verify when the workflow does not declare the job then the caveat is unconditional",
			// Attribution failed for a different reason, but the command knows exactly as little.
			spec: runnerSpec{
				cacheDirs:    []string{"actions/checkout/v4"},
				workflowYAML: "jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@v4\n",
			},
			mode:         writtenWorkflowFile,
			jobID:        "build",
			wantContains: []string{"Not covered", "no workflow file was available"},
		},
		{
			name: "verify when a composite declares a local step then the caveat names it and its declarer",
			spec: runnerSpec{
				cacheDirs: []string{"some-org/wrapper/v1"},
				cacheFiles: map[string]string{
					"some-org/wrapper/v1/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: ./scripts/build\n",
				},
				workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: some-org/wrapper@v1\n",
			},
			mode:         writtenWorkflowFile,
			jobID:        "build",
			wantContains: []string{"Not covered", "./scripts/build", "declared by some-org/wrapper@v1"},
		},
		{
			name: "verify when attribution is unavailable then a composite's local step is not detected at all",
			// Detection needs the walk, and the walk needs a workflow file. Without one the
			// command genuinely does not know - which is why that caveat is unconditional rather
			// than a list, and why it must not name a path it never read.
			spec: runnerSpec{
				cacheDirs: []string{"some-org/wrapper/v1"},
				cacheFiles: map[string]string{
					"some-org/wrapper/v1/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: ./scripts/build\n",
				},
			},
			mode:            noWorkflowFile,
			wantContains:    []string{"Not covered", "no workflow file was available"},
			wantNotContains: []string{"./scripts/build"},
		},
		{
			name: "verify when a sibling job declares the local action then this job does not claim it",
			// Each job runs on its own runner. A local step in another job says nothing about the
			// coverage of this one, and naming it here would be a false lead.
			spec: runnerSpec{
				cacheDirs: []string{"actions/checkout/v4"},
				workflowYAML: "jobs:\n" +
					"  build:\n    steps:\n      - uses: actions/checkout@v4\n" +
					"  publish:\n    steps:\n      - uses: ./.github/actions/release\n",
			},
			mode:            writtenWorkflowFile,
			jobID:           "build",
			wantNotContains: []string{"Not covered", "./.github/actions/release"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")

			report, err := captureReport(t, tt.spec.newCommand(t, tt.mode, tt.jobID, &scriptedDecider{}))

			require.NoError(t, err)
			for _, want := range tt.wantContains {
				assert.Contains(t, report, want)
			}
			for _, notWant := range tt.wantNotContains {
				assert.NotContains(t, report, notWant)
			}
		})
	}
}

func TestCurationActionsCommand_Run_EveryParentNamesARowInTheTable(t *testing.T) {
	// Parent is a cross-reference into the report's own rows, so a row it names has to be there.
	// The action delivering this check is the one that could break that: it is a parent like any
	// other, and it is curated like any other rather than being filtered out of the table after
	// attribution has already pointed at it.
	pinRunnerEnv(t, testGithubRepo, "", "")
	decider := &scriptedDecider{}
	spec := runnerSpec{
		cacheDirs: []string{"jfrog/setup-jfrog-cli/v4", "some-org/pulled-by-delivery/v1"},
		cacheFiles: map[string]string{
			"jfrog/setup-jfrog-cli/v4/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: some-org/pulled-by-delivery@v1\n",
		},
		workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: jfrog/setup-jfrog-cli@v4\n",
	}

	report, err := captureReport(t, spec.newCommand(t, writtenWorkflowFile, "build", decider))

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"jfrog/setup-jfrog-cli@v4", "some-org/pulled-by-delivery@v1"}, decider.asked,
		"no action is exempt from the gate, including the one that installed this CLI")
	// The child names its parent, and that parent has a row of its own above it.
	assert.Contains(t, report, "| some-org/pulled-by-delivery | v1 | jfrog/setup-jfrog-cli@v4 |")
	assert.Contains(t, report, "| jfrog/setup-jfrog-cli | v4 |")
}

func TestCurationActionsCommand_Run_UnreadableWorkflowFileFallsBackRatherThanFailing(t *testing.T) {
	// The path resolves and opening it still fails - a permission error rather than an absent
	// file. It reaches the command as neither ErrNotExist nor a parse error, which is the one
	// route that used to abort the run. Curation is the job, so it degrades like every other
	// workflow-file problem.
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod on Windows only toggles the read-only attribute, so reads are not denied and the failure cannot be produced")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions do not deny access, so the failure cannot be produced")
	}
	pinRunnerEnv(t, testGithubRepo, derivedWorkflowRef, "")
	decider := &scriptedDecider{}
	spec := runnerSpec{
		cacheDirs:          []string{"actions/checkout/v4"},
		workflowYAML:       "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
		unreadableWorkflow: true,
	}

	report, err := captureReport(t, spec.newCommand(t, noWorkflowFile, "build", decider))

	require.NoError(t, err, "a job gated on this command must not fail because the workflow file could not be opened")
	assert.Equal(t, []string{"actions/checkout@v4"}, decider.asked, "the cache is curated in full regardless")
	// Attribution is gone, and the report says so rather than passing silently.
	assert.NotContains(t, report, "| Action | Ref | Parent |", "a run with no attribution must not render a Parent column")
	assert.Contains(t, report, "no workflow file was available")
}

func TestCurationActionsCommand_Run_ErrorHandlingHookAppliesToFailuresNotOutcomes(t *testing.T) {
	// errorutils.CheckError is a hook, not a wrapper: it is the identity function until
	// JFROG_CLI_ERROR_HANDLING=panic replaces it with one that panics at the error site, which
	// is how this repository gets a stack trace pointing at an origin. That makes WHERE it is
	// applied the whole decision - an operational failure should reach it, while a normal
	// outcome expressed as an error must not, or debugging with that flag set turns working
	// runs into panics.
	origCheckError := errorutils.CheckError
	errorutils.CheckError = func(err error) error {
		if err != nil {
			panic(err)
		}
		return nil
	}
	defer func() { errorutils.CheckError = origCheckError }()

	tests := []struct {
		name            string
		spec            runnerSpec
		mode            workflowFileMode
		rejected        []string
		undecidable     []string
		unresolvableVcs bool
		wantPanic       bool
		wantErr         bool
	}{
		{
			// The gate's verdict. The command worked exactly as designed; the error is only how
			// a rejection reaches the exit code.
			name:     "verify when an action is rejected then the verdict is not treated as a failure",
			spec:     runnerSpec{cacheDirs: []string{"evil-org/backdoor/v1"}},
			mode:     noWorkflowFile,
			rejected: []string{"evil-org/backdoor@v1"},
			wantErr:  true,
		},
		{
			// The ordinary case on a runner: no checkout yet, so the workflow file is absent and
			// the run degrades to structure-only. Nothing failed.
			name: "verify when the workflow file is absent then degrading is not treated as a failure",
			spec: runnerSpec{cacheDirs: []string{"actions/checkout/v4"}},
			mode: missingWorkflowFile,
		},
		{
			// A remote seam. Reaching no verdict is an anticipated condition of calling a
			// service, and the fail-open / fail-close setting is what decides its consequence -
			// so it must not crash, least of all on a transient fault.
			name:        "verify when a decision cannot be reached then the remote failure is not treated as a failure of this command",
			spec:        runnerSpec{cacheDirs: []string{"actions/checkout/v4"}},
			mode:        noWorkflowFile,
			undecidable: []string{"actions/checkout@v4"},
			wantErr:     true,
		},
		{
			// The other remote seam, for the same reason.
			name:            "verify when the vcs repository cannot be resolved then the remote failure does not crash",
			spec:            runnerSpec{cacheDirs: []string{"actions/checkout/v4"}},
			mode:            noWorkflowFile,
			unresolvableVcs: true,
			wantErr:         true,
		},
		{
			// An operational failure: the cache holds an entry that cannot be resolved to an
			// action, so the run cannot be reported as curated. This one must reach the hook.
			name: "verify when the cache cannot be accounted for then the failure reaches the hook",
			spec: runnerSpec{
				cacheDirs:  []string{"actions/checkout/v4"},
				cacheFiles: map[string]string{"actions/checkout/feature/my-branch/action.yml": "runs:\n  using: node20\n"},
			},
			mode:      noWorkflowFile,
			wantPanic: true,
		},
		{
			// A malformed flag, rejected before anything is read.
			name:      "verify when the workflow path is relative then the usage error reaches the hook",
			spec:      runnerSpec{cacheDirs: []string{"actions/checkout/v4"}},
			mode:      relativeWorkflowFile,
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")
			run := func() error {
				cmd := tt.spec.newCommand(t, tt.mode, "",
					&scriptedDecider{rejected: tt.rejected, undecidable: tt.undecidable})
				if tt.unresolvableVcs {
					cmd.SetVcsRepoResolver(&fixedResolver{err: errors.New("mapping API unreachable")})
				}
				return cmd.Run()
			}

			if tt.wantPanic {
				assert.Panics(t, func() { _ = run() })
				return
			}
			var err error
			require.NotPanics(t, func() { err = run() })
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// probeDecider approves or refuses actions on a script while measuring concurrency: how many
// decisions were in flight at once, and how many were made.
type probeDecider struct {
	// hold is how long a decision takes, per action; nil means immediate.
	hold func(ref githubactions.ActionRef) time.Duration
	// barrier, when set, holds every decision until that many are in flight at once, then releases
	// them all - proof of parallelism that does not depend on sleeps overlapping.
	barrier     int32
	release     chan struct{}
	releaseOnce sync.Once
	// denied actions fail as an access failure, keyed "owner/repo@ref"; "*" denies every action.
	denied []string
	// rejected actions are Rejected, keyed "owner/repo@ref".
	rejected []string

	calls       atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
}

func (p *probeDecider) Decide(_ context.Context, _ string, ref githubactions.ActionRef) (githubactions.ActionCurationResult, error) {
	p.calls.Add(1)
	now := p.inFlight.Add(1)
	defer p.inFlight.Add(-1)
	for {
		seen := p.maxInFlight.Load()
		if now <= seen || p.maxInFlight.CompareAndSwap(seen, now) {
			break
		}
	}
	if p.hold != nil {
		time.Sleep(p.hold(ref))
	}
	if p.barrier > 0 {
		if now >= p.barrier {
			p.releaseOnce.Do(func() { close(p.release) })
		}
		select {
		case <-p.release:
		case <-time.After(5 * time.Second):
			// Only stops a serialized runner from hanging the test; the maxInFlight assertion fails it.
		}
	}
	key := ref.Owner + "/" + ref.Repo + "@" + ref.Ref
	if slices.Contains(p.denied, "*") || slices.Contains(p.denied, key) {
		return githubactions.ActionCurationResult{}, fmt.Errorf("fetching %s: %w", key, githubactions.ErrAccessDenied)
	}
	if slices.Contains(p.rejected, key) {
		return githubactions.ActionCurationResult{Status: githubactions.ActionRejected, Notes: "rejected in test"}, nil
	}
	return githubactions.ActionCurationResult{Status: githubactions.ActionApproved}, nil
}

// orderedActions is a cache of n actions that discovery lists in name order: a-org, b-org, ...
func orderedActions(n int) (runnerSpec, []string) {
	var spec runnerSpec
	var keys []string
	for i := range n {
		owner := string(rune('a'+i)) + "-org"
		spec.cacheDirs = append(spec.cacheDirs, owner+"/act/v1")
		keys = append(keys, owner+"/act@v1")
	}
	return spec, keys
}

func TestCurationActionsCommand_Run_StopsOnAccessFailure(t *testing.T) {
	t.Run("verify when one action is refused access with a single thread then no later action is decided and nothing is reported", func(t *testing.T) {
		pinRunnerEnv(t, testGithubRepo, "", "")
		summaryDir := t.TempDir()
		t.Setenv(coreutils.SummaryOutputDirPathEnv, summaryDir)
		spec, keys := orderedActions(5)
		decider := &probeDecider{denied: []string{keys[1]}} // the 2nd of 5 in discovery order

		report, err := captureReport(t, spec.newCommand(t, noWorkflowFile, "", decider).SetParallelRequests(1))

		require.Error(t, err)
		assert.True(t, errors.Is(err, githubactions.ErrAccessDenied), "Run() error = %v, want ErrAccessDenied", err)
		assert.LessOrEqual(t, decider.calls.Load(), int32(2), "no action after the refused one may be decided")
		assert.NotContains(t, report, "GitHub Actions Curation Report", "a run stopped part-way must not report")
		entries, readErr := os.ReadDir(summaryDir)
		require.NoError(t, readErr)
		assert.Empty(t, entries, "a run stopped part-way must not record a job summary")
	})
	t.Run("verify when access is refused with several threads then the run stops well short of every action", func(t *testing.T) {
		pinRunnerEnv(t, testGithubRepo, "", "")
		const threads = 3
		spec, _ := orderedActions(20)
		decider := &probeDecider{denied: []string{"*"}}

		err := spec.newCommand(t, noWorkflowFile, "", decider).SetParallelRequests(threads).Run()

		require.Error(t, err)
		assert.True(t, errors.Is(err, githubactions.ErrAccessDenied), "Run() error = %v, want ErrAccessDenied", err)
		// Up to threads decisions are in flight when the first refusal lands, and each other worker
		// may begin at most one more before it sees the stop; 20 would mean nothing stopped.
		assert.LessOrEqual(t, decider.calls.Load(), int32(2*threads), "the run did not stop on the access failure")
		assert.Equal(t, 1, strings.Count(err.Error(), githubactions.ErrAccessDenied.Error()),
			"one access failure is reported, not one per action: %v", err)
	})
	t.Run("verify when an action is rejected then the run does not stop and every action is decided", func(t *testing.T) {
		pinRunnerEnv(t, testGithubRepo, "", "")
		spec, keys := orderedActions(5)
		decider := &probeDecider{rejected: []string{keys[1]}}

		report, err := captureReport(t, spec.newCommand(t, noWorkflowFile, "", decider).SetParallelRequests(1))

		require.Error(t, err)
		assert.False(t, errors.Is(err, githubactions.ErrAccessDenied), "a curation block must not stop the run: %v", err)
		assert.Equal(t, int32(5), decider.calls.Load(), "every action must be decided after a rejection")
		assert.Equal(t, 4, strings.Count(report, "| Approved |"))
		assert.Equal(t, 1, strings.Count(report, "| Rejected |"))
	})
}

func TestCurationActionsCommand_Run_ParallelDecisions(t *testing.T) {
	tests := []struct {
		name        string
		threads     int
		wantMaxOpen int32
	}{
		{name: "verify when threads is set then no more decisions than that run at once", threads: 2, wantMaxOpen: 2},
		{name: "verify when threads is not set then the CLI default bounds the decisions in flight", threads: 0, wantMaxOpen: int32(cliutils.Threads)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")
			spec, _ := orderedActions(8)
			decider := &probeDecider{barrier: tt.wantMaxOpen, release: make(chan struct{})}

			err := spec.newCommand(t, noWorkflowFile, "", decider).SetParallelRequests(tt.threads).Run()

			require.NoError(t, err)
			assert.Equal(t, int32(8), decider.calls.Load())
			assert.Equal(t, tt.wantMaxOpen, decider.maxInFlight.Load(), "decisions in flight at once, want exactly the thread bound")
		})
	}
}

func TestCurationActionsCommand_Run_ReportOrderIsDiscoveryOrder(t *testing.T) {
	t.Run("verify when decisions finish in reverse then the report still lists actions in discovery order", func(t *testing.T) {
		pinRunnerEnv(t, testGithubRepo, "", "")
		spec, _ := orderedActions(5)
		// The first action is the slowest, so with every action in flight at once they finish last-first.
		decider := &probeDecider{hold: func(ref githubactions.ActionRef) time.Duration {
			return time.Duration('f'-rune(ref.Owner[0])) * 15 * time.Millisecond
		}}

		report, err := captureReport(t, spec.newCommand(t, noWorkflowFile, "", decider).SetParallelRequests(5))

		require.NoError(t, err)
		last := -1
		for _, owner := range []string{"a-org", "b-org", "c-org", "d-org", "e-org"} {
			idx := strings.Index(report, "| "+owner+"/act |")
			require.GreaterOrEqual(t, idx, 0, "%s missing from the report:\n%s", owner, report)
			assert.Greater(t, idx, last, "%s is out of discovery order:\n%s", owner, report)
			last = idx
		}
	})
}

func TestCurationActionsCommand_Run_MixedOutcomes(t *testing.T) {
	t.Run("verify when actions are approved, rejected and undecidable then each is its own row and the error names both failures", func(t *testing.T) {
		pinRunnerEnv(t, testGithubRepo, "", "")
		spec := runnerSpec{cacheDirs: []string{"actions/checkout/v4", "evil-org/backdoor/v1", "flaky-org/remote/v1"}}
		decider := &scriptedDecider{rejected: []string{"evil-org/backdoor@v1"}, undecidable: []string{"flaky-org/remote@v1"}}

		report, err := captureReport(t, spec.newCommand(t, noWorkflowFile, "", decider))

		require.Error(t, err)
		assert.Equal(t, 1, strings.Count(report, "| Approved |"), report)
		assert.Equal(t, 1, strings.Count(report, "| Rejected |"), report)
		assert.Equal(t, 1, strings.Count(report, "| Undetermined |"), report)
		assert.ErrorContains(t, err, `evil-org/backdoor@v1: status "Rejected"`)
		assert.ErrorContains(t, err, "flaky-org/remote@v1")
		assert.ErrorContains(t, err, "decision service unavailable")
		assert.NotContains(t, err.Error(), `status "Undetermined"`, "an Undetermined action is explained once, by its cause")
	})
	t.Run("verify when a decider returns Undetermined without an error then the command still fails", func(t *testing.T) {
		pinRunnerEnv(t, testGithubRepo, "", "")
		spec := runnerSpec{cacheDirs: []string{"actions/checkout/v4", "quiet-org/action/v1"}}
		decider := &scriptedDecider{silentlyUndetermined: []string{"quiet-org/action@v1"}}

		report, err := captureReport(t, spec.newCommand(t, noWorkflowFile, "", decider))

		require.Error(t, err, "only an explicit Approved may clear the gate")
		assert.Equal(t, 1, strings.Count(report, "| Undetermined |"), report)
		assert.ErrorContains(t, err, `quiet-org/action@v1: status "Undetermined"`)
	})
}

func TestCurationActionsCommand_Run_RequiresAServerWithoutATestDecider(t *testing.T) {
	tests := []struct {
		name          string
		serverDetails *config.ServerDetails
	}{
		{name: "verify when no server details are set then the command reports no JFrog server"},
		// What the CLI resolves when jf config holds no server: empty, not nil.
		{name: "verify when the server details are empty then the command reports no JFrog server", serverDetails: &config.ServerDetails{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")
			workingDir, actionsCacheDir := runnerSpec{cacheDirs: []string{"actions/checkout/v4"}}.build(t)

			err := NewCurationActionsCommand().SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).
				SetServerDetails(tt.serverDetails).Run()

			assert.ErrorContains(t, err, "no JFrog server is configured")
		})
	}
}
