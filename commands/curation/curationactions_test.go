package curation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
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
type scriptedDecider struct {
	rejected    []string
	undecidable []string
	asked       []string
	// vcsRepos records the Artifactory VCS repository each decision was made under, so tests can
	// prove the resolved value actually reached the decider rather than being computed and dropped.
	vcsRepos []string
}

func (d *scriptedDecider) Decide(_ context.Context, artifactoryVcsRepo string, ref githubactions.ActionRef) (githubactions.ActionCurationResult, error) {
	key := ref.Owner + "/" + ref.Repo + "@" + ref.Ref
	d.asked = append(d.asked, key)
	d.vcsRepos = append(d.vcsRepos, artifactoryVcsRepo)
	if slices.Contains(d.undecidable, key) {
		return githubactions.ActionCurationResult{}, errors.New("decision service unavailable")
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

// workflowFileMode selects what --workflow-file points at, if anything.
type workflowFileMode int

const (
	noWorkflowFile       workflowFileMode = iota // omit the flag; resolution falls to the environment
	writtenWorkflowFile                          // the ci.yml runnerSpec wrote into the working directory
	fixtureWorkflowFile                          // the curation-project fixture's own ci.yml
	missingWorkflowFile                          // a path that does not exist
	relativeWorkflowFile                         // a relative path - --workflow-file must be absolute
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
		require.NoError(t, os.WriteFile(filepath.Join(workflowsDir, "ci.yml"), []byte(s.workflowYAML), 0600))
	}
	return workingDir, actionsCacheDir
}

// newCommand builds the command every Run test exercises, wiring --workflow-file per mode.
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
		// Absolute on purpose: a relative --workflow-file resolves against the working directory,
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
			name: "verify when the cache holds the delivery action then it is excluded from curation",
			spec: runnerSpec{
				cacheDirs:    []string{"jfrog/setup-jfrog-cli/v4", "actions/checkout/v4"},
				workflowYAML: "jobs:\n  build:\n    steps:\n      - uses: jfrog/setup-jfrog-cli@v4\n      - uses: actions/checkout@v4\n",
			},
			mode:      writtenWorkflowFile,
			jobID:     "build",
			wantAsked: []string{"actions/checkout@v4"},
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
			name: "verify when the cache is empty then the command succeeds",
			spec: runnerSpec{},
			mode: fixtureWorkflowFile,
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
	// An action that cannot be decided has an unknown status, and a report that quietly omitted
	// it would read as a clean run. So the whole run fails and emits nothing - every row asserts
	// the job summary directory stays empty, not just the one that motivated the rule.
	twoActions := runnerSpec{cacheDirs: []string{"actions/checkout/v4", "actions/setup-node/v4"}}

	tests := []struct {
		name               string
		spec               runnerSpec
		mode               workflowFileMode
		undecidable        []string
		wantErrContains    []string
		wantErrNotContains []string
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
			name:               "verify when only one decision fails then the error names it alone",
			spec:               twoActions,
			undecidable:        []string{"actions/setup-node@v4"},
			wantErrContains:    []string{"actions/setup-node@v4"},
			wantErrNotContains: []string{"actions/checkout@v4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinRunnerEnv(t, testGithubRepo, "", "")
			// Recording is a no-op unless this is set, so set it and assert nothing lands there.
			summaryDir := t.TempDir()
			t.Setenv(coreutils.SummaryOutputDirPathEnv, summaryDir)
			decider := &scriptedDecider{undecidable: tt.undecidable}

			err := tt.spec.newCommand(t, tt.mode, "", decider).Run()

			require.Error(t, err)
			for _, want := range tt.wantErrContains {
				assert.ErrorContains(t, err, want)
			}
			for _, notWant := range tt.wantErrNotContains {
				assert.NotContains(t, err.Error(), notWant)
			}
			entries, readErr := os.ReadDir(summaryDir)
			require.NoError(t, readErr)
			assert.Empty(t, entries, "no job summary may be recorded when an action could not be decided")
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
			// that did not pass --workflow-file would fail here.
			name:        "verify when the derived workflow path is absent then curation falls back to structure-only",
			spec:        runnerSpec{cacheDirs: oneAction},
			workflowRef: derivedWorkflowRef,
			wantAsked:   []string{"actions/checkout@v4"},
		},
		{
			name:            "verify when an explicit workflow path is absent then the command fails",
			spec:            runnerSpec{cacheDirs: oneAction},
			mode:            missingWorkflowFile,
			wantErrContains: "reading workflow file",
		},
		{
			// --workflow-file is an explicit, single-file assertion; only the derived path
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
			assert.Equal(t, tt.wantAsked, decider.asked,
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
			name:           "verify when --github-repo is passed then it overrides the environment",
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
			name:            "verify when no GitHub repository is known then the error names both ways to supply one",
			envRepo:         "", // GITHUB_REPOSITORY unset, e.g. a local run
			wantErrContains: []string{"--github-repo", githubactions.GithubRepoEnvVar},
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

func TestCurationActionsCommand_Run_EmptyCacheMakesNoResolutionCall(t *testing.T) {
	pinRunnerEnv(t, testGithubRepo, "", "")
	resolver := &fixedResolver{repo: "unused"}

	require.NoError(t, runnerSpec{}.newCommand(t, noWorkflowFile, "", &scriptedDecider{}).
		SetVcsRepoResolver(resolver).Run())

	assert.Empty(t, resolver.askedAbout, "a job with nothing to curate must not call the mapping API")
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
			name: "verify when a local composite action pulls in a remote one then it is still decided",
			// uses: ./... is read from the workspace, so there is nothing to walk outward from.
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
