package curation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/commands/curation/githubactions"
)

const curationActionsFixture = "../../tests/testdata/projects/githubactions/curation-project"

// fixedDecider deterministically rejects exactly the given "owner/repo@ref" keys and approves
// everything else - used instead of the timestamp-parity mock so this test doesn't depend on
// the real clock.
type fixedDecider struct {
	rejected map[string]bool
}

func (f *fixedDecider) Decide(_ context.Context, _ string, ref githubactions.ActionRef) (githubactions.ActionCurationResult, error) {
	key := ref.Owner + "/" + ref.Repo + "@" + ref.Ref
	if f.rejected[key] {
		return githubactions.ActionCurationResult{Status: githubactions.ActionRejected, Notes: "rejected in test"}, nil
	}
	return githubactions.ActionCurationResult{Status: githubactions.ActionApproved}, nil
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

const testGithubRepo = "my-org/my-repo"

func TestCurationActionsCommand_Run_AllApproved(t *testing.T) {
	pinRunnerEnv(t, testGithubRepo, "", "")
	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(filepath.Join(curationActionsFixture, "_work", "_actions")).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(&fixedDecider{})

	assert.NoError(t, cmd.Run())
}

func TestCurationActionsCommand_Run_RejectedActionFailsTheCommand(t *testing.T) {
	pinRunnerEnv(t, testGithubRepo, "", "")
	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(filepath.Join(curationActionsFixture, "_work", "_actions")).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(&fixedDecider{rejected: map[string]bool{"some-org/transitive-action@v1": true}})

	err := cmd.Run()
	assert.Error(t, err)
}

func TestCurationActionsCommand_Run_UnrelatedCachedActionDoesNotFailTheCommand(t *testing.T) {
	// A cache entry not referenced by this job's workflow, directly or transitively. Filtering
	// it out needs ATTRIBUTED mode, which needs both a workflow file and the job id - hence
	// SetJobID below. Without a job id the run is structure-only and the entry would be curated
	// like any other, which is the correct behaviour for that mode rather than a regression.
	pinRunnerEnv(t, testGithubRepo, "", "")
	actionsCacheDir := t.TempDir()
	require.NoError(t, os.CopyFS(actionsCacheDir, os.DirFS(filepath.Join(curationActionsFixture, "_work", "_actions"))))
	require.NoError(t, os.MkdirAll(filepath.Join(actionsCacheDir, "some-other-org", "leftover-action", "v9"), 0755))

	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(actionsCacheDir).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetJobID("build").
		SetDecider(&fixedDecider{rejected: map[string]bool{"some-other-org/leftover-action@v9": true}})

	assert.NoError(t, cmd.Run(), "an unrelated leftover cache entry must never be decided, let alone fail the command")
}

func TestCurationActionsCommand_Run_NoActionsIsANoop(t *testing.T) {
	pinRunnerEnv(t, testGithubRepo, "", "")
	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(t.TempDir()).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(&fixedDecider{})

	assert.NoError(t, cmd.Run())
}

// recordingDecider approves everything and records which actions it was asked about, so a test
// can assert on the curation SCOPE rather than only on the command's exit status.
type recordingDecider struct {
	asked []string
	// vcsRepos records the Artifactory VCS repository each decision was made under, so tests
	// can prove the resolved value actually reached the decider rather than being computed and
	// dropped.
	vcsRepos []string
}

func (r *recordingDecider) Decide(_ context.Context, artifactoryVcsRepo string, ref githubactions.ActionRef) (githubactions.ActionCurationResult, error) {
	r.asked = append(r.asked, ref.Owner+"/"+ref.Repo+"@"+ref.Ref)
	r.vcsRepos = append(r.vcsRepos, artifactoryVcsRepo)
	return githubactions.ActionCurationResult{Status: githubactions.ActionApproved}, nil
}

// erroringDecider fails every decision, standing in for the real decision service being
// unreachable. The timestamp-parity mock never errors, so this is the only way to reach
// Run's decide-error path.
type erroringDecider struct{}

func (erroringDecider) Decide(context.Context, string, githubactions.ActionRef) (githubactions.ActionCurationResult, error) {
	return githubactions.ActionCurationResult{}, errors.New("decision service unavailable")
}

func TestCurationActionsCommand_Run_StructureOnlyCuratesTheWholeCache(t *testing.T) {
	// No --workflow-file and no GITHUB_WORKFLOW_REF: nothing identifies the running workflow,
	// so the action cache is curated as-is. Every discovered entry must still be decided -
	// structure-only loses report detail, not coverage.
	pinRunnerEnv(t, testGithubRepo, "", "")

	decider := &recordingDecider{}
	cmd := NewCurationActionsCommand().
		SetWorkingDir(curationActionsFixture).
		SetActionsCacheDir(filepath.Join(curationActionsFixture, "_work", "_actions")).
		SetDecider(decider)

	require.NoError(t, cmd.Run())
	assert.ElementsMatch(t,
		[]string{"actions/checkout@v4", "github/codeql-action@v3", "some-org/transitive-action@v1"},
		decider.asked,
		"structure-only mode must curate every entry in the cache")
}

func TestCurationActionsCommand_Run_StructureOnlyCuratesEntriesNoWorkflowReferences(t *testing.T) {
	// The distinguishing case. This entry is in the cache but appears in no workflow file, so
	// attributed mode would drop it via FilterRelevant. Structure-only must still decide it -
	// the runner put it in this job's cache, so it is this job's action.
	actionsCacheDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(actionsCacheDir, "some-org", "unreferenced", "v9"), 0755))

	pinRunnerEnv(t, testGithubRepo, "", "")

	decider := &recordingDecider{}
	require.NoError(t, NewCurationActionsCommand().
		SetWorkingDir(t.TempDir()).
		SetActionsCacheDir(actionsCacheDir).
		SetDecider(decider).
		Run())

	assert.Equal(t, []string{"some-org/unreferenced@v9"}, decider.asked)
}

func TestCurationActionsCommand_Run_AttributedModeStillFiltersToTheWorkflow(t *testing.T) {
	pinRunnerEnv(t, testGithubRepo, "", "")
	// With a workflow file, the existing relevance filter applies: an entry no workflow
	// references is dropped rather than decided. This is the behaviour structure-only mode
	// deliberately does not have.
	actionsCacheDir := t.TempDir()
	require.NoError(t, os.CopyFS(actionsCacheDir, os.DirFS(filepath.Join(curationActionsFixture, "_work", "_actions"))))
	require.NoError(t, os.MkdirAll(filepath.Join(actionsCacheDir, "some-org", "unreferenced", "v9"), 0755))

	decider := &recordingDecider{}
	require.NoError(t, NewCurationActionsCommand().
		SetActionsCacheDir(actionsCacheDir).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetJobID("build").
		SetDecider(decider).
		Run())

	assert.NotContains(t, decider.asked, "some-org/unreferenced@v9")
	assert.Contains(t, decider.asked, "actions/checkout@v4")
}

func TestCurationActionsCommand_Run_DerivesTheWorkflowFileFromTheEnvironment(t *testing.T) {
	// On a runner the workflow is identified by GITHUB_WORKFLOW_REF, whose path component is
	// repo-relative and so must resolve against the working directory.
	pinRunnerEnv(t, testGithubRepo, "some-org/some-repo/.github/workflows/ci.yml@refs/heads/main", "build")

	decider := &recordingDecider{}
	cmd := NewCurationActionsCommand().
		SetWorkingDir(curationActionsFixture).
		SetActionsCacheDir(filepath.Join(curationActionsFixture, "_work", "_actions")).
		SetDecider(decider)

	require.NoError(t, cmd.Run())
	assert.ElementsMatch(t,
		[]string{"actions/checkout@v4", "github/codeql-action@v3", "some-org/transitive-action@v1"},
		decider.asked)
}

func TestCurationActionsCommand_Run_ScopesToTheRunningJob(t *testing.T) {
	// A sibling job in the same workflow file references an action that is also sitting in the
	// runner's cache. Curating the job we run in means that action is out of scope - and a
	// decider that would reject it must never be consulted.
	workingDir := t.TempDir()
	workflowsDir := filepath.Join(workingDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowsDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(workflowsDir, "ci.yml"), []byte(
		"jobs:\n"+
			"  build:\n    steps:\n      - uses: actions/checkout@v4\n"+
			"  publish:\n    steps:\n      - uses: some-other-org/publisher@v9\n"), 0600))

	actionsCacheDir := filepath.Join(workingDir, "_work", "_actions")
	for _, dir := range []string{
		filepath.Join(actionsCacheDir, "actions", "checkout", "v4"),
		filepath.Join(actionsCacheDir, "some-other-org", "publisher", "v9"),
	} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}

	pinRunnerEnv(t, testGithubRepo, "some-org/some-repo/.github/workflows/ci.yml@refs/heads/main", "build")

	decider := &recordingDecider{}
	cmd := NewCurationActionsCommand().
		SetWorkingDir(workingDir).
		SetActionsCacheDir(actionsCacheDir).
		SetDecider(decider)

	require.NoError(t, cmd.Run())
	assert.Equal(t, []string{"actions/checkout@v4"}, decider.asked,
		"an action referenced only by a sibling job must not be curated by this job")
}

func TestCurationActionsCommand_Run_DecideErrorFailsTheCommand(t *testing.T) {
	pinRunnerEnv(t, testGithubRepo, "", "")
	cmd := NewCurationActionsCommand().
		SetActionsCacheDir(filepath.Join(curationActionsFixture, "_work", "_actions")).
		SetWorkflowFile(filepath.Join(curationActionsFixture, ".github", "workflows", "ci.yml")).
		SetDecider(erroringDecider{})

	err := cmd.Run()
	assert.ErrorContains(t, err, "deciding curation status for")
	assert.ErrorContains(t, err, "decision service unavailable")
}
func TestCurationActionsCommand_Run_DeliveryActionIsNotCurated(t *testing.T) {
	pinRunnerEnv(t, testGithubRepo, "", "")
	// The Delivery 01 shape: jfrog/setup-jfrog-cli is the job's first step, so it resolves
	// into _actions and is a direct uses: reference - yet it must never be decided. A decider
	// that would reject it is not even consulted, so the check cannot fail the job on itself.
	workingDir := t.TempDir()
	workflowsDir := filepath.Join(workingDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowsDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(workflowsDir, "ci.yml"), []byte(
		"jobs:\n  build:\n    steps:\n"+
			"      - uses: jfrog/setup-jfrog-cli@v4\n"+
			"      - uses: actions/checkout@v4\n"), 0600))

	actionsCacheDir := filepath.Join(workingDir, "_work", "_actions")
	for _, dir := range []string{
		filepath.Join(actionsCacheDir, "jfrog", "setup-jfrog-cli", "v4"),
		filepath.Join(actionsCacheDir, "actions", "checkout", "v4"),
	} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}

	decider := &recordingDecider{}
	cmd := NewCurationActionsCommand().
		SetWorkingDir(workingDir).
		SetActionsCacheDir(actionsCacheDir).
		SetWorkflowFile(filepath.Join(workflowsDir, "ci.yml")).
		SetJobID("build").
		SetDecider(decider)

	require.NoError(t, cmd.Run())
	assert.Equal(t, []string{"actions/checkout@v4"}, decider.asked,
		"the action delivering this check must not be subject to it")
}

func TestCurationActionsCommand_Run_WorkflowFileResolution(t *testing.T) {
	// The three branches of parseWorkflowUses, exercised through Run in the shape a real
	// runner produces: _actions populated, workspace empty because checkout has not run.
	newRunner := func(t *testing.T) (workingDir, actionsCacheDir string) {
		t.Helper()
		workingDir = t.TempDir()
		actionsCacheDir = filepath.Join(t.TempDir(), "_actions")
		require.NoError(t, os.MkdirAll(filepath.Join(actionsCacheDir, "actions", "checkout", "v4"), 0755))
		return workingDir, actionsCacheDir
	}

	t.Run("derived path absent from disk falls back to structure-only", func(t *testing.T) {
		// GITHUB_WORKFLOW_REF is always set on a runner, so without this fallback every job
		// that did not pass --workflow-file would fail here.
		workingDir, actionsCacheDir := newRunner(t)
		pinRunnerEnv(t, testGithubRepo, "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main", "build")

		decider := &recordingDecider{}
		require.NoError(t, NewCurationActionsCommand().
			SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).SetDecider(decider).Run())
		assert.Equal(t, []string{"actions/checkout@v4"}, decider.asked,
			"the cache must still be curated when the derived workflow file is not on disk")
	})

	t.Run("explicit path absent from disk is an error", func(t *testing.T) {
		// The caller named the file, so its absence is their mistake, not a condition to absorb.
		pinRunnerEnv(t, testGithubRepo, "", "")
		workingDir, actionsCacheDir := newRunner(t)
		decider := &recordingDecider{}
		err := NewCurationActionsCommand().
			SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).
			SetWorkflowFile(filepath.Join(workingDir, "no-such-workflow.yml")).
			SetDecider(decider).Run()

		assert.ErrorContains(t, err, "reading workflow file")
		assert.Empty(t, decider.asked)
	})

	t.Run("derived path present but malformed is an error", func(t *testing.T) {
		// Not an absence, so it is not the fallback's business: a workflow this parser cannot
		// read but GitHub could is worth surfacing rather than silently downgrading.
		workingDir, actionsCacheDir := newRunner(t)
		workflowsDir := filepath.Join(workingDir, ".github", "workflows")
		require.NoError(t, os.MkdirAll(workflowsDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(workflowsDir, "ci.yml"),
			[]byte("jobs:\n\t- this is not valid yaml\n"), 0600))

		pinRunnerEnv(t, testGithubRepo, "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main", "build")

		decider := &recordingDecider{}
		err := NewCurationActionsCommand().
			SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).SetDecider(decider).Run()

		assert.ErrorContains(t, err, "parsing workflow file")
		assert.Empty(t, decider.asked)
	})

	t.Run("derived path present and valid attributes normally", func(t *testing.T) {
		workingDir, actionsCacheDir := newRunner(t)
		workflowsDir := filepath.Join(workingDir, ".github", "workflows")
		require.NoError(t, os.MkdirAll(workflowsDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(workflowsDir, "ci.yml"),
			[]byte("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"), 0600))

		pinRunnerEnv(t, testGithubRepo, "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main", "build")

		decider := &recordingDecider{}
		require.NoError(t, NewCurationActionsCommand().
			SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).SetDecider(decider).Run())
		assert.Equal(t, []string{"actions/checkout@v4"}, decider.asked)
	})
}

// erroringResolver stands in for the mapping API being unreachable.
type erroringResolver struct{}

func (erroringResolver) Resolve(context.Context, string) (string, error) {
	return "", errors.New("mapping service unavailable")
}

// fixedResolver returns a known key so a test can assert what reached the decider.
type fixedResolver struct {
	repo       string
	askedAbout []string
}

func (f *fixedResolver) Resolve(_ context.Context, githubRepo string) (string, error) {
	f.askedAbout = append(f.askedAbout, githubRepo)
	return f.repo, nil
}

func TestCurationActionsCommand_Run_ArtifactoryVcsRepoResolution(t *testing.T) {
	newRunner := func(t *testing.T) (workingDir, actionsCacheDir string) {
		t.Helper()
		workingDir = t.TempDir()
		actionsCacheDir = filepath.Join(t.TempDir(), "_actions")
		for _, d := range []string{"checkout", "setup-node"} {
			require.NoError(t, os.MkdirAll(filepath.Join(actionsCacheDir, "actions", d, "v4"), 0755))
		}
		return workingDir, actionsCacheDir
	}

	t.Run("resolved from GITHUB_REPOSITORY and passed to every decision", func(t *testing.T) {
		workingDir, actionsCacheDir := newRunner(t)
		pinRunnerEnv(t, testGithubRepo, "", "")

		resolver := &fixedResolver{repo: "my-org-github-remote"}
		decider := &recordingDecider{}
		require.NoError(t, NewCurationActionsCommand().
			SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).
			SetVcsRepoResolver(resolver).SetDecider(decider).Run())

		assert.Equal(t, []string{testGithubRepo}, resolver.askedAbout, "resolution happens once per run, not once per action")
		assert.Len(t, decider.asked, 2)
		assert.Equal(t, []string{"my-org-github-remote", "my-org-github-remote"}, decider.vcsRepos,
			"the resolved repository must reach every decision")
	})

	t.Run("--github-repo overrides the environment", func(t *testing.T) {
		workingDir, actionsCacheDir := newRunner(t)
		pinRunnerEnv(t, testGithubRepo, "", "")

		resolver := &fixedResolver{repo: "resolved"}
		require.NoError(t, NewCurationActionsCommand().
			SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).
			SetGithubRepo("flag-org/flag-repo").
			SetVcsRepoResolver(resolver).SetDecider(&recordingDecider{}).Run())

		assert.Equal(t, []string{"flag-org/flag-repo"}, resolver.askedAbout)
	})

	t.Run("failed resolution fails the command", func(t *testing.T) {
		// Without the governing repository there is no basis for any decision, so this must
		// fail loudly rather than approve anything.
		workingDir, actionsCacheDir := newRunner(t)
		pinRunnerEnv(t, testGithubRepo, "", "")

		decider := &recordingDecider{}
		err := NewCurationActionsCommand().
			SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).
			SetVcsRepoResolver(erroringResolver{}).SetDecider(decider).Run()

		assert.ErrorContains(t, err, "resolving the Artifactory VCS repository governing")
		assert.ErrorContains(t, err, "mapping service unavailable")
		assert.Empty(t, decider.asked, "nothing may be decided when the governing repository is unknown")
	})

	t.Run("no GitHub repository at all fails with an actionable message", func(t *testing.T) {
		workingDir, actionsCacheDir := newRunner(t)
		pinRunnerEnv(t, "", "", "") // GITHUB_REPOSITORY unset, e.g. a local run

		decider := &recordingDecider{}
		err := NewCurationActionsCommand().
			SetWorkingDir(workingDir).SetActionsCacheDir(actionsCacheDir).SetDecider(decider).Run()

		assert.ErrorContains(t, err, "--github-repo")
		assert.ErrorContains(t, err, githubactions.GithubRepoEnvVar)
		assert.Empty(t, decider.asked)
	})

	t.Run("an empty cache makes no resolution call", func(t *testing.T) {
		pinRunnerEnv(t, testGithubRepo, "", "")
		resolver := &fixedResolver{repo: "unused"}
		require.NoError(t, NewCurationActionsCommand().
			SetWorkingDir(t.TempDir()).SetActionsCacheDir(t.TempDir()).
			SetVcsRepoResolver(resolver).SetDecider(&recordingDecider{}).Run())
		assert.Empty(t, resolver.askedAbout, "a job with nothing to curate must not call the mapping API")
	})
}

func TestCurationActionsCommand_Run_UndecidableActionProducesNoReportOrSummary(t *testing.T) {
	// An action that cannot be decided has an unknown status, and a report that quietly omitted
	// it would read as a clean run. So the whole run fails and emits nothing.
	pinRunnerEnv(t, testGithubRepo, "", "")

	// Recording is a no-op unless this is set, so set it and assert the directory stays empty.
	summaryDir := t.TempDir()
	t.Setenv(coreutils.SummaryOutputDirPathEnv, summaryDir)

	cacheDir := filepath.Join(t.TempDir(), "_actions")
	for _, repo := range []string{"checkout", "setup-node"} {
		require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "actions", repo, "v4"), 0755))
	}

	err := NewCurationActionsCommand().
		SetWorkingDir(t.TempDir()).SetActionsCacheDir(cacheDir).
		SetDecider(flakyDecider{failRepo: "setup-node"}).Run()

	// Named the action it could not decide...
	assert.ErrorContains(t, err, "actions/setup-node@v4")
	assert.ErrorContains(t, err, "connection refused")
	// ...and did not report the one it could.
	assert.NotContains(t, err.Error(), "actions/checkout")

	entries, readErr := os.ReadDir(summaryDir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "no job summary may be recorded when an action could not be decided")
}

func TestCurationActionsCommand_Run_UndecidableActionsAreAllNamed(t *testing.T) {
	// The decide loop keeps going after a failure so the error accounts for every action it
	// could not decide, not just the first one encountered.
	pinRunnerEnv(t, testGithubRepo, "", "")

	cacheDir := filepath.Join(t.TempDir(), "_actions")
	for _, repo := range []string{"checkout", "setup-node"} {
		require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "actions", repo, "v4"), 0755))
	}

	err := NewCurationActionsCommand().
		SetWorkingDir(t.TempDir()).SetActionsCacheDir(cacheDir).
		SetDecider(erroringDecider{}).Run()

	require.Error(t, err)
	assert.ErrorContains(t, err, "actions/checkout@v4")
	assert.ErrorContains(t, err, "actions/setup-node@v4")
}

// flakyDecider fails for exactly one action, leaving the others decidable.
type flakyDecider struct{ failRepo string }

func (f flakyDecider) Decide(_ context.Context, _ string, ref githubactions.ActionRef) (githubactions.ActionCurationResult, error) {
	if ref.Repo == f.failRepo {
		return githubactions.ActionCurationResult{}, errors.New("connection refused")
	}
	return githubactions.ActionCurationResult{Status: githubactions.ActionApproved}, nil
}

func TestCurationActionsCommand_Run_UndeclaredJobCuratesTheCacheNotOtherJobs(t *testing.T) {
	// Each job runs on its own runner with its own _actions, so the cache here is exactly what
	// THIS job resolved. When the workflow file does not declare this job - the reusable-workflow
	// case - the other jobs in that file describe different runners entirely. Attributing from
	// them previously curated an action only they declared and dropped one this job really used.
	pinRunnerEnv(t, testGithubRepo, "", "")

	workingDir := t.TempDir()
	workflowsDir := filepath.Join(workingDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowsDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(workflowsDir, "ci.yml"),
		[]byte("jobs:\n  some-other-job:\n    steps:\n      - uses: actions/checkout@v4\n"), 0600))

	// What this job actually resolved: checkout AND setup-node.
	actionsCacheDir := filepath.Join(t.TempDir(), "_actions")
	for _, repo := range []string{"checkout", "setup-node"} {
		require.NoError(t, os.MkdirAll(filepath.Join(actionsCacheDir, "actions", repo, "v4"), 0755))
	}

	decider := &recordingDecider{}
	require.NoError(t, NewCurationActionsCommand().
		SetWorkingDir(workingDir).
		SetActionsCacheDir(actionsCacheDir).
		SetWorkflowFile(filepath.Join(workflowsDir, "ci.yml")).
		SetJobID("the-job-this-command-runs-in").
		SetDecider(decider).Run())

	assert.ElementsMatch(t, []string{"actions/checkout@v4", "actions/setup-node@v4"}, decider.asked,
		"every action this job resolved must be curated, not just the ones another job declared")
}
