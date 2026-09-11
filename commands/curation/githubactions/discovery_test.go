package githubactions

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

const fixturesRoot = "../../../tests/testdata/projects/githubactions"

func TestDiscoverActionCache_GoodFixture(t *testing.T) {
	actionsDir := filepath.Join(fixturesRoot, "curation-project", "_work", "_actions")

	refs, err := DiscoverActionCache(actionsDir)
	assert.NoError(t, err)

	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Owner+refs[i].Repo < refs[j].Owner+refs[j].Repo
	})

	if assert.Len(t, refs, 3) {
		assert.Equal(t, "actions", refs[0].Owner)
		assert.Equal(t, "checkout", refs[0].Repo)
		assert.Equal(t, "v4", refs[0].Ref)
		assert.Equal(t, filepath.Join(actionsDir, "actions", "checkout", "v4"), refs[0].Path)

		assert.Equal(t, "github", refs[1].Owner)
		assert.Equal(t, "codeql-action", refs[1].Repo)
		assert.Equal(t, "v3", refs[1].Ref)

		assert.Equal(t, "some-org", refs[2].Owner)
		assert.Equal(t, "transitive-action", refs[2].Repo)
		assert.Equal(t, "v1", refs[2].Ref)
	}

	for _, ref := range refs {
		assert.Empty(t, ref.Subpaths, "DiscoverActionCache must not set Subpaths - that's CrossReference's job")
		assert.Empty(t, ref.Parent, "DiscoverActionCache must not set Parent - that's CrossReference's job")
	}
}

func TestDiscoverActionCache_MissingDir(t *testing.T) {
	refs, err := DiscoverActionCache(filepath.Join(fixturesRoot, "does-not-exist"))
	assert.NoError(t, err)
	assert.Empty(t, refs)
	assert.NotNil(t, refs)
}

func TestDiscoverActionCache_MalformedTreeSkipsDefensively(t *testing.T) {
	actionsDir := filepath.Join(fixturesRoot, "malformed-project", "_work", "_actions")

	refs, err := DiscoverActionCache(actionsDir)
	assert.NoError(t, err)

	// Only actions/checkout/v4 is a well-formed owner/repo/ref triple.
	// stray-file.txt (owner level), actions/stray-file-at-repo-level.txt (repo level),
	// and onlyowner/ (a valid owner dir with no repo subdirectories) must all be
	// skipped without error.
	if assert.Len(t, refs, 1) {
		assert.Equal(t, "actions", refs[0].Owner)
		assert.Equal(t, "checkout", refs[0].Repo)
		assert.Equal(t, "v4", refs[0].Ref)
	}
}

func TestDefaultActionsCacheDir(t *testing.T) {
	// RUNNER_WORKSPACE is <_work>/<repo> (one segment) - _actions is its sibling under
	// <_work>. Matches the layout used by working reference scripts added under
	// ~/Downloads/github-actions (poc-github-action/action.yml, demo-workflows/action.yml):
	// dirname(RUNNER_WORKSPACE)/_actions.
	t.Setenv(RunnerWorkspaceEnvVar, "/home/runner/work/my-repo")

	dir, err := DefaultActionsCacheDir()
	assert.NoError(t, err)
	assert.Equal(t, filepath.Clean("/home/runner/work/_actions"), dir)
}

func TestDefaultActionsCacheDir_NotSet(t *testing.T) {
	t.Setenv(RunnerWorkspaceEnvVar, "")

	_, err := DefaultActionsCacheDir()
	assert.Error(t, err)
}

func TestDefaultWorkflowFile(t *testing.T) {
	tests := []struct {
		name        string
		workflowRef string
		want        string
	}{
		{"standard ref", "octocat/hello-world/.github/workflows/ci.yml@refs/heads/main", ".github/workflows/ci.yml"},
		{"ref containing slashes", "octocat/hello-world/.github/workflows/ci.yml@refs/heads/my/feature", ".github/workflows/ci.yml"},
		{"tag ref", "octocat/hello-world/.github/workflows/release.yaml@refs/tags/v1.2.3", ".github/workflows/release.yaml"},
		{"unset", "", ""},
		{"owner and repo only", "octocat/hello-world@refs/heads/main", ""},
		{"no ref suffix still yields the path", "octocat/hello-world/.github/workflows/ci.yml", ".github/workflows/ci.yml"},
		{"malformed is not an error, just unusable", "nonsense", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(WorkflowRefEnvVar, tt.workflowRef)
			assert.Equal(t, tt.want, DefaultWorkflowFile())
		})
	}
}

func TestDefaultJobID(t *testing.T) {
	t.Setenv(JobIDEnvVar, "build")
	assert.Equal(t, "build", DefaultJobID())

	t.Setenv(JobIDEnvVar, "")
	assert.Empty(t, DefaultJobID())
}

func TestExcludeDeliveryAction(t *testing.T) {
	tests := []struct {
		name      string
		refs      []ActionRef
		wantRepos []string
	}{
		{
			name: "the delivery action is dropped at any ref",
			refs: []ActionRef{
				{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "v4"},
				{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "9a4c2881"},
				{Owner: "actions", Repo: "checkout", Ref: "v4"},
			},
			wantRepos: []string{"checkout"},
		},
		{
			name: "other jfrog actions are still curated",
			refs: []ActionRef{
				{Owner: "jfrog", Repo: "frogbot", Ref: "v2"},
				{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "v4"},
			},
			wantRepos: []string{"frogbot"},
		},
		{
			name: "a same-named action from another owner is still curated",
			refs: []ActionRef{
				{Owner: "not-jfrog", Repo: "setup-jfrog-cli", Ref: "v4"},
			},
			wantRepos: []string{"setup-jfrog-cli"},
		},
		{
			name:      "a cache holding only the delivery action leaves nothing to curate",
			refs:      []ActionRef{{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "v4"}},
			wantRepos: nil,
		},
		{
			name:      "no refs stays empty",
			refs:      nil,
			wantRepos: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept := ExcludeDeliveryAction(tt.refs)
			repos := make([]string, len(kept))
			for i, ref := range kept {
				repos[i] = ref.Repo
			}
			if tt.wantRepos == nil {
				assert.Empty(t, repos)
				return
			}
			assert.Equal(t, tt.wantRepos, repos)
		})
	}
}

func TestExcludeDeliveryAction_PreservesTransitiveAttribution(t *testing.T) {
	// Excluding the delivery action must not orphan anything it pulled in: attribution runs
	// before this filter, so a child keeps its Parent even though that parent is not reported.
	kept := ExcludeDeliveryAction([]ActionRef{
		{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "v4"},
		{Owner: "some-org", Repo: "pulled-in-by-delivery", Ref: "v1", Parent: "jfrog/setup-jfrog-cli@v4"},
	})

	if assert.Len(t, kept, 1) {
		assert.Equal(t, "pulled-in-by-delivery", kept[0].Repo)
		assert.Equal(t, "jfrog/setup-jfrog-cli@v4", kept[0].Parent, "attribution must survive the exclusion")
	}
}
