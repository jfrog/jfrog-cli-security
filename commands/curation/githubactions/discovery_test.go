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
		assert.Empty(t, ref.Subpath, "DiscoverActionCache must not set Subpath - that's CrossReference's job")
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
