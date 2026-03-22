package contributors

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndReadRepoCache(t *testing.T) {
	dir := t.TempDir()
	result := repoScanResult{
		repo:         "my-org/my-repo",
		totalCommits: 42,
		uniqueContributors: map[BasicContributor]Contributor{
			{Email: "alice@example.com", Repo: "my-org/my-repo"}: {
				Email: "alice@example.com",
				Name:  "Alice",
				RepoLastCommit: RepoLastCommit{
					Repo:       "my-org/my-repo",
					LastCommit: LastCommit{Date: "2024-01-01T00:00:00Z", Hash: "abc123"},
				},
			},
		},
	}

	writeRepoCache(dir, "my-org/my-repo", result, 3)

	got := readRepoCache(dir, "my-org/my-repo", 24*time.Hour)
	require.NotNil(t, got)
	assert.Equal(t, result.repo, got.repo)
	assert.Equal(t, result.totalCommits, got.totalCommits)
	// uniqueContributors round-trips through a []cacheContributorEntry slice, verify key presence.
	for k, v := range result.uniqueContributors {
		gotVal, ok := got.uniqueContributors[k]
		assert.True(t, ok, "expected key %v in cached result", k)
		assert.Equal(t, v, gotVal)
	}
}

func TestReadRepoCache_Expired(t *testing.T) {
	dir := t.TempDir()
	result := repoScanResult{repo: "repo", totalCommits: 1}
	writeRepoCache(dir, "repo", result, 1)

	// maxAge of 1 nanosecond is guaranteed to be exceeded by the time we read.
	got := readRepoCache(dir, "repo", 1*time.Nanosecond)
	assert.Nil(t, got)
}

func TestReadRepoCache_ZeroMaxAge(t *testing.T) {
	dir := t.TempDir()
	// maxAge == 0 short-circuits before any file I/O.
	got := readRepoCache(dir, "any-repo", 0)
	assert.Nil(t, got)
}

func TestReadRepoCache_Missing(t *testing.T) {
	dir := t.TempDir()
	got := readRepoCache(dir, "nonexistent-repo", 24*time.Hour)
	assert.Nil(t, got)
}
