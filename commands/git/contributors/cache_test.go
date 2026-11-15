package contributors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

func TestWriteAndReadRepoCache_SubgroupRepoPath(t *testing.T) {
	dir := t.TempDir()
	// GitLab projects in subgroups are reported as a path relative to the owner group, which contains '/'.
	const repo = "team-a/nested/my-repo"
	result := repoScanResult{repo: repo, totalCommits: 7}
	writeRepoCache(dir, repo, result, 1)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.NotContains(t, entries[0].Name(), "/")
	assert.True(t, strings.HasSuffix(entries[0].Name(), ".json"), entries[0].Name())

	got := readRepoCache(dir, repo, 24*time.Hour)
	require.NotNil(t, got)
	assert.Equal(t, repo, got.repo)
	assert.Equal(t, 7, got.totalCommits)
}

func TestReadRepoCache_SanitizedNameCollision(t *testing.T) {
	dir := t.TempDir()
	// "team-a/repo" and "team-a_repo" have the same sanitized name. Each must get its own cache file,
	// and the cache of one must never be served for the other.
	assert.NotEqual(t, repoCacheFilePath(dir, "team-a/repo"), repoCacheFilePath(dir, "team-a_repo"))

	writeRepoCache(dir, "team-a/repo", repoScanResult{repo: "team-a/repo", totalCommits: 3}, 1)
	assert.Nil(t, readRepoCache(dir, "team-a_repo", 24*time.Hour))

	writeRepoCache(dir, "team-a_repo", repoScanResult{repo: "team-a_repo", totalCommits: 5}, 1)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	got := readRepoCache(dir, "team-a/repo", 24*time.Hour)
	require.NotNil(t, got)
	assert.Equal(t, 3, got.totalCommits)
	got = readRepoCache(dir, "team-a_repo", 24*time.Hour)
	require.NotNil(t, got)
	assert.Equal(t, 5, got.totalCommits)
}

func TestReadRepoCache_IgnoresFileOfOtherRepo(t *testing.T) {
	dir := t.TempDir()
	// A cache file whose content belongs to another repository is ignored, even when it is not expired.
	result := repoScanResult{repo: "other-repo", totalCommits: 9}
	writeRepoCache(dir, "other-repo", result, 1)
	data, err := os.ReadFile(repoCacheFilePath(dir, "other-repo"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(repoCacheFilePath(dir, "my-repo"), data, 0600))

	assert.Nil(t, readRepoCache(dir, "my-repo", 24*time.Hour))
}

func TestRepoCacheFilePath_BoundedLength(t *testing.T) {
	dir := t.TempDir()
	// GitLab allows up to 20 nested subgroups of up to 255 characters each, so the repository path can be far longer
	// than a file name may be. The readable prefix is bounded, and the digest keeps long paths distinct.
	longPrefix := strings.Repeat("sub-group-with-a-long-name/", 20)
	repoA := longPrefix + "repo-a"
	repoB := longPrefix + "repo-b"

	pathA := repoCacheFilePath(dir, repoA)
	pathB := repoCacheFilePath(dir, repoB)
	assert.NotEqual(t, pathA, pathB)
	for _, path := range []string{pathA, pathB} {
		name := filepath.Base(path)
		assert.LessOrEqual(t, len(name+".tmp"), 255, name)
		assert.True(t, strings.HasSuffix(name, ".json"), name)
	}

	writeRepoCache(dir, repoA, repoScanResult{repo: repoA, totalCommits: 1}, 1)
	writeRepoCache(dir, repoB, repoScanResult{repo: repoB, totalCommits: 2}, 1)
	got := readRepoCache(dir, repoA, 24*time.Hour)
	require.NotNil(t, got)
	assert.Equal(t, 1, got.totalCommits)
	got = readRepoCache(dir, repoB, 24*time.Hour)
	require.NotNil(t, got)
	assert.Equal(t, 2, got.totalCommits)
}

func TestRepoCacheFilePath_DoesNotSplitMultiByteCharacter(t *testing.T) {
	repo := strings.Repeat("a", maxCacheFileNamePrefixLength-1) + "é" + "/repo"
	name := filepath.Base(repoCacheFilePath(t.TempDir(), repo))
	assert.True(t, utf8.ValidString(name), name)
	assert.True(t, strings.HasPrefix(name, strings.Repeat("a", maxCacheFileNamePrefixLength-1)+"-"), name)
}

func TestRepoCacheFilePath_BoundedLengthWithMultiByteCharacters(t *testing.T) {
	// Multi-byte characters are the worst case for the byte budget: 2 bytes per visible character.
	repo := strings.Repeat("é/", 200) + "repo"
	name := filepath.Base(repoCacheFilePath(t.TempDir(), repo))
	assert.LessOrEqual(t, len(name+".tmp"), 255, name)
	assert.True(t, utf8.ValidString(name), name)
	assert.True(t, strings.HasPrefix(name, "é_é_"), name)
}

func TestRepoCacheFilePath_InvalidUTF8KeepsReadablePrefix(t *testing.T) {
	// An invalid byte early in the path must not erase the readable prefix that follows it.
	repo := "team-\xff/" + strings.Repeat("a", maxCacheFileNamePrefixLength) + "/repo"
	name := filepath.Base(repoCacheFilePath(t.TempDir(), repo))
	assert.True(t, utf8.ValidString(name), name)
	assert.True(t, strings.HasPrefix(name, "team-__"+strings.Repeat("a", 20)), name)
	assert.LessOrEqual(t, len(name+".tmp"), 255, name)
}

func TestWriteRepoCache_RemovesLegacyFile(t *testing.T) {
	dir := t.TempDir()
	const repo = "team-a/repo"
	// Older versions named the file after the sanitized repository path only.
	legacyPath := filepath.Join(dir, "team-a_repo.json")
	require.NoError(t, os.WriteFile(legacyPath, []byte("{}"), 0600))

	writeRepoCache(dir, repo, repoScanResult{repo: repo, totalCommits: 1}, 1)

	_, err := os.Stat(legacyPath)
	assert.True(t, os.IsNotExist(err), "legacy cache file must be removed")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	require.NotNil(t, readRepoCache(dir, repo, 24*time.Hour))
}

func TestWriteRepoCache_StoresRequestedRepo(t *testing.T) {
	dir := t.TempDir()
	// The stored repository is the one the file name is derived from, even if the result carries another value,
	// otherwise readRepoCache would reject the file forever.
	writeRepoCache(dir, "team-a/repo", repoScanResult{repo: "", totalCommits: 4}, 1)
	got := readRepoCache(dir, "team-a/repo", 24*time.Hour)
	require.NotNil(t, got)
	assert.Equal(t, "team-a/repo", got.repo)
	assert.Equal(t, 4, got.totalCommits)
}

func TestSanitizeFilename(t *testing.T) {
	assert.Equal(t, "a_b_c_d", sanitizeFilename("a/b\\c:d"))
	assert.Equal(t, "repo__name_", sanitizeFilename("repo\x00\nname\t"))
	assert.Equal(t, "plain-repo.v2", sanitizeFilename("plain-repo.v2"))
	// Multi-byte characters are kept intact, invalid UTF-8 is replaced.
	assert.Equal(t, "équipe_dépôt", sanitizeFilename("équipe/dépôt"))
	assert.Equal(t, "team-__repo", sanitizeFilename("team-\xff/repo"))
}
