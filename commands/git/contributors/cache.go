package contributors

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	secutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// cacheContributorEntry serializes one entry of the uniqueContributors map.
// Go's encoding/json does not support struct keys in maps, so we use a slice instead.
type cacheContributorEntry struct {
	Key   BasicContributor `json:"key"`
	Value Contributor      `json:"value"`
}

const (
	DefaultCacheValidity = 3 // days
)

// repoCacheFile holds the data persisted to disk for one fully-scanned repository.
type repoCacheFile struct {
	Repo                 string                                           `json:"repo"`
	ScannedAt            string                                           `json:"scanned_at"`
	Months               int                                              `json:"last_months_analyzed"`
	UniqueContributors   []cacheContributorEntry                          `json:"unique_contributors"`
	DetailedContributors map[string]map[string]ContributorDetailedSummary `json:"detailed_contributors,omitempty"`
	DetailedRepos        map[string]map[string]RepositoryDetailedSummary  `json:"detailed_repos,omitempty"`
	TotalCommits         int                                              `json:"total_commits"`
	Skipped              bool                                             `json:"skipped,omitempty"`
}

// getRepoCacheDir returns (and creates) the cache directory for a specific combination of
// scm-type / scm-api-url / owner / months so caches never collide across configurations.
func getRepoCacheDir(params BasicGitServerParams, months int) (string, error) {
	base, err := secutils.GetContributorsCacheDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine contributors cache directory: %w", err)
	}
	key := fmt.Sprintf("%d|%s|%s|%d", params.ScmType, params.ScmApiUrl, params.Owner, months)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	dir := filepath.Join(base, hash)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create cache directory %s: %w", dir, err)
	}
	return dir, nil
}

// readRepoCache reads the cache entry for repo. Returns nil when the file does not exist
// or when the entry is older than maxAge. maxAge == 0 means "always expired" (skip cache).
func readRepoCache(cacheDir, repo string, maxAge time.Duration) *repoScanResult {
	if maxAge <= 0 {
		return nil
	}
	path := repoCacheFilePath(cacheDir, repo)
	data, err := os.ReadFile(path)
	if err != nil {
		// File simply doesn't exist yet — not an error worth logging.
		return nil
	}
	var entry repoCacheFile
	if err = json.Unmarshal(data, &entry); err != nil {
		log.Warn(fmt.Sprintf("Contributors cache: failed to parse cache file %s: %v", path, err))
		return nil
	}
	if entry.Repo != repo {
		log.Debug(fmt.Sprintf("Contributors cache: file %s belongs to repo %q, not %q. Ignoring it.", path, entry.Repo, repo))
		return nil
	}
	scannedAt, err := time.Parse(time.RFC3339, entry.ScannedAt)
	if err != nil {
		log.Warn(fmt.Sprintf("Contributors cache: invalid scanned_at in %s: %v", path, err))
		return nil
	}
	if time.Since(scannedAt) > maxAge {
		log.Debug(fmt.Sprintf("Contributors cache: entry for %q expired (scanned %s ago)", repo, time.Since(scannedAt).Round(time.Second)))
		return nil
	}
	log.Debug(fmt.Sprintf("Contributors cache: using cached data for repo %q (scanned at %s)", repo, entry.ScannedAt))
	uniqueContributors := make(map[BasicContributor]Contributor, len(entry.UniqueContributors))
	for _, e := range entry.UniqueContributors {
		uniqueContributors[e.Key] = e.Value
	}
	return &repoScanResult{
		repo:                 entry.Repo,
		uniqueContributors:   uniqueContributors,
		detailedContributors: entry.DetailedContributors,
		detailedRepos:        entry.DetailedRepos,
		totalCommits:         entry.TotalCommits,
		skipped:              entry.Skipped,
	}
}

// writeRepoCache persists the scan result for repo to disk atomically (write tmp → rename).
func writeRepoCache(cacheDir, repo string, result repoScanResult, months int) {
	uniqueEntries := make([]cacheContributorEntry, 0, len(result.uniqueContributors))
	for k, v := range result.uniqueContributors {
		uniqueEntries = append(uniqueEntries, cacheContributorEntry{Key: k, Value: v})
	}
	entry := repoCacheFile{
		Repo:                 result.repo,
		ScannedAt:            time.Now().UTC().Format(time.RFC3339),
		Months:               months,
		UniqueContributors:   uniqueEntries,
		DetailedContributors: result.detailedContributors,
		DetailedRepos:        result.detailedRepos,
		TotalCommits:         result.totalCommits,
		Skipped:              result.skipped,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		log.Warn(fmt.Sprintf("Contributors cache: failed to marshal cache for repo %q: %v", repo, err))
		return
	}
	finalPath := repoCacheFilePath(cacheDir, repo)
	tmpPath := finalPath + ".tmp"
	if err = os.WriteFile(tmpPath, data, 0600); err != nil {
		log.Warn(fmt.Sprintf("Contributors cache: failed to write tmp file %s: %v", tmpPath, err))
		return
	}
	if err = os.Rename(tmpPath, finalPath); err != nil {
		log.Warn(fmt.Sprintf("Contributors cache: failed to rename %s → %s: %v", tmpPath, finalPath, err))
		_ = os.Remove(tmpPath)
	}
}

// maxCacheFileNamePrefixLength bounds the readable part of a cache file name. Together with the digest, ".json" and
// the ".tmp" suffix of the temporary file, the resulting names stay well below the 255 byte limit of common file systems,
// whatever the length of the repository path (GitLab allows deeply nested subgroups).
const maxCacheFileNamePrefixLength = 100

// repoCacheFilePath returns the cache file for a repository. The name keeps a (sanitized, bounded) prefix of the
// repository path for readability and ends with a digest of the exact path, so that repositories whose sanitized
// names are identical (for example the GitLab subgroup project "team-a/repo" and the project "team-a_repo") or
// whose names only differ beyond the bounded prefix never share a file.
func repoCacheFilePath(cacheDir, repo string) string {
	prefix := sanitizeFilename(repo)
	if len(prefix) > maxCacheFileNamePrefixLength {
		prefix = prefix[:maxCacheFileNamePrefixLength]
		// Do not cut a multi-byte character in half.
		for !utf8.ValidString(prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	digest := sha256.Sum256([]byte(repo))
	return filepath.Join(cacheDir, fmt.Sprintf("%s-%x.json", prefix, digest[:8]))
}

// sanitizeFilename replaces characters that are unsafe in file names (e.g. '/' in repo paths).
func sanitizeFilename(name string) string {
	safe := make([]byte, len(name))
	for i := range name {
		c := name[i]
		if c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' {
			safe[i] = '_'
		} else {
			safe[i] = c
		}
	}
	return string(safe)
}
