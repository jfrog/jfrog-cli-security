package githubactions

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// GithubWorkspaceEnvVar is the env var GitHub Actions sets to the checked-out repo's root
// (e.g. /home/runner/work/<repo>/<repo>).
const GithubWorkspaceEnvVar = "GITHUB_WORKSPACE"

// ActionRef is one resolved action instance found in the runner's action cache.
type ActionRef struct {
	Owner string
	Repo  string
	// Ref is the literal ref string taken verbatim from the cache directory name.
	// It is intentionally uninterpreted here - classifying it as a SHA or a mutable
	// tag/branch can't be done reliably from the string alone, so that responsibility
	// belongs to whatever calls the real decision service.
	Ref string
	// Path is the absolute path to _work/_actions/<Owner>/<Repo>/<Ref>.
	Path string
	// Subpath and Parent are filled in by CrossReference, not by DiscoverActionCache.
	Subpath string
	Parent  string
}

// DiscoverActionCache walks actionsCacheDir (the runner's _work/_actions root) exactly three
// levels deep (owner/repo/ref) and returns one ActionRef per leaf directory found.
//
// GitHub's runner downloads every referenced action into this directory before any job step
// runs, including transitive actions pulled in by another action's own action.yml that never
// appear in the job's own workflow file - so this directory, not the workflow YAML, is the
// authoritative source of which actions actually resolved.
//
// A missing actionsCacheDir returns an empty (non-nil) slice and no error - the caller decides
// whether that's fatal (e.g. not running under a GitHub Actions runner at all). Entries that
// don't match the expected owner/repo/ref shape at any level are skipped, not treated as errors,
// since this walks a directory this code doesn't control the contents of.
func DiscoverActionCache(actionsCacheDir string) ([]ActionRef, error) {
	refs := []ActionRef{}

	ownerEntries, err := os.ReadDir(actionsCacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return refs, nil
		}
		return nil, fmt.Errorf("reading actions cache dir %q: %w", actionsCacheDir, err)
	}

	for _, ownerEntry := range ownerEntries {
		if !ownerEntry.IsDir() {
			log.Debug(fmt.Sprintf("github-actions curation: skipping non-directory entry %q at owner level", ownerEntry.Name()))
			continue
		}
		owner := ownerEntry.Name()
		ownerPath := filepath.Join(actionsCacheDir, owner)

		repoEntries, err := os.ReadDir(ownerPath)
		if err != nil {
			log.Debug(fmt.Sprintf("github-actions curation: skipping owner dir %q: %v", ownerPath, err))
			continue
		}
		for _, repoEntry := range repoEntries {
			if !repoEntry.IsDir() {
				log.Debug(fmt.Sprintf("github-actions curation: skipping non-directory entry %q at repo level", repoEntry.Name()))
				continue
			}
			repo := repoEntry.Name()
			repoPath := filepath.Join(ownerPath, repo)

			refEntries, err := os.ReadDir(repoPath)
			if err != nil {
				log.Debug(fmt.Sprintf("github-actions curation: skipping repo dir %q: %v", repoPath, err))
				continue
			}
			for _, refEntry := range refEntries {
				if !refEntry.IsDir() {
					log.Debug(fmt.Sprintf("github-actions curation: skipping non-directory entry %q at ref level", refEntry.Name()))
					continue
				}
				refs = append(refs, ActionRef{
					Owner: owner,
					Repo:  repo,
					Ref:   refEntry.Name(),
					Path:  filepath.Join(repoPath, refEntry.Name()),
				})
			}
		}
	}
	return refs, nil
}

// DefaultActionsCacheDir derives the runner's _work/_actions path from GITHUB_WORKSPACE.
// GitHub Actions' documented layout is <_work>/<repo>/<repo> for the workspace and
// <_work>/_actions for the actions cache - one level up from the workspace, then into _actions.
func DefaultActionsCacheDir() (string, error) {
	workspace := os.Getenv(GithubWorkspaceEnvVar)
	if workspace == "" {
		return "", fmt.Errorf("%s is not set - cannot derive the actions cache directory", GithubWorkspaceEnvVar)
	}
	return filepath.Join(workspace, "..", "_actions"), nil
}
