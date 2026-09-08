package githubactions

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// RunnerWorkspaceEnvVar is the env var GitHub Actions sets to the runner's workspace directory
// (e.g. /home/runner/work/<repo>). _actions is a sibling of this directory.
const RunnerWorkspaceEnvVar = "RUNNER_WORKSPACE"

// ActionRef is one resolved action instance found in the runner's action cache.
type ActionRef struct {
	Owner string
	Repo  string
	// Ref is the literal ref string taken verbatim from the cache directory name.
	// It could be SHA, tag or branch.
	Ref string
	// Path is the absolute path to _work/_actions/<Owner>/<Repo>/<Ref>.
	Path string
	// Subpaths is filled from the job's workflow YAML uses: lines. A monorepo action (e.g.
	// github/codeql-action) can be invoked via more than one subpath from the same owner/repo/ref
	// - all distinct subpaths used are collected here
	// Parent is filled from the composite action's own action.yml when the action was pulled in transitively.
	Subpaths []string
	Parent   string
}

// DiscoverActionCache walks actionsCacheDir (the runner's _work/_actions root) exactly three
// levels deep (owner/repo/ref) and returns one ActionRef per leaf directory found.
//
// GitHub's runner downloads every referenced action into this directory before any job step runs, including
// transitive actions pulled in by another action's own action.yml that never appear in the job's own workflow file -
// so this directory is the authoritative source of which actions actually resolved.
//
// Entries that don't match the expected owner/repo/ref shape at any level are skipped, not
// treated as errors, since this walks a directory this code doesn't control the contents of.
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

// DefaultActionsCacheDir derives the runner's _actions cache path from RUNNER_WORKSPACE
// (<_work>/<repo>) - _actions is its sibling, i.e. dirname(RUNNER_WORKSPACE)/_actions.
func DefaultActionsCacheDir() (string, error) {
	runnerWorkspace := os.Getenv(RunnerWorkspaceEnvVar)
	if runnerWorkspace == "" {
		return "", fmt.Errorf("%s is not set - cannot derive the actions cache directory", RunnerWorkspaceEnvVar)
	}
	return filepath.Join(runnerWorkspace, "..", "_actions"), nil
}
