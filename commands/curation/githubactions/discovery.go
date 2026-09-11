package githubactions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// RunnerWorkspaceEnvVar is the env var GitHub Actions sets to the runner's workspace directory
// (e.g. /home/runner/work/<repo>). _actions is a sibling of this directory.
const RunnerWorkspaceEnvVar = "RUNNER_WORKSPACE"

// WorkflowRefEnvVar is the env var GitHub Actions sets to the ref path of the running workflow,
// e.g. "octocat/hello-world/.github/workflows/ci.yml@main".
const WorkflowRefEnvVar = "GITHUB_WORKFLOW_REF"

// JobIDEnvVar is the env var GitHub Actions sets to the job_id of the running job - the key
// under `jobs:` in the workflow YAML.
const JobIDEnvVar = "GITHUB_JOB"

// GithubRepoEnvVar is the env var GitHub Actions sets to the repository running the job, in
// "<owner>/<repo>" form.
const GithubRepoEnvVar = "GITHUB_REPOSITORY"

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

// DefaultWorkflowFile derives the repo-relative path of the running workflow from
// GITHUB_WORKFLOW_REF, whose shape is "<owner>/<repo>/<path/to/workflow.yml>@<ref>".
//
// Returns "" - never an error - when the variable is unset or doesn't have that shape. An
// unrecognized value must not fail the command: the caller falls back to curating the action
// cache structure alone, without parent attribution.
func DefaultWorkflowFile() string {
	workflowRef := os.Getenv(WorkflowRefEnvVar)
	if workflowRef == "" {
		return ""
	}
	// The trailing "@<ref>" is a git ref and may itself contain "/" (refs/heads/my/branch).
	if atIdx := strings.LastIndex(workflowRef, "@"); atIdx >= 0 {
		workflowRef = workflowRef[:atIdx]
	}
	// Drop the leading "<owner>/<repo>/"; the rest is the path within the repository.
	segments := strings.SplitN(workflowRef, "/", 3)
	if len(segments) < 3 || segments[2] == "" {
		log.Debug(fmt.Sprintf("github-actions curation: %s=%q is not in <owner>/<repo>/<path>@<ref> form - cannot derive the workflow file from it", WorkflowRefEnvVar, os.Getenv(WorkflowRefEnvVar)))
		return ""
	}
	return segments[2]
}

// DefaultJobID returns the running job's job_id from GITHUB_JOB, or "" when unset.
func DefaultJobID() string {
	return os.Getenv(JobIDEnvVar)
}

// DefaultGithubRepo returns the running job's repository from GITHUB_REPOSITORY ("<owner>/<repo>"),
// or "" when unset.
func DefaultGithubRepo() string {
	return os.Getenv(GithubRepoEnvVar)
}

const (
	deliveryActionOwner = "jfrog"
	deliveryActionRepo  = "setup-jfrog-cli"
)

// ExcludeDeliveryAction drops jfrog/setup-jfrog-cli from refs, at any ref, so it is neither
// decided nor reported.
func ExcludeDeliveryAction(refs []ActionRef) []ActionRef {
	kept := make([]ActionRef, 0, len(refs))
	for _, ref := range refs {
		if ref.Owner == deliveryActionOwner && ref.Repo == deliveryActionRepo {
			log.Debug(fmt.Sprintf("github-actions curation: skipping %s/%s@%s - it delivers and invokes this check rather than being subject to it", ref.Owner, ref.Repo, ref.Ref))
			continue
		}
		kept = append(kept, ref)
	}
	return kept
}
