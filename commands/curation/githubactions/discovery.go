package githubactions

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// What GitHub Actions sets on every runner.
const (
	// RunnerWorkspaceEnvVar is the workspace directory, e.g. /home/runner/work/<repo>, whose
	// sibling is _actions.
	RunnerWorkspaceEnvVar = "RUNNER_WORKSPACE"
	// WorkflowRefEnvVar is the running workflow's ref path, e.g.
	// "octocat/hello-world/.github/workflows/ci.yml@main".
	WorkflowRefEnvVar = "GITHUB_WORKFLOW_REF"
	// JobIDEnvVar is the running job's job_id - its key under `jobs:` in the workflow YAML.
	JobIDEnvVar = "GITHUB_JOB"
	// GithubRepoEnvVar is the repository running the job, as "<owner>/<repo>".
	GithubRepoEnvVar = "GITHUB_REPOSITORY"
)

// ActionRef is one resolved action instance found in the runner's action cache.
type ActionRef struct {
	Owner string
	Repo  string
	// Ref is taken verbatim from the cache directory name; it may be a SHA, tag or branch.
	Ref string
	// Path is the absolute path to _work/_actions/<Owner>/<Repo>/<Ref>.
	Path string
	// Subpaths holds every distinct subpath the job invoked this action through - a monorepo
	// action such as github/codeql-action can be used via several from one owner/repo/ref.
	Subpaths []string
	// Parent is the composite action that pulled this one in, "" when unattributed.
	Parent string
}

// UnaccountedEntry is a cache entry that exists but could not be resolved to an action.
type UnaccountedEntry struct {
	Path   string
	Reason string
}

// ActionCacheScan is what one walk of the runner's action cache found.
type ActionCacheScan struct {
	// Refs holds one entry per action the walk resolved.
	Refs []ActionRef
	// Unaccounted holds the entries it could not.
	Unaccounted []UnaccountedEntry
}

// UnaccountedError returns an error naming every entry the walk could not resolve, or nil when
// there are none.
func (s ActionCacheScan) UnaccountedError() error {
	if len(s.Unaccounted) == 0 {
		return nil
	}
	var msg strings.Builder
	msg.WriteString("cannot account for every entry in the runner's action cache, so this job cannot be reported as curated:")
	for _, entry := range s.Unaccounted {
		fmt.Fprintf(&msg, "\n  %s: %s", entry.Path, entry.Reason)
	}
	return errors.New(msg.String())
}

// DiscoverActionCache walks actionsCacheDir (the runner's _work/_actions root) and returns one
// ActionRef per action the runner resolved.
//
// The runner downloads resolved actions here before the job's steps run, including transitive
// ones pulled in by another action's action.yml that never appear in the job's own workflow
// file - so the directory is the account of what actually resolved.
//
// The layout is <owner>/<repo>/<ref>, but <ref> is a git ref and may contain "/" - a branch such
// as copilot/backport-v4 lands at <owner>/<repo>/copilot/backport-v4. So the depth of a ref is
// not fixed, and the walk asks the runner where each one ends.
//
// An entry the walk understands but that holds no action - a stray file, an owner directory with
// no repositories, a watermark - is skipped. An entry it cannot examine, or cannot resolve to a
// ref, is recorded in Unaccounted instead.
func DiscoverActionCache(actionsCacheDir string) (ActionCacheScan, error) {
	scan := ActionCacheScan{Refs: []ActionRef{}}

	ownerEntries, err := os.ReadDir(actionsCacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return scan, nil
		}
		return ActionCacheScan{}, fmt.Errorf("reading actions cache dir %q: %w", actionsCacheDir, err)
	}

	for _, ownerEntry := range ownerEntries {
		owner := ownerEntry.Name()
		ownerPath := filepath.Join(actionsCacheDir, owner)
		walkable, err := walkableDir(ownerPath, "owner")
		if err != nil {
			scan.Unaccounted = append(scan.Unaccounted, unresolvedEntry(ownerPath, err))
		}
		if !walkable {
			continue
		}

		repoEntries, err := os.ReadDir(ownerPath)
		if err != nil {
			scan.Unaccounted = append(scan.Unaccounted, unlistableEntry(ownerPath, err))
			continue
		}
		for _, repoEntry := range repoEntries {
			repo := repoEntry.Name()
			repoPath := filepath.Join(ownerPath, repo)
			walkable, err := walkableDir(repoPath, "repo")
			if err != nil {
				scan.Unaccounted = append(scan.Unaccounted, unresolvedEntry(repoPath, err))
			}
			if !walkable {
				continue
			}

			roots, unaccounted, err := scanRepo(repoPath)
			if err != nil {
				scan.Unaccounted = append(scan.Unaccounted, unlistableEntry(repoPath, err))
				continue
			}
			scan.Unaccounted = append(scan.Unaccounted, unaccounted...)
			for _, root := range roots {
				scan.Refs = append(scan.Refs, ActionRef{Owner: owner, Repo: repo, Ref: root.ref, Path: root.path})
			}
		}
	}

	// Distinct from Unaccounted: every entry here was understood, and none of them held an action.
	// Odd enough in a populated cache to say once, and cheaper than a per-entry log nobody reads.
	if len(scan.Refs) == 0 && len(scan.Unaccounted) == 0 && len(ownerEntries) > 0 {
		log.Warn(fmt.Sprintf("github-actions curation: %q holds %d entries but none resolved to an <owner>/<repo>/<ref> action, "+
			"so nothing will be curated. The debug log names every entry that was skipped.", actionsCacheDir, len(ownerEntries)))
	}
	return scan, nil
}

// watermarkSuffix names the file the runner writes beside an action it extracted:
// _actions/<owner>/<repo>/<ref>.completed, at whatever depth <ref> lands.
const watermarkSuffix = ".completed"

// actionRoot is one resolved action: the ref that names it, and the directory holding it.
type actionRoot struct {
	ref  string
	path string
}

// scanRepo finds the action roots under one <owner>/<repo> directory, and the entries under it
// that no action root could be made of.
func scanRepo(repoPath string) (roots []actionRoot, unaccounted []UnaccountedEntry, err error) {
	refEntries, err := os.ReadDir(repoPath)
	if err != nil {
		return nil, nil, err
	}
	watermarked := watermarkedNames(refEntries)
	for _, refEntry := range refEntries {
		if isWatermarkFile(refEntry) {
			continue
		}
		refPath := filepath.Join(repoPath, refEntry.Name())
		walkable, statErr := walkableDir(refPath, "ref")
		if statErr != nil {
			unaccounted = append(unaccounted, unresolvedEntry(refPath, statErr))
		}
		if !walkable {
			continue
		}
		entryRoots, entryUnaccounted := actionRootsUnder(refPath, refEntry.Name(), watermarked)
		unaccounted = append(unaccounted, entryUnaccounted...)
		switch {
		case len(entryRoots) > 0:
			roots = append(roots, entryRoots...)
		case len(entryUnaccounted) > 0:
			// Already recorded, with the reason the descent stopped. Naming it again for a missing
			// marker would report one entry twice and blame the marker for a failure to read.
		default:
			unaccounted = append(unaccounted, UnaccountedEntry{
				Path:   refPath,
				Reason: fmt.Sprintf("nothing at or below it carries a %s marker or is a symlink, so no action ref can be read from it", watermarkSuffix),
			})
		}
	}
	return roots, unaccounted, nil
}

// actionRootsUnder returns every action root at or below dir, with ref accumulated from the path
// segments walked to reach it. It returns no roots when no marker is found, leaving what that
// means to the caller.
//
// watermarked holds the names in dir's own parent that carry a marker, so dir's root-ness comes
// out of a listing the caller already read.
//
// The descent is bounded by the cache's own shape rather than by a depth limit: a ref's
// intermediate directories hold nothing but the next segment, so the first directory holding
// content of its own is where a ref can no longer continue. A guess at a maximum segment count
// would instead have to be wrong in one direction or the other - stopping short of a marker on a
// legitimately deep branch ref, or walking several levels into an action that carries no marker.
func actionRootsUnder(dir, ref string, watermarked map[string]bool) (roots []actionRoot, unaccounted []UnaccountedEntry) {
	if isActionRoot(dir, watermarked) {
		return []actionRoot{{ref: ref, path: dir}}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []UnaccountedEntry{unlistableEntry(dir, err)}
	}
	if !isRefPathSegment(entries) {
		log.Debug(fmt.Sprintf("github-actions curation: not descending past %q - it holds content of its own, so no ref continues through it", dir))
		return nil, nil
	}
	childWatermarks := watermarkedNames(entries)
	for _, entry := range entries {
		if isWatermarkFile(entry) {
			continue
		}
		child := filepath.Join(dir, entry.Name())
		walkable, err := walkableDir(child, "ref")
		if err != nil {
			unaccounted = append(unaccounted, unresolvedEntry(child, err))
		}
		if !walkable {
			continue
		}
		childRoots, childUnaccounted := actionRootsUnder(child, ref+"/"+entry.Name(), childWatermarks)
		roots = append(roots, childRoots...)
		unaccounted = append(unaccounted, childUnaccounted...)
	}
	return roots, unaccounted
}

// isActionRoot reports whether dir is where a ref ends and an action's own content begins.
//
// The runner marks that boundary itself, in the only two ways it materializes an entry: it
// writes <dir>.completed beside a directory it extracted, or - when serving from the archive
// cache - it makes dir a symlink to the unpacked copy and returns before writing any watermark.
// Neither marker appears on a subpath inside an action, which is what keeps a monorepo action
// like github/codeql-action@v3 from being reported as v3/analyze and v3/init.
func isActionRoot(dir string, watermarked map[string]bool) bool {
	return watermarked[filepath.Base(dir)] || isSymlink(dir)
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// watermarkedNames returns the names in one directory listing that a .completed file marks.
func watermarkedNames(entries []os.DirEntry) map[string]bool {
	watermarked := map[string]bool{}
	for _, entry := range entries {
		if isWatermarkFile(entry) {
			watermarked[strings.TrimSuffix(entry.Name(), watermarkSuffix)] = true
		}
	}
	return watermarked
}

// isWatermarkFile reports whether entry is a watermark rather than something to walk. The
// directory test matters: a ref may legitimately end in ".completed".
func isWatermarkFile(entry os.DirEntry) bool {
	return !entry.IsDir() && strings.HasSuffix(entry.Name(), watermarkSuffix)
}

// isRefPathSegment reports whether a directory holding these entries is one a ref passes through,
// as opposed to one an action's own content begins in. A ref's intermediate directories hold only
// the next segment, plus - at the last of them - that segment's watermark. Any other regular file
// is content, and a ref never continues below an action's content.
//
// Only regular files count. A symlinked entry is a ref the runner served from the archive cache,
// and DirEntry reports it by the directory entry's own type rather than the target's - so testing
// for a directory here would end the descent on exactly those entries.
func isRefPathSegment(entries []os.DirEntry) bool {
	for _, entry := range entries {
		if entry.Type().IsRegular() && !isWatermarkFile(entry) {
			return false
		}
	}
	return true
}

// unresolvedEntry records an entry that exists but cannot be classified at all.
func unresolvedEntry(path string, err error) UnaccountedEntry {
	return UnaccountedEntry{Path: path, Reason: fmt.Sprintf("cannot be resolved: %v", err)}
}

// unlistableEntry records a directory whose contents could not be read.
func unlistableEntry(path string, err error) UnaccountedEntry {
	return UnaccountedEntry{Path: path, Reason: fmt.Sprintf("cannot be listed: %v", err)}
}

// walkableDir reports whether path resolves to a directory.
func walkableDir(path, level string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		log.Debug(fmt.Sprintf("github-actions curation: skipping non-directory entry %q at %s level", path, level))
		return false, nil
	}
	return true, nil
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
// decided nor reported. Owner and repo are matched case-insensitively.
func ExcludeDeliveryAction(refs []ActionRef) []ActionRef {
	kept := make([]ActionRef, 0, len(refs))
	for _, ref := range refs {
		if strings.EqualFold(ref.Owner, deliveryActionOwner) && strings.EqualFold(ref.Repo, deliveryActionRepo) {
			log.Debug(fmt.Sprintf("github-actions curation: skipping %s/%s@%s - it delivers and invokes this check rather than being subject to it", ref.Owner, ref.Repo, ref.Ref))
			continue
		}
		kept = append(kept, ref)
	}
	return kept
}
