package scm

import (
	"fmt"
	"strings"

	goGit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

type GitManager struct {
	// repository represents a git repository as a .git dir.
	localGitRepository *goGit.Repository
	// remote represents a remote server of the git repository.
	remote *goGit.Remote
}

func NewGitManager(localRepositoryWorkingDir string) (gm *GitManager, err error) {
	if localRepositoryWorkingDir == "" {
		// The Git repository project is the current directory.
		localRepositoryWorkingDir = "."
	}
	gm = &GitManager{}
	if gm.localGitRepository, err = goGit.PlainOpen(localRepositoryWorkingDir); err != nil {
		return
	}
	if gm.remote, err = gm.getRootRemote(); err != nil {
		return
	}
	return
}

func (gm *GitManager) getRootRemote() (root *goGit.Remote, err error) {
	remotes, err := gm.localGitRepository.Remotes()
	if err != nil {
		return
	}
	if len(remotes) == 0 {
		err = fmt.Errorf("no remotes found")
		return
	}
	if len(remotes) == 1 {
		return remotes[0], nil
	}
	log.Debug(fmt.Sprintf("Multiple (%d) remotes found, detecting the current active branch remote. (remotes: %v)", len(remotes), getRemoteNames(remotes...)))
	return gm.detectCurrentRemote(remotes)
}

// Try to resolve the remote of the current active branch in the project.
func (gm *GitManager) detectCurrentRemote(remotes []*goGit.Remote) (remote *goGit.Remote, err error) {
	// Get the current branch
	branchRef, err := gm.localGitRepository.Head()
	if err != nil {
		err = fmt.Errorf("failed to get the current branch: %s", err)
		return
	}
	// Get the branch configuration
	branchConfig, err := gm.localGitRepository.Config()
	if err != nil {
		err = fmt.Errorf("failed to get the repository configuration: %s", err)
		return
	}
	// Check if the current branch has a remote
	if branch, exists := branchConfig.Branches[branchRef.Name().Short()]; exists {
		// Obtain the referenced remote
		for _, remote := range remotes {
			if remote.Config().Name == branch.Remote {
				return remote, nil
			}
		}
	}
	return
}

func getRemoteNames(remotes ...*goGit.Remote) []string {
	names := []string{}
	for _, remote := range remotes {
		names = append(names, remote.Config().Name)
	}
	return names
}

// IsClean returns true if all the files are in Unmodified status.
func (gm *GitManager) isClean() (bool, error) {
	worktree, err := gm.localGitRepository.Worktree()
	if err != nil {
		return false, err
	}
	status, err := worktree.Status()
	if err != nil {
		return false, err
	}
	isClean := status.IsClean()
	if !isClean {
		log.Debug(fmt.Sprintf("Git status:\n%v", status))
	}
	return isClean, nil
}

// Detect git information
func (gm *GitManager) GetSourceControlContext() (gitInfo *services.XscGitInfoContext, err error) {
	remoteUrl, err := getRemoteUrl(gm.remote)
	if err != nil {
		return nil, err
	}
	currentBranch, err := gm.localGitRepository.Head()
	if err != nil {
		return nil, err
	}
	lastCommit, err := gm.localGitRepository.CommitObject(currentBranch.Hash())
	if err != nil {
		return nil, err
	}
	// Create the gitInfo object with known git information
	gitInfo = &services.XscGitInfoContext{
		GitProvider: getGitProvider(remoteUrl).String(),
		// Use Clone URLs as Repo Url, on browsers it will redirect to repository URLS.
		GitRepoHttpsCloneUrl: remoteUrl,
		GitRepoName:          getGitRepoName(remoteUrl),
		GitProject:           getGitProject(remoteUrl),

		BranchName: currentBranch.Name().Short(),

		LastCommitHash:    lastCommit.Hash.String(),
		LastCommitMessage: strings.TrimSpace(lastCommit.Message),
		LastCommitAuthor:  lastCommit.Author.Name,
	}
	isClean, err := gm.isClean()
	if err != nil {
		return nil, err
	}
	if !isClean {
		return nil, fmt.Errorf("uncommitted changes found in the repository, not supported in git audit")
	}
	log.Debug(fmt.Sprintf("Git Context: %+v", gitInfo))
	return gitInfo, nil
}

func getRemoteUrl(remote *goGit.Remote) (remoteUrl string, err error) {
	if remote == nil || remote.Config() == nil {
		return "", fmt.Errorf("failed to get remote information")
	}
	if len(remote.Config().URLs) == 0 {
		return "", fmt.Errorf("failed to get remote URL")
	}
	if len(remote.Config().URLs) > 1 {
		log.Warn(fmt.Sprintf("Multiple URLs found for remote, using the first one: %s from options: %v", remote.Config().URLs[0], remote.Config().URLs))
	}
	return remote.Config().URLs[0], nil
}

func (gm *GitManager) GetCommonAncestor(reference string) (ancestorCommit string, err error) {
	// Get the current branch
	currentBranch, err := gm.localGitRepository.Head()
	if err != nil {
		return
	}
	// Get the commit object of the current branch
	currentCommit, err := gm.localGitRepository.CommitObject(currentBranch.Hash())
	if err != nil {
		return
	}
	// Get the commit object of the reference
	referenceCommit, err := gm.localGitRepository.CommitObject(plumbing.NewHash(reference))
	if err != nil {
		return
	}
	// Get the common ancestor commit
	log.Debug(fmt.Sprintf("Finding common ancestor between %s and %s", currentBranch.Name().Short(), reference))
	ancestorCommitHash, err := currentCommit.MergeBase(referenceCommit)
	if err != nil {
		return
	}
	if len(ancestorCommitHash) == 0 {
		err = fmt.Errorf("no common ancestor found between %s and %s", currentBranch.Name().Short(), reference)
	} else if len(ancestorCommitHash) > 1 {
		err = fmt.Errorf("multiple common ancestors found between %s and %s", currentBranch.Name().Short(), reference)
	}
	ancestorCommit = ancestorCommitHash[0].Hash.String()
	return
}

func (gm *GitManager) Diff(reference string) (changes []diff.FilePatch, err error) {
	// Get the current branch
	currentBranch, err := gm.localGitRepository.Head()
	if err != nil {
		return
	}
	// Get the commit object of the current branch
	currentCommit, err := gm.localGitRepository.CommitObject(currentBranch.Hash())
	if err != nil {
		return
	}
	// Get the commit object of the reference
	referenceCommit, err := gm.localGitRepository.CommitObject(plumbing.NewHash(reference))
	if err != nil {
		return
	}
	// Get the diff between the current branch and the reference
	diff, err := currentCommit.Patch(referenceCommit)
	if err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Diff stats between %s and %s:\n%v", currentBranch.Name().Short(), reference, diff.Stats()))
	changes = diff.FilePatches()
	return
}

func (gm *GitManager) DiffGetRemovedContent(reference string) (changes DiffContent, err error) {
	diff, err := gm.Diff(reference)
	if err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Checking for removed content in the diff between the cwd and %s", reference))
	changes = FilePatchToDiffContent(diff...)
	return
}
