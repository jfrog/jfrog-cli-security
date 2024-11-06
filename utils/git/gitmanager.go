package git

import (
	"fmt"

	goGit "github.com/go-git/go-git/v5"
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
	// gm.localGitRepository.Remotes()
	// gitRemote, err := gm.localGitRepository.Remote(gm.remoteName)
	// if err != nil {
	// 	return nil, fmt.Errorf("'git remote %s' failed with error: %s", gm.remoteName, err.Error())
	// }

	// if len(gitRemote.Config().URLs) < 1 {
	// 	return nil, errors.New("failed to find git remote URL")
	// }

	// gm.remoteGitUrl = gitRemote.Config().URLs[0]

	// // If the remote URL in the .git directory is not using the HTTPS protocol, update remoteGitUrl to use HTTPS protocol.
	// if !strings.HasPrefix(gm.remoteGitUrl, "https://") {
	// 	gm.remoteGitUrl = remoteHttpsGitUrl
	// }
	return
}

func (gm *GitManager) getRootRemote() (root *goGit.Remote, err error) {
	remotes, err := gm.localGitRepository.Remotes()
	if err != nil {
		return
	}
	if len(remotes) != 1 {
		// TODO: Forked repository remote is not supported yet. (how to handle multiple remotes?)
		err = fmt.Errorf("Currently only one remote is supported, found %d remotes", len(remotes))
		return
	}
	return remotes[0], nil
}

// IsClean returns true if all the files are in Unmodified status.
func (gm *GitManager) IsClean() (bool, error) {
	worktree, err := gm.localGitRepository.Worktree()
	if err != nil {
		return false, err
	}
	status, err := worktree.Status()
	if err != nil {
		return false, err
	}

	return status.IsClean(), nil
}