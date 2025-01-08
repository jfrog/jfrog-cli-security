package gitutils

import (
	"fmt"
	goGit "github.com/go-git/go-git/v5"

	"github.com/jfrog/jfrog-client-go/utils/log"
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
}

func (gm *GitManager) getRootRemote(priorityNames ...string) (root *goGit.Remote, err error) {
	remotes, err := gm.localGitRepository.Remotes()
	if err != nil {
		return
	}
	if len(remotes) == 0 {
		err = fmt.Errorf("No remotes found")
		return
	}
	if len(remotes) == 1 {
		return remotes[0], nil
	}
	log.Info(fmt.Sprintf("Multiple remotes found: %v", remotes))

	if len(remotes) != 1 {
		// TODO: Forked repository remote is not supported yet. (how to handle multiple remotes?)
		err = fmt.Errorf("Currently only one remote is supported, found %d remotes", len(remotes))
		return
	}
	return remotes[0], nil
}