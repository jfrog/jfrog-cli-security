package gitutils

import (
	"fmt"
	"strings"

	goGit "github.com/go-git/go-git/v5"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

const (
	Github    GitProvider = "github"
	Gitlab    GitProvider = "gitlab"
	Bitbucket GitProvider = "bitbucket"
	Azure     GitProvider = "azure"
	Unknown   GitProvider = ""
)

type GitProvider string

func (gp GitProvider) String() string {
	return string(gp)
}

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
	// TODO: Forked repository remote is not supported yet. (how to handle multiple remotes?)
	err = fmt.Errorf("multiple (%d) remotes found, currently only one remote is supported, remotes: %s", len(remotes), strings.Join(getRemoteNames(remotes...), ", "))
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

func (gm *GitManager) GetGitContext() (gitInfo *services.XscGitInfoContext, err error) {
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
	isClean, err := gm.IsClean()
	if err != nil {
		return nil, err
	}
	if !isClean {
		log.Warn("Uncommitted changes found in the repository, not supported in git audit.")
		return nil, nil
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

func normalizeGitUrl(url string) string {
	// Normalize the URL by removing "http://", "https://", and any trailing ".git"
	url = strings.TrimSuffix(strings.TrimPrefix(url, "http://"), ".git")
	url = strings.TrimSuffix(strings.TrimPrefix(url, "https://"), ".git")
	return url
}

func getGitRepoName(url string) string {
	urlParts := strings.Split(normalizeGitUrl(url), "/")
	return urlParts[len(urlParts)-1]
}

func getGitProject(url string) string {
	// First part after base Url is the owner/organization name.
	urlParts := strings.Split(url, "/")
	if len(urlParts) < 2 {
		log.Debug(fmt.Sprintf("Failed to get project name from URL: %s", url))
		return ""
	}
	return urlParts[1]
}

func getGitProvider(url string) GitProvider {
	if strings.Contains(url, Github.String()) {
		return Github
	}
	if strings.Contains(url, Gitlab.String()) {
		return Gitlab
	}
	if strings.Contains(url, Bitbucket.String()) {
		return Bitbucket
	}
	if strings.Contains(url, Azure.String()) {
		return Azure
	}
	// Unknown for self-hosted git providers
	log.Debug(fmt.Sprintf("Unknown git provider for URL: %s", url))
	return Unknown
}
