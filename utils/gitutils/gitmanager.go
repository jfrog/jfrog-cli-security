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

	// TODO: Add support for other git providers

	// git clone https://sourceforge.net/projects/svn-sample-repo/
	SourceForge GitProvider = "sourceforge"
	// git clone https://git-codecommit.{region}.amazonaws.com/v1/repos/{repository_name}
	AWSCodeCommit GitProvider = "codecommit"
	// git clone https://gerrit.googlesource.com/git-repo
	Gerrit GitProvider = "gerrit"
	// git clone https://gitea.com/gitea/helm-chart.git
	Gitea GitProvider = "gitea"

	Unknown GitProvider = ""
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

// Detect git information
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

// Normalize the URL by removing protocol prefix and any trailing ".git"
func normalizeGitUrl(url string) string {
	// jfrog-ignore - false positive, not used for communication
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "ssh://")
	return strings.TrimSuffix(url, ".git")
}

func getGitRepoName(url string) string {
	urlParts := strings.Split(normalizeGitUrl(url), "/")
	return urlParts[len(urlParts)-1]
}

func getGitProject(url string) string {
	// First part after base Url is the owner or the organization name.
	urlParts := strings.Split(normalizeGitUrl(url), "/")
	if len(urlParts) < 2 {
		log.Debug(fmt.Sprintf("Failed to get project name from URL: %s", url))
		return ""
	}
	if len(urlParts) > 2 && urlParts[1] == "scm" {
		// In BB https clone url looks like this: https://git.id.info/scm/repo-name/repo-name.git --> ['git.id.info', 'scm', 'repo-name', 'repo-name']
		return urlParts[2]
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
	if isBitbucketProvider(url) {
		return Bitbucket
	}
	if strings.Contains(url, Azure.String()) {
		return Azure
	}
	// Unknown for self-hosted git providers
	log.Debug(fmt.Sprintf("Unknown git provider for URL: %s", url))
	return Unknown
}

func isBitbucketProvider(url string) bool {
	if urlParts := strings.Split(normalizeGitUrl(url), "/"); len(urlParts) > 2 && urlParts[1] == "scm" {
		return true
	}
	if projectName := getGitProject(url); strings.Contains(projectName, "~") {
		return true
	}
	return strings.Contains(url, Bitbucket.String())
}
