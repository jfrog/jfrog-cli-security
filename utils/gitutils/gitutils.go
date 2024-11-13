package gitutils

import (
	"fmt"
	"strings"

	goGit "github.com/go-git/go-git/v5"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
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

func DetectGitInfo() (gitManager *GitManager, gitInfo *services.XscGitInfoContext, err error) {
	gitManager, err = NewGitManager(".")
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to found local git repository at the current directory: %v", err)
	}
	gitInfo, err = GetGitContext(gitManager)
	return
}

func GetGitContext(manager *GitManager) (gitInfo *services.XscGitInfoContext, err error) {
	remoteUrl, err := getRemoteUrl(manager.remote)
	if err != nil {
		return nil, err
	}
	currentBranch, err := manager.localGitRepository.Head()
	if err != nil {
		return nil, err
	}
	lastCommit, err := manager.localGitRepository.CommitObject(currentBranch.Hash())
	if err != nil {
		return nil, err
	}
	// Create the gitInfo object with known git information
	gitInfo = &services.XscGitInfoContext{
		// Use Clone URLs as Repo Url, on browsers it will redirect to repository URLS.
		GitRepoUrl:        remoteUrl,
		GitRepoName:       getGitRepoName(remoteUrl),
		GitProject:        getGitProject(remoteUrl),
		GitProvider:       getGitProvider(remoteUrl).String(),
		BranchName:        currentBranch.Name().Short(),
		LastCommitHash:    lastCommit.Hash.String(),
		LastCommitMessage: strings.TrimSpace(lastCommit.Message),
		LastCommitAuthor:  lastCommit.Author.Name,
	}
	isClean, err := manager.IsClean()
	if err != nil {
		return nil, err
	}
	gitInfo.IsDirty = !isClean
	log.Debug(fmt.Sprintf("Git Context: %+v", gitInfo))
	return gitInfo, nil
}

func getRemoteUrl(remote *goGit.Remote) (remoteUrl string, err error) {
	if remote == nil || remote.Config() == nil {
		return "", fmt.Errorf("Failed to get remote information")
	}
	if len(remote.Config().URLs) == 0 {
		return "", fmt.Errorf("Failed to get remote URL")
	}
	if len(remote.Config().URLs) > 1 {
		log.Warn(fmt.Sprintf("Multiple URLs found for remote, using the first one: %s from options: %v", remote.Config().URLs[0], remote.Config().URLs))
	}
	return remote.Config().URLs[0], nil
}

func NormalizeGitUrl(url string) string {
	// Normalize the URL by removing "http://", "https://", and any trailing ".git"
	url = strings.TrimSuffix(strings.TrimPrefix(url, "http://"), ".git")
	url = strings.TrimSuffix(strings.TrimPrefix(url, "https://"), ".git")
	return url
}

func getGitRepoName(url string) string {
	urlParts := strings.Split(NormalizeGitUrl(url), "/")
	return urlParts[len(urlParts)-1]
}

func getGitProject(url string) string {
	// In some VCS providers, there are no git projects, fallback to the repository owner.
	if gitProject == "" {
		gitProject = sc.RepoOwner
	}
	urlParts := strings.Split(url, "/")
	return urlParts[len(urlParts)-2]
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
