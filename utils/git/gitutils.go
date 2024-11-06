package git

import (
	"fmt"
	"strings"

	goGit "github.com/go-git/go-git/v5"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	Github         GitProvider = "github"
	Gitlab         GitProvider = "gitlab"
	Bitbucket      GitProvider = "bitbucket"
	Azure 		   GitProvider = "azure"
	Other          GitProvider = ""
)
type GitProvider string

func (gp GitProvider) String() string {
	return string(gp)
}

func NormalizeGitUrl(url string) string {
	// Normalize the URL by removing "http://", "https://", and any trailing ".git"
	url = strings.TrimSuffix(strings.TrimPrefix(url, "http://"), ".git")
	url = strings.TrimSuffix(strings.TrimPrefix(url, "https://"), ".git")
	return url
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
	// Create the gitInfo object
	gitInfo = &services.XscGitInfoContext{
		GitRepoUrl: remoteUrl,
		GitRepoName: getGitRepoName(remoteUrl),
		GitProject: getGitProject(remoteUrl),
		GitProvider: getGitProvider(remoteUrl).String(),
		BranchName: currentBranch.Name().Short(),
		LastCommit:   lastCommit.Hash.String(),
	}
	isLocalRepoClean, err := manager.IsClean()
	if err != nil {
		return nil, err
	}
	if isLocalRepoClean {
		gitInfo.CommitHash = lastCommit.Hash.String()
		gitInfo.CommitMessage = strings.TrimSpace(lastCommit.Message)
		gitInfo.CommitAuthor = lastCommit.Author.Name
	}
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

func getGitRepoName(url string) string {
	urlParts := strings.Split(url, "/")
	return strings.TrimSuffix(urlParts[len(urlParts)-1], ".git")
}

func getGitProject(url string) string {
	urlParts := strings.Split(url, "/")
	return urlParts[len(urlParts)-2]
}

func getGitProvider(url string) GitProvider {
	if strings.Contains(url, "github") {
		return Github
	}
	if strings.Contains(url, "gitlab") {
		return Gitlab
	}
	if strings.Contains(url, "bitbucket") {
		return Bitbucket
	}
	if strings.Contains(url, "dev.azure.com") {
		return Azure
	}

	log.Warn(fmt.Sprintf("Unknown git provider for URL: %s", url))
	return Other
}