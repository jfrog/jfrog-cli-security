package scm

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
)

const (
	Github        ScProvider = "github"
	Gitlab        ScProvider = "gitlab"
	Bitbucket     ScProvider = "bitbucket"
	Azure         ScProvider = "azure"
	Gerrit        ScProvider = "gerrit"
	Gitea         ScProvider = "gitea"
	AWSCodeCommit ScProvider = "codecommit"

	Unknown ScProvider = ""
)

// ScProvider is the type of source control provider
type ScProvider string

func (sp ScProvider) String() string {
	return string(sp)
}

const (
	Git ScType = "git"
)

// ScType is the type of source control manager
type ScType string

func (st ScType) String() string {
	return string(st)
}

// ScmTypeData holds the data for each source control manager type
type ScmTypeData struct {
	indicator string
}

var supportedScmTypes = map[ScType]ScmTypeData{Git: {".git"}}

type ScmManager interface {
	GetSourceControlContext() (gitInfo *services.XscGitInfoContext, err error)
}

func DetectScmInProject(projectPath string) (manager ScmManager, err error) {
	for scmType, scmData := range supportedScmTypes {
		if exists, e := isScmProject(projectPath, scmData); !exists || err != nil {
			err = errors.Join(e, err)
			continue
		}
		if scmType == Git {
			return NewGitManager(projectPath)
		}
	}
	err = errors.Join(err, fmt.Errorf("failed to detect source control manager in project path: %s", projectPath))
	return
}

func isScmProject(projectPath string, scmData ScmTypeData) (bool, error) {
	return fileutils.IsDirExists(path.Join(projectPath, scmData.indicator), false)
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
	projectPathComponents := []string{}
	// Loop from the second element to the second last element of the URL. (first part is the base URL, last part is the repo name)
	for i := 1; i < len(urlParts)-1; i++ {
		if i == 1 && urlParts[i] == "scm" {
			// In BB ssh clone url looks like this: https://git.id.info/scm/repo-name/repo-name.git --> ['git.id.info', 'scm', 'repo-name', 'repo-name']
			continue
		}
		// Aws code commit clone url looks like this: https://git-codecommit.{region}.amazonaws.com/v1/repos/{repository_name} --> ['git-codecommit.{region}.amazonaws.com', 'v1', 'repos', '{repository_name}']
		if len(urlParts) > 3 && ((i == 1 && urlParts[i] == "v1") || (i == 2 && urlParts[i] == "repos")) {
			continue
		}
		projectPathComponents = append(projectPathComponents, urlParts[i])
	}
	if len(projectPathComponents) == 0 {
		// In Gerrit clone URL looks like this: https://gerrit.googlesource.com/git-repo --> ['gerrit.googlesource.com', 'git-repo']
		// add repo name (last part of the URL) as project name
		projectPathComponents = append(projectPathComponents, urlParts[len(urlParts)-1])
	}

	return strings.Join(projectPathComponents, "/")
}

func getGitProvider(url string) ScProvider {
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
	if strings.Contains(url, Gerrit.String()) {
		return Gerrit
	}
	if strings.Contains(url, Gitea.String()) {
		return Gitea
	}
	if strings.Contains(url, AWSCodeCommit.String()) {
		return AWSCodeCommit
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
