package downloadstatus

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	artifactoryUtils "github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const rclassVirtual = "virtual"

type artifactLocator interface {
	GetRepository(repoKey string, repoDetails interface{}) error
	FileInfo(relativePath string) (*artifactoryUtils.FileInfo, error)
}

type repoConfig struct {
	Rclass       string   `json:"rclass"`
	Repositories []string `json:"repositories"`
}

type locatedArtifact struct {
	repo   string
	path   string
	sha256 string
}

// Xray only tracks concrete repos: local ones and the '-cache' repo behind a remote one.
func locateArtifact(locator artifactLocator, repo string, pathCandidates []string) (*locatedArtifact, error) {
	found, lastErr := locateInRepo(locator, repo, pathCandidates, map[string]bool{})
	if found != nil {
		return found, nil
	}
	tried := strings.Join(pathCandidates, ", ")
	if lastErr == nil {
		return nil, errorutils.CheckErrorf("could not find artifact under repo '%s' (tried: %s)", repo, tried)
	}
	if !isArtifactNotFound(lastErr) {
		return nil, lastErr
	}
	return nil, errorutils.CheckErrorf("could not find artifact under repo '%s' (tried: %s): %s", repo, tried, lastErr.Error())
}

func locateInRepo(locator artifactLocator, repo string, pathCandidates []string, visited map[string]bool) (*locatedArtifact, error) {
	if visited[repo] {
		return nil, nil
	}
	visited[repo] = true

	config := repoConfig{}
	if err := locator.GetRepository(repo, &config); err != nil {
		log.Debug(fmt.Sprintf("Could not read the configuration of repo '%s', treating it as a concrete repo: %s", repo, err.Error()))
		return probeRepo(locator, repo, pathCandidates)
	}
	if !strings.EqualFold(config.Rclass, rclassVirtual) {
		return probeRepo(locator, repo, pathCandidates)
	}

	log.Debug(fmt.Sprintf("Repo '%s' is virtual, looking for the artifact in its members: %s", repo, strings.Join(config.Repositories, ", ")))
	var lastErr error
	for _, member := range config.Repositories {
		found, err := locateInRepo(locator, member, pathCandidates, visited)
		if found != nil {
			log.Debug(fmt.Sprintf("Artifact found in member repo '%s' of virtual repo '%s'", found.repo, repo))
			return found, nil
		}
		if err == nil {
			continue
		}
		if !isSkippableMemberError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func isSkippableMemberError(err error) bool {
	var httpErr *errorutils.HttpResponseError
	return errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusNotFound || httpErr.StatusCode == http.StatusForbidden)
}

// For a remote repo the storage API answers with the '-cache' repo that holds the file.
func probeRepo(locator artifactLocator, repo string, pathCandidates []string) (*locatedArtifact, error) {
	var lastErr error
	for _, candidate := range pathCandidates {
		fileInfo, err := locator.FileInfo(repo + "/" + candidate)
		if err == nil {
			resolvedRepo := fileInfo.Repo
			if resolvedRepo == "" {
				resolvedRepo = repo
			}
			if resolvedRepo != repo {
				log.Debug(fmt.Sprintf("Repo '%s' resolved to '%s'", repo, resolvedRepo))
			}
			return &locatedArtifact{repo: resolvedRepo, path: candidate, sha256: fileInfo.Checksums.Sha256}, nil
		}
		if !isArtifactNotFound(err) {
			log.Debug(fmt.Sprintf("File info for %s/%s failed: %s", repo, candidate, err.Error()))
			return nil, err
		}
		log.Debug(fmt.Sprintf("Artifact %s/%s was not found", repo, candidate))
		lastErr = err
	}
	return nil, lastErr
}
