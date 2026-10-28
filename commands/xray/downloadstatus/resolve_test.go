package downloadstatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	artifactoryUtils "github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/stretchr/testify/assert"
)

type fakeLocator struct {
	configs map[string]repoConfig
	files   map[string]artifactoryUtils.FileInfo
	errors  map[string]error
	probed  []string
}

func (f *fakeLocator) GetRepository(repoKey string, repoDetails interface{}) error {
	config, ok := f.configs[repoKey]
	if !ok {
		return &errorutils.HttpResponseError{StatusCode: http.StatusBadRequest}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, repoDetails)
}

func (f *fakeLocator) FileInfo(relativePath string) (*artifactoryUtils.FileInfo, error) {
	f.probed = append(f.probed, relativePath)
	if err, ok := f.errors[relativePath]; ok {
		return nil, err
	}
	info, ok := f.files[relativePath]
	if !ok {
		return nil, &errorutils.HttpResponseError{StatusCode: http.StatusNotFound}
	}
	return &info, nil
}

func fileInfo(repo, sha256 string) artifactoryUtils.FileInfo {
	info := artifactoryUtils.FileInfo{Repo: repo}
	info.Checksums.Sha256 = sha256
	return info
}

func TestLocateArtifact(t *testing.T) {
	configs := map[string]repoConfig{
		"libs-local":   {Rclass: "local"},
		"central":      {Rclass: "remote"},
		"inner":        {Rclass: "virtual", Repositories: []string{"libs-local", "central"}},
		"libs-virtual": {Rclass: "virtual", Repositories: []string{"empty-local", "inner", "central"}},
		"loop-a":       {Rclass: "virtual", Repositories: []string{"loop-b"}},
		"loop-b":       {Rclass: "virtual", Repositories: []string{"loop-a"}},
		"empty-local":  {Rclass: "local"},
	}
	files := map[string]artifactoryUtils.FileInfo{
		"libs-local/a.jar":    fileInfo("libs-local", "sha-local"),
		"central/b.jar":       fileInfo("central-cache", "sha-remote"),
		"central-cache/b.jar": fileInfo("central-cache", ""),
	}

	tests := []struct {
		name           string
		repo           string
		candidates     []string
		expectedRepo   string
		expectedPath   string
		expectedSha    string
		expectNotFound bool
	}{
		{name: "local repo", repo: "libs-local", candidates: []string{"a.jar"}, expectedRepo: "libs-local", expectedPath: "a.jar", expectedSha: "sha-local"},
		{name: "remote repo resolves to its cache", repo: "central", candidates: []string{"b.jar"}, expectedRepo: "central-cache", expectedPath: "b.jar", expectedSha: "sha-remote"},
		{name: "virtual repo with local member", repo: "inner", candidates: []string{"a.jar"}, expectedRepo: "libs-local", expectedPath: "a.jar", expectedSha: "sha-local"},
		{name: "virtual repo with remote member", repo: "inner", candidates: []string{"b.jar"}, expectedRepo: "central-cache", expectedPath: "b.jar", expectedSha: "sha-remote"},
		{name: "nested virtual repo", repo: "libs-virtual", candidates: []string{"a.jar"}, expectedRepo: "libs-local", expectedPath: "a.jar", expectedSha: "sha-local"},
		{name: "second path candidate", repo: "inner", candidates: []string{"missing.jar", "a.jar"}, expectedRepo: "libs-local", expectedPath: "a.jar", expectedSha: "sha-local"},
		{name: "cache repo key is treated as concrete", repo: "central-cache", candidates: []string{"b.jar"}, expectedRepo: "central-cache", expectedPath: "b.jar"},
		{name: "not found in any member", repo: "inner", candidates: []string{"missing.jar"}, expectNotFound: true},
		{name: "virtual cycle terminates", repo: "loop-a", candidates: []string{"a.jar"}, expectNotFound: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			locator := &fakeLocator{configs: configs, files: files}
			located, err := locateArtifact(locator, test.repo, test.candidates)
			if test.expectNotFound {
				assert.ErrorContains(t, err, "could not find artifact under repo '"+test.repo+"'")
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.expectedRepo, located.repo)
			assert.Equal(t, test.expectedPath, located.path)
			assert.Equal(t, test.expectedSha, located.sha256)
		})
	}
}

func TestLocateArtifactVirtualMemberOrder(t *testing.T) {
	locator := &fakeLocator{
		configs: map[string]repoConfig{
			"v":  {Rclass: "virtual", Repositories: []string{"l1", "l2"}},
			"l1": {Rclass: "local"},
			"l2": {Rclass: "local"},
		},
		files: map[string]artifactoryUtils.FileInfo{
			"l1/a.jar": fileInfo("l1", "one"),
			"l2/a.jar": fileInfo("l2", "two"),
		},
	}
	located, err := locateArtifact(locator, "v", []string{"a.jar"})
	assert.NoError(t, err)
	assert.Equal(t, "l1", located.repo)
	assert.Equal(t, []string{"l1/a.jar"}, locator.probed)
}

func TestLocateArtifactSkipsUnreadableMember(t *testing.T) {
	locator := &fakeLocator{
		configs: map[string]repoConfig{
			"v":  {Rclass: "virtual", Repositories: []string{"l1", "l2"}},
			"l1": {Rclass: "local"},
			"l2": {Rclass: "local"},
		},
		files:  map[string]artifactoryUtils.FileInfo{"l2/a.jar": fileInfo("l2", "two")},
		errors: map[string]error{"l1/a.jar": &errorutils.HttpResponseError{StatusCode: http.StatusForbidden}},
	}
	located, err := locateArtifact(locator, "v", []string{"a.jar"})
	assert.NoError(t, err)
	assert.Equal(t, "l2", located.repo)
}

func TestLocateArtifactSurfacesNonNotFoundError(t *testing.T) {
	locator := &fakeLocator{
		configs: map[string]repoConfig{"l1": {Rclass: "local"}},
		errors:  map[string]error{"l1/a.jar": errors.New("connection reset")},
	}
	_, err := locateArtifact(locator, "l1", []string{"a.jar"})
	assert.EqualError(t, err, "connection reset")
}

func TestLocateArtifactUnknownRepoConfigFallsBackToProbing(t *testing.T) {
	locator := &fakeLocator{files: map[string]artifactoryUtils.FileInfo{"repo/a.jar": fileInfo("repo", "sha")}}
	located, err := locateArtifact(locator, "repo", []string{"a.jar"})
	assert.NoError(t, err)
	assert.Equal(t, "repo", located.repo)
}

func TestLocateArtifactStopsOnNonSkippableMemberError(t *testing.T) {
	locator := &fakeLocator{
		configs: map[string]repoConfig{
			"v":  {Rclass: "virtual", Repositories: []string{"l1", "l2"}},
			"l1": {Rclass: "local"},
			"l2": {Rclass: "local"},
		},
		files:  map[string]artifactoryUtils.FileInfo{"l2/a.jar": fileInfo("l2", "two")},
		errors: map[string]error{"l1/a.jar": &errorutils.HttpResponseError{StatusCode: http.StatusInternalServerError}},
	}
	_, err := locateArtifact(locator, "v", []string{"a.jar"})
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "could not find artifact")
	assert.Equal(t, []string{"l1/a.jar"}, locator.probed)
}

func TestLocateArtifactEarlierFailureIsNotHiddenByLaterNotFound(t *testing.T) {
	locator := &fakeLocator{
		configs: map[string]repoConfig{
			"v":  {Rclass: "virtual", Repositories: []string{"l1", "l2"}},
			"l1": {Rclass: "local"},
			"l2": {Rclass: "local"},
		},
		errors: map[string]error{"l1/a.jar": errors.New("connection reset")},
	}
	_, err := locateArtifact(locator, "v", []string{"a.jar"})
	assert.EqualError(t, err, "connection reset")
}

func TestLocateArtifactDeepVirtualHierarchy(t *testing.T) {
	const depth = 25
	configs := map[string]repoConfig{"local": {Rclass: "local"}}
	next := "local"
	for i := 0; i < depth; i++ {
		key := fmt.Sprintf("virtual-%d", i)
		configs[key] = repoConfig{Rclass: "virtual", Repositories: []string{next}}
		next = key
	}
	locator := &fakeLocator{configs: configs, files: map[string]artifactoryUtils.FileInfo{"local/a.jar": fileInfo("local", "sha")}}
	located, err := locateArtifact(locator, next, []string{"a.jar"})
	assert.NoError(t, err)
	assert.Equal(t, "local", located.repo)
}
