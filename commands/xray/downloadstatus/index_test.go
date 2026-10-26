package downloadstatus

import (
	"errors"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"io"
	"net/http"
	"strings"
	"testing"

	artifactoryUtils "github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

type fakeManifestSource struct {
	fakeLocator
	content map[string]string
}

func (f *fakeManifestSource) ReadRemoteFile(readPath string) (io.ReadCloser, error) {
	content, ok := f.content[readPath]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

const testManifestList = `{
  "schemaVersion": 2,
  "manifests": [
    {"digest": "sha256:aaa", "platform": {"os": "linux", "architecture": "amd64"}},
    {"digest": "sha256:bbb", "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
    {"digest": "sha256:ccc", "platform": {"os": "unknown", "architecture": "unknown"}},
    {"digest": "sha256:ddd", "platform": {"os": "linux", "architecture": "s390x"}}
  ]
}`

func TestIsManifestListPath(t *testing.T) {
	assert.True(t, isManifestListPath("team/app/1.0/list.manifest.json"))
	assert.True(t, isManifestListPath("app/sha256__abc/list.manifest.json"))
	assert.False(t, isManifestListPath("team/app/1.0/manifest.json"))
	assert.False(t, isManifestListPath("list.manifest.json"))
}

func TestListPlatformManifests(t *testing.T) {
	source := &fakeManifestSource{
		fakeLocator: fakeLocator{files: map[string]artifactoryUtils.FileInfo{
			"docker-cache/team/app/sha256__aaa/manifest.json": fileInfo("docker-cache", "sha-amd64"),
			"docker-cache/team/app/sha256__bbb/manifest.json": fileInfo("docker-cache", "sha-arm64"),
		}},
		content: map[string]string{"docker-cache/team/app/1.0/list.manifest.json": testManifestList},
	}
	manifests, err := listPlatformManifests(source, "docker-cache", "team/app/1.0/list.manifest.json")
	assert.NoError(t, err)
	assert.Equal(t, []platformManifest{
		{platform: "linux/amd64", path: "team/app/sha256__aaa/manifest.json", sha256: "sha-amd64"},
		{platform: "linux/arm64/v8", path: "team/app/sha256__bbb/manifest.json", sha256: "sha-arm64"},
	}, manifests)
}

func TestListPlatformManifestsErrors(t *testing.T) {
	source := &fakeManifestSource{content: map[string]string{"r/app/1/list.manifest.json": "not json"}}
	_, err := listPlatformManifests(source, "r", "app/1/list.manifest.json")
	assert.ErrorContains(t, err, "couldn't parse manifest list")

	_, err = listPlatformManifests(source, "r", "app/2/list.manifest.json")
	assert.Error(t, err)
}

func blockingResult(path string) *Result {
	return buildResult("repo", path, "", "https://acme.jfrog.io", "gav://a:b", "1", false,
		&services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone}}},
		[]services.XrayViolation{{
			Id:       "v1",
			Severity: "High",
			Policies: []services.ViolationPolicy{{PolicyName: "p", Rule: "r", IsBlocking: true}},
		}})
}

func allowedResult(path string) *Result {
	return buildResult("repo", path, "", "https://acme.jfrog.io", "gav://a:b", "1", false,
		&services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone}}}, nil)
}

func TestMergePlatformResults(t *testing.T) {
	t.Run("blocked platform blocks the list", func(t *testing.T) {
		result := allowedResult("app/1/list.manifest.json")
		mergePlatformResults(result, []platformResult{
			{platform: "linux/amd64", result: blockingResult("app/sha256__a/manifest.json")},
			{platform: "linux/arm64", result: allowedResult("app/sha256__b/manifest.json")},
		})
		assert.Equal(t, StatusBlocked, result.DownloadStatus)
		assert.Contains(t, result.StatusReason, "linux/amd64")
		assert.Len(t, result.Platforms, 2)
		assert.Equal(t, StatusBlocked, result.Platforms[0].DownloadStatus)
		assert.Equal(t, StatusAllowed, result.Platforms[1].DownloadStatus)
		assert.Len(t, result.Violations, 1)
		assert.Equal(t, "linux/amd64", result.Violations[0].Platform)
	})

	t.Run("all platforms allowed", func(t *testing.T) {
		result := allowedResult("app/1/list.manifest.json")
		mergePlatformResults(result, []platformResult{{platform: "linux/amd64", result: allowedResult("app/sha256__a/manifest.json")}})
		assert.Equal(t, StatusAllowed, result.DownloadStatus)
		assert.Empty(t, result.StatusReason)
	})

	t.Run("no platforms keeps the list result", func(t *testing.T) {
		result := allowedResult("app/1/list.manifest.json")
		mergePlatformResults(result, nil)
		assert.Equal(t, StatusAllowed, result.DownloadStatus)
		assert.Empty(t, result.Platforms)
	})

	t.Run("incomplete scan makes the list unknown", func(t *testing.T) {
		result := allowedResult("app/1/list.manifest.json")
		incomplete := buildResult("repo", "app/sha256__a/manifest.json", "", "https://acme.jfrog.io", "gav://a:b", "1", false,
			&services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusScanning}}}, nil)
		mergePlatformResults(result, []platformResult{{platform: "linux/amd64", result: incomplete}})
		assert.Equal(t, StatusUnknown, result.DownloadStatus)
	})
}

func TestListPlatformManifestsLookupFailureIsNotSkipped(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		source := &fakeManifestSource{
			fakeLocator: fakeLocator{
				files:  map[string]artifactoryUtils.FileInfo{"docker-cache/team/app/sha256__bbb/manifest.json": fileInfo("docker-cache", "sha-arm64")},
				errors: map[string]error{"docker-cache/team/app/sha256__aaa/manifest.json": &errorutils.HttpResponseError{StatusCode: status}},
			},
			content: map[string]string{"docker-cache/team/app/1.0/list.manifest.json": testManifestList},
		}
		_, err := listPlatformManifests(source, "docker-cache", "team/app/1.0/list.manifest.json")
		assert.Error(t, err, "status %d", status)
	}
}

func TestEvaluatePlatformManifests(t *testing.T) {
	source := &fakeManifestSource{
		fakeLocator: fakeLocator{files: map[string]artifactoryUtils.FileInfo{
			"docker-cache/team/app/sha256__aaa/manifest.json": fileInfo("docker-cache", "sha-amd64"),
			"docker-cache/team/app/sha256__bbb/manifest.json": fileInfo("docker-cache", "sha-arm64"),
		}},
		content: map[string]string{"docker-cache/team/app/1.0/list.manifest.json": testManifestList},
	}

	t.Run("evaluates every platform", func(t *testing.T) {
		var evaluated []string
		platforms, err := evaluatePlatformManifests(source, "docker-cache", "team/app/1.0/list.manifest.json", func(path, sha256 string) (*Result, error) {
			evaluated = append(evaluated, path+"@"+sha256)
			return allowedResult(path), nil
		})
		assert.NoError(t, err)
		assert.Len(t, platforms, 2)
		assert.Equal(t, []string{"team/app/sha256__aaa/manifest.json@sha-amd64", "team/app/sha256__bbb/manifest.json@sha-arm64"}, evaluated)
	})

	t.Run("platform status failure is returned", func(t *testing.T) {
		calls := 0
		platforms, err := evaluatePlatformManifests(source, "docker-cache", "team/app/1.0/list.manifest.json", func(path, sha256 string) (*Result, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("xray unavailable")
			}
			return allowedResult(path), nil
		})
		assert.EqualError(t, err, "xray unavailable")
		assert.Nil(t, platforms)
	})

	t.Run("unreadable manifest list is returned", func(t *testing.T) {
		_, err := evaluatePlatformManifests(source, "docker-cache", "team/app/2.0/list.manifest.json", func(path, sha256 string) (*Result, error) {
			return allowedResult(path), nil
		})
		assert.Error(t, err)
	})
}
