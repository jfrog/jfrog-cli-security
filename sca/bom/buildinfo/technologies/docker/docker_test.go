package docker

import (
	"net/http"
	"strings"
	"testing"

	coreCommonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
)

func TestBuildDependencyTree(t *testing.T) {
	tests := []struct {
		name               string
		dockerImageName    string
		expectedUniqueDeps []string
		expectError        bool
	}{
		{
			name:               "Valid docker image with repo and tag",
			dockerImageName:    "my-repo/my-image:v1.0.0",
			expectedUniqueDeps: []string{"docker://my-image:v1.0.0"},
			expectError:        false,
		},
		{
			name:               "Docker image with library prefix",
			dockerImageName:    "my-repo/library/my-image:latest",
			expectedUniqueDeps: []string{"docker://my-image:latest"},
			expectError:        false,
		},
		{
			name:               "Docker image without tag (defaults to latest)",
			dockerImageName:    "my-repo/my-image",
			expectedUniqueDeps: []string{"docker://my-image:latest"},
			expectError:        false,
		},
		{
			name:               "Empty docker image name",
			dockerImageName:    "",
			expectedUniqueDeps: nil,
			expectError:        true,
		},
		{
			name:               "Invalid format - no repo",
			dockerImageName:    "image:tag",
			expectedUniqueDeps: nil,
			expectError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := technologies.BuildInfoBomGeneratorParams{
				DockerImageName: tt.dockerImageName,
			}
			_, uniqueDeps, err := BuildDependencyTree(params)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.ElementsMatch(t, uniqueDeps, tt.expectedUniqueDeps, "Unique dependencies mismatch. First is actual, Second is Expected")
			}
		})
	}
}
func TestBuildDependencyTree_MultiArch(t *testing.T) {
	manifestListResponse := `{
		"schemaVersion": 2,
		"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
		"manifests": [
			{
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"size": 2413,
				"digest": "sha256:3446f171923148a8e1ef9ed402f6eefcf69811c2b25cd969e13ef175a310836d",
				"platform": {
					"architecture": "amd64",
					"os": "linux"
				}
			},
			{
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"size": 2413,
				"digest": "sha256:cb7bf93be94a38ca93a8dbca4468ce86079c6c83aacc8d603090db29fcaaf7b8",
				"platform": {
					"architecture": "arm64",
					"os": "linux"
				}
			},
			{
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"size": 2412,
				"digest": "sha256:27ac676b8471b951f257b1349c6f69b5f8738499494f89270f48b3c798beada4",
				"platform": {
					"architecture": "arm",
					"os": "linux",
					"variant": "v7"
				}
			}
		]
	}`

	serverMock, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			if strings.Contains(r.RequestURI, "/api/docker/") && strings.Contains(r.RequestURI, "/manifests/") {
				w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.list.v2+json")
				w.WriteHeader(http.StatusOK)
			}
		}
		if r.Method == http.MethodGet {
			if strings.Contains(r.RequestURI, "/api/docker/") && strings.Contains(r.RequestURI, "/manifests/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(manifestListResponse))
			}
		}
	})
	defer serverMock.Close()

	serverDetails.ArtifactoryUrl = serverDetails.Url + "artifactory"

	params := technologies.BuildInfoBomGeneratorParams{
		DockerImageName: "my-repo/my-image:v1.0.0",
		ServerDetails:   serverDetails,
	}

	trees, uniqueDeps, err := BuildDependencyTree(params)
	assert.NoError(t, err)
	assert.NotNil(t, trees)

	expectedUniqueDeps := []string{
		"docker://my-image:sha256:3446f171923148a8e1ef9ed402f6eefcf69811c2b25cd969e13ef175a310836d",
		"docker://my-image:sha256:cb7bf93be94a38ca93a8dbca4468ce86079c6c83aacc8d603090db29fcaaf7b8",
		"docker://my-image:sha256:27ac676b8471b951f257b1349c6f69b5f8738499494f89270f48b3c798beada4",
	}
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "Unique dependencies mismatch. First is actual, Second is Expected")

	require.Len(t, trees, 1)
	assert.Equal(t, "root", trees[0].Id)
	assert.Len(t, trees[0].Nodes, 3)

	nodeIds := make([]string, 0, len(trees[0].Nodes))
	for _, node := range trees[0].Nodes {
		nodeIds = append(nodeIds, node.Id)
	}
	assert.ElementsMatch(t, nodeIds, expectedUniqueDeps)
}
