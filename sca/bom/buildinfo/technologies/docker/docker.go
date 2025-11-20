package docker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
)

const (
	dockerPackagePrefix = "docker://"
)

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	if params.DockerImageName == "" {
		return nil, nil, fmt.Errorf("docker image name is required")
	}

	imageName := normalizeImageName(params.DockerImageName)
	repo, pkgName, pkgVersion := extractRepoImageAndTag(imageName)
	if repo == "" {
		return nil, nil, fmt.Errorf("invalid docker image format: '%s'. Expected format: 'repo/path/image:tag' or 'repo/image:tag'", imageName)
	}
	if pkgName == "" {
		return nil, nil, fmt.Errorf("invalid docker image format: '%s'. Image name is missing", imageName)
	}

	pkgName = strings.TrimPrefix(pkgName, "library/")
	imageRef := dockerPackagePrefix + pkgName + ":" + pkgVersion
	uniqueDeps = []string{imageRef}
	childNodes := []*xrayUtils.GraphNode{{Id: imageRef}}

	if hasServerDetails(params) {
		shaRefs := getMultiArchShaRefs(params, repo, pkgName, pkgVersion)
		if len(shaRefs) > 0 {
			uniqueDeps = shaRefs
			childNodes = createShaNodes(shaRefs)
		}
	}

	return []*xrayUtils.GraphNode{{Id: "root", Nodes: childNodes}}, uniqueDeps, nil
}

func normalizeImageName(imageName string) string {
	imageName = strings.TrimSpace(imageName)
	if idx := strings.Index(imageName, ","); idx > 0 {
		imageName = strings.TrimSpace(imageName[:idx])
	}
	return strings.TrimSuffix(imageName, "/")
}

func hasServerDetails(params technologies.BuildInfoBomGeneratorParams) bool {
	return params.ServerDetails != nil && (params.ServerDetails.ArtifactoryUrl != "" || params.ServerDetails.Url != "")
}

func getMultiArchShaRefs(params technologies.BuildInfoBomGeneratorParams, repo, pkgName, pkgVersion string) []string {
	rtManager, err := rtUtils.CreateServiceManager(params.ServerDetails, 2, 0, false)
	if err != nil {
		return nil
	}

	rtAuth, err := params.ServerDetails.CreateArtAuthConfig()
	if err != nil {
		return nil
	}

	manifestUrl := buildManifestUrl(params.ServerDetails, repo, pkgName, pkgVersion)
	httpClientDetails := createDockerHttpClientDetails(rtAuth)

	resp, _, err := rtManager.Client().SendHead(manifestUrl, &httpClientDetails)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "manifest.list.v2+json") && !strings.Contains(contentType, "image.index.v1+json") {
		return nil
	}

	manifestList := fetchManifestList(rtManager, manifestUrl, httpClientDetails)
	if manifestList == nil || len(manifestList.Manifests) == 0 {
		return nil
	}

	shaRefs := make([]string, 0, len(manifestList.Manifests))
	for _, manifest := range manifestList.Manifests {
		if manifest.Digest != "" {
			shaRefs = append(shaRefs, dockerPackagePrefix+pkgName+":"+manifest.Digest)
		}
	}
	return shaRefs
}

func buildManifestUrl(serverDetails *config.ServerDetails, repo, pkgName, pkgVersion string) string {
	artiUrl := serverDetails.ArtifactoryUrl
	if artiUrl == "" && serverDetails.Url != "" {
		artiUrl = strings.TrimSuffix(serverDetails.Url, "/") + "/artifactory"
	}
	return fmt.Sprintf("%s/api/docker/%s/v2/%s/manifests/%s",
		strings.TrimSuffix(artiUrl, "/"), repo, pkgName, pkgVersion)
}

func createDockerHttpClientDetails(rtAuth auth.ServiceDetails) httputils.HttpClientDetails {
	httpClientDetails := rtAuth.CreateHttpClientDetails()
	httpClientDetails.Headers["Accept"] = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v1+prettyjws, application/json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json"
	return httpClientDetails
}

func fetchManifestList(rtManager artifactory.ArtifactoryServicesManager, manifestUrl string, httpClientDetails httputils.HttpClientDetails) *dockerManifestList {
	resp, respBody, _, err := rtManager.Client().SendGet(manifestUrl, false, &httpClientDetails)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	var manifestList dockerManifestList
	if err := json.Unmarshal(respBody, &manifestList); err != nil {
		return nil
	}
	return &manifestList
}

func createShaNodes(shaRefs []string) []*xrayUtils.GraphNode {
	nodes := make([]*xrayUtils.GraphNode, 0, len(shaRefs))
	for _, shaRef := range shaRefs {
		nodes = append(nodes, &xrayUtils.GraphNode{Id: shaRef})
	}
	return nodes
}

func extractRepoImageAndTag(imagePath string) (repo, image, tag string) {
	tag = "latest"
	if lastColon := strings.LastIndex(imagePath, ":"); lastColon > 0 {
		tag = imagePath[lastColon+1:]
		imagePath = imagePath[:lastColon]
	}

	parts := strings.Split(imagePath, "/")
	if len(parts) < 2 {
		return "", imagePath, tag
	}

	return parts[0], strings.Join(parts[1:], "/"), tag
}

func GetDockerRepositoryConfig(serverDetails *config.ServerDetails, imageName, depsRepo, packageManagerRepo string) (*project.RepositoryConfig, error) {
	repo := packageManagerRepo
	if repo == "" && imageName != "" {
		repo, _, _ = extractRepoImageAndTag(imageName)
	}
	if repo == "" {
		repo = depsRepo
	}
	if repo == "" {
		if imageName != "" {
			return nil, fmt.Errorf("invalid docker image format: '%s'. Expected format: 'repo/path/image:tag' or 'repo/image:tag'. Repository name is required", imageName)
		}
		return nil, fmt.Errorf("docker repository name is required")
	}

	repoConfig := &project.RepositoryConfig{}
	repoConfig.SetServerDetails(serverDetails).SetTargetRepo(repo)

	return repoConfig, nil
}

func GetDockerRepoConfig(serverDetails *config.ServerDetails, imageName, depsRepo string) (*project.RepositoryConfig, error) {
	if imageName == "" {
		return nil, fmt.Errorf("docker image name is required. Use --image flag with format 'repo/path/image:tag'")
	}
	if serverDetails == nil {
		return nil, fmt.Errorf("server details are required")
	}
	return GetDockerRepositoryConfig(serverDetails, imageName, depsRepo, "")
}

type dockerManifestList struct {
	Manifests []struct {
		Digest string `json:"digest"`
	} `json:"manifests"`
}
