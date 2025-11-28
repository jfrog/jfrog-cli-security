package docker

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-client-go/utils/log"

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

	fullImageName := normalizeImageName(params.DockerImageName)

	_, pkgName, pkgVersion := extractRepoImageAndTag(fullImageName)
	if pkgName == "" {
		return nil, nil, fmt.Errorf("invalid docker image format: '%s'. Image name is missing", fullImageName)
	}

	pkgName = strings.TrimPrefix(pkgName, "library/")

	archDigest, dockerErr := getArchDigestUsingDocker(fullImageName)
	if dockerErr != nil {
		return nil, nil, dockerErr
	}

	var imageRef string
	if archDigest != "" {
		imageRef = dockerPackagePrefix + pkgName + ":" + archDigest
		log.Debug("Using arch-specific Docker digest: %s", imageRef)
	} else {
		imageRef = dockerPackagePrefix + pkgName + ":" + pkgVersion
		log.Debug("Using tag for Docker image: %s", imageRef)
	}

	uniqueDeps = []string{imageRef}
	childNodes := []*xrayUtils.GraphNode{{Id: imageRef}}

	return []*xrayUtils.GraphNode{{Id: "root", Nodes: childNodes}}, uniqueDeps, nil
}

func normalizeImageName(imageName string) string {
	imageName = strings.TrimSpace(imageName)
	if idx := strings.Index(imageName, ","); idx > 0 {
		imageName = strings.TrimSpace(imageName[:idx])
	}
	return strings.TrimSuffix(imageName, "/")
}

func getArchDigestUsingDocker(fullImageName string) (string, error) {
	log.Debug("Running docker buildx imagetools inspect for: %s", fullImageName)

	cmd := exec.Command("docker", "buildx", "imagetools", "inspect", "--raw", fullImageName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)

		if strings.Contains(outputStr, "403") || strings.Contains(outputStr, "Forbidden") {
			log.Debug(fmt.Sprintf("Received 403 Forbidden: %s", outputStr))
			log.Debug("403 response received (single-arch image or blocked), using tag for validating checks")
			return "", nil
		}

		// For other errors, return the original Docker error output
		return "", fmt.Errorf("%s", strings.TrimSpace(outputStr))
	}

	var manifestList dockerManifestList
	if err := json.Unmarshal(output, &manifestList); err != nil {
		log.Debug("Not a multi-arch manifest list, will use tag directly")
		return "", nil
	}

	if len(manifestList.Manifests) == 0 {
		log.Debug("Single-arch image, will use tag directly")
		return "", nil
	}

	currentArch := runtime.GOARCH
	for _, manifest := range manifestList.Manifests {
		if manifest.Digest != "" && manifest.Platform.Architecture == currentArch {
			log.Debug("Found matching Docker architecture %s, digest: %s", currentArch, manifest.Digest)
			return manifest.Digest, nil
		}
	}

	log.Debug("No matching architecture found for %s in multi-arch image, will use tag directly", currentArch)
	return "", nil
}

func extractRepoImageAndTag(imagePath string) (repo, image, tag string) {
	tag = "latest"

	if lastColon := strings.LastIndex(imagePath, ":"); lastColon > 0 {
		afterColon := imagePath[lastColon+1:]
		if !strings.Contains(afterColon, "/") {
			tag = afterColon
			imagePath = imagePath[:lastColon]
		}
	}

	parts := strings.Split(imagePath, "/")
	if len(parts) < 2 {
		return "", imagePath, tag
	}

	firstPart := parts[0]
	if strings.Contains(firstPart, ".") || strings.Contains(firstPart, ":") {
		if len(parts) == 2 {
			return "", parts[1], tag
		}
		if len(parts) == 3 {
			return parts[1], parts[2], tag
		}
		return parts[1], strings.Join(parts[2:], "/"), tag
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
		return nil, fmt.Errorf("docker image name is required. Use --image flag with format 'RT-URL/repo/path/image:tag'")
	}
	if serverDetails == nil {
		return nil, fmt.Errorf("server details are required")
	}
	return GetDockerRepositoryConfig(serverDetails, imageName, depsRepo, "")
}

type dockerManifestList struct {
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"manifests"`
}
