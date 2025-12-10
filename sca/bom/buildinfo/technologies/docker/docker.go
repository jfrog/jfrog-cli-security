package docker

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const dockerPackagePrefix = "docker://"

type DockerImageInfo struct {
	Registry string
	Repo     string
	Image    string
	Tag      string
}

var (
	jfrogSubdomainPattern = regexp.MustCompile(`^([a-zA-Z0-9]+)-([a-zA-Z0-9-]+)\.jfrog\.io$`)
	ipAddressPattern      = regexp.MustCompile(`^\d+\.`)
	hexDigestPattern      = regexp.MustCompile(`[a-fA-F0-9]{64}`)
)

func ParseDockerImage(imageName string) (*DockerImageInfo, error) {
	imageName = strings.TrimSpace(imageName)
	info := &DockerImageInfo{Tag: "latest"}
	if idx := strings.LastIndex(imageName, ":"); idx > 0 {
		afterColon := imageName[idx+1:]
		if !strings.Contains(afterColon, "/") {
			info.Tag = afterColon
			imageName = imageName[:idx]
		}
	}

	parts := strings.Split(imageName, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid docker image format: '%s'", imageName)
	}

	info.Registry = parts[0]
	info.Repo, info.Image = parseRegistryAndExtract(info.Registry, parts[1:])

	log.Debug(fmt.Sprintf("Parsed Docker image - Registry: %s, Repo: %s, Image: %s, Tag: %s",
		info.Registry, info.Repo, info.Image, info.Tag))

	return info, nil
}

func parseRegistryAndExtract(registry string, remainingParts []string) (repo, image string) {
	image = strings.Join(remainingParts, "/")

	// SaaS subdomain: <INSTANCE>-<REPO>.jfrog.io/image:tag (repo in subdomain, check first)
	if matches := jfrogSubdomainPattern.FindStringSubmatch(registry); matches != nil {
		repo = matches[2]
		return
	}

	// Subdomain pattern: <REPO>.<DOMAIN>/image:tag (repo in subdomain, not IP, check first)
	registryParts := strings.Split(registry, ".")
	if len(registryParts) >= 3 && !strings.HasSuffix(registry, ".jfrog.io") && !ipAddressPattern.MatchString(registry) {
		repo = registryParts[0]
		return
	}

	// Repository path: <REGISTRY>/<REPO>/image:tag (2+ parts means repo in path)
	if len(remainingParts) >= 2 {
		repo = remainingParts[0]
		image = strings.Join(remainingParts[1:], "/")
		return
	}

	// Port method: <INSTANCE>:<PORT>/image:tag (port IS the repo, single part only)
	if strings.Contains(registry, ":") {
		_, repo, _ = strings.Cut(registry, ":")
		return
	}

	return "", ""
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) ([]*xrayUtils.GraphNode, []string, error) {
	if params.DockerImageName == "" {
		return nil, nil, fmt.Errorf("docker image name is required")
	}

	imageInfo, err := ParseDockerImage(params.DockerImageName)
	if err != nil {
		return nil, nil, err
	}

	archDigest, err := getArchDigestUsingDocker(params.DockerImageName)
	if err != nil {
		return nil, nil, err
	}

	imageRef := dockerPackagePrefix + imageInfo.Image + ":"
	if archDigest != "" {
		imageRef += archDigest
	} else {
		imageRef += imageInfo.Tag
	}

	log.Debug(fmt.Sprintf("Docker image reference: %s", imageRef))

	return []*xrayUtils.GraphNode{{Id: "root", Nodes: []*xrayUtils.GraphNode{{Id: imageRef}}}},
		[]string{imageRef}, nil
}

func getArchDigestUsingDocker(fullImageName string) (string, error) {
	log.Debug(fmt.Sprintf("Pulling Docker image: %s", fullImageName))
	pullCmd := exec.Command("docker", "pull", fullImageName)
	output, err := pullCmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "curation service") {
			return extractDigestFromBlockedMessage(outputStr), nil
		}
		return "", fmt.Errorf("docker pull failed: %s", strings.TrimSpace(outputStr))
	}

	inspectCmd := exec.Command("docker", "inspect", fullImageName, "--format", "{{index .RepoDigests 0}}")
	output, err = inspectCmd.CombinedOutput()
	if err != nil {
		return "", nil
	}
	repoDigest := strings.TrimSpace(string(output))
	if idx := strings.Index(repoDigest, "@"); idx > 0 {
		return repoDigest[idx+1:], nil
	}
	return "", nil
}

func extractDigestFromBlockedMessage(output string) string {
	if match := hexDigestPattern.FindString(output); match != "" {
		return "sha256:" + match
	}
	return ""
}

func GetDockerRepositoryConfig(serverDetails *config.ServerDetails, imageName string) (*project.RepositoryConfig, error) {
	imageInfo, err := ParseDockerImage(imageName)
	if err != nil {
		return nil, err
	}
	return GetDockerRepositoryConfigFromInfo(serverDetails, imageInfo)
}

func GetDockerRepositoryConfigFromInfo(serverDetails *config.ServerDetails, imageInfo *DockerImageInfo) (*project.RepositoryConfig, error) {
	repoConfig := &project.RepositoryConfig{}
	repoConfig.SetServerDetails(serverDetails).SetTargetRepo(imageInfo.Repo)
	return repoConfig, nil
}
