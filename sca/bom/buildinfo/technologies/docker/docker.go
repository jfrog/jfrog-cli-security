package docker

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/artifactory"
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

type dockerManifestList struct {
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"manifests"`
}

var (
	hexDigestPattern = regexp.MustCompile(`[a-fA-F0-9]{64}`)
)

// getArtifactoryHostPort extracts the host and port from the configured Artifactory URL.
// e.g., "https://myinstance.jfrog.io/artifactory" -> "myinstance.jfrog.io", ""
// e.g., "http://177.111.1.100:8082/artifactory" -> "192.168.1.100", "8082"
func getArtifactoryHostPort(artifactoryUrl string) (host, port string) {
	parsed, err := url.Parse(artifactoryUrl)
	if err != nil || parsed.Host == "" {
		return "", ""
	}
	return splitHostPort(parsed.Host)
}

// ParseDockerImageWithArtifactoryUrl parses a Docker image name and extracts repo based on Artifactory URL.
func ParseDockerImageWithArtifactoryUrl(imageName, url string) (*DockerImageInfo, error) {
	imageName = strings.TrimSpace(imageName)
	info := &DockerImageInfo{Tag: "latest"}
	if idx := strings.LastIndex(imageName, ":"); idx > 0 {
		afterColon := imageName[idx+1:]
		if !strings.Contains(afterColon, "/") {
			info.Tag = afterColon
			imageName = imageName[:idx]
		}
	}

	parts := strings.SplitN(imageName, "/", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid docker image format: '%s'", imageName)
	}

	info.Registry = parts[0]
	remaining := parts[1]

	info.Repo, info.Image = parseWithArtifactoryUrl(info.Registry, remaining, url)

	log.Debug(fmt.Sprintf("Parsed Docker image - Registry: %s, Repo: %s, Image: %s, Tag: %s",
		info.Registry, info.Repo, info.Image, info.Tag))

	return info, nil
}

// parseWithArtifactoryUrl determines Docker access method by comparing registry with Artifactory URL.
func parseWithArtifactoryUrl(registry, remaining, url string) (repo, image string) {
	artifactoryHost, artifactoryPort := getArtifactoryHostPort(url)

	registryHost, registryPort := splitHostPort(registry)

	isSaaS := strings.HasSuffix(artifactoryHost, ".jfrog.io") || strings.HasSuffix(artifactoryHost, ".jfrogdev.org")

	if repo = extractSubdomainRepo(registryHost, artifactoryHost, isSaaS); repo != "" {
		log.Debug(fmt.Sprintf("Subdomain method detected (repo=%s)", repo))
		return repo, remaining
	}
	if registryPort != "" && registryHost == artifactoryHost && registryPort != artifactoryPort {
		log.Debug(fmt.Sprintf("Port method detected (repo=%s)", registryPort))
		return registryPort, remaining
	}

	if registryHost == artifactoryHost {
		log.Debug("Repository Path method detected")
		return extractRepoFromPath(remaining)
	}
	log.Debug("Using Repository Path extraction")
	return extractRepoFromPath(remaining)
}

func splitHostPort(registry string) (host, port string) {
	if idx := strings.LastIndex(registry, ":"); idx > 0 {
		return registry[:idx], registry[idx+1:]
	}
	return registry, ""
}

// extractSubdomainRepo extracts repo from subdomain based on platform type.
// SaaS: <instance>-<repo>.<domain> → repo is after hyphen
// Self-hosted: <repo>.<baseDomain> → repo is prepended subdomain
func extractSubdomainRepo(registryHost, baseDomain string, isSaaS bool) string {
	if isSaaS {
		// SaaS pattern: <instance>-<repo>.<domain>
		baseParts := strings.SplitN(baseDomain, ".", 2)
		if len(baseParts) != 2 {
			return ""
		}
		instance, domainSuffix := baseParts[0], baseParts[1]
		expectedSuffix := "." + domainSuffix

		if strings.HasSuffix(registryHost, expectedSuffix) {
			prefix := strings.TrimSuffix(registryHost, expectedSuffix)
			if strings.HasPrefix(prefix, instance+"-") && prefix != instance {
				return strings.TrimPrefix(prefix, instance+"-")
			}
		}
	} else if strings.HasSuffix(registryHost, "."+baseDomain) {
		// Self-hosted pattern: <repo>.<baseDomain>
		return strings.TrimSuffix(registryHost, "."+baseDomain)
	}
	return ""
}

// extractRepoFromPath extracts repo as first segment if path contains "/"
func extractRepoFromPath(path string) (repo, image string) {
	if strings.Contains(path, "/") {
		repo, image, _ = strings.Cut(path, "/")
		return
	}
	return "", path
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) ([]*xrayUtils.GraphNode, []string, error) {
	if params.DockerImageName == "" {
		return nil, nil, fmt.Errorf("docker image name is required")
	}

	serverDetails, err := config.GetDefaultServerConf()
	if err != nil {
		return nil, nil, err
	}

	imageInfo, err := ParseDockerImageWithArtifactoryUrl(params.DockerImageName, serverDetails.Url)
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

	// Note: It does NOT extract the actual dependencies/packages inside the Docker image layers.
	// The graph contains just the image reference to verify if it's blocked by curation policies.
	rootId := imageInfo.Image + ":" + imageInfo.Tag
	return []*xrayUtils.GraphNode{{Id: rootId, Nodes: []*xrayUtils.GraphNode{{Id: imageRef}}}},
		[]string{imageRef}, nil
}

func getArchDigestUsingDocker(fullImageName string) (string, error) {
	pullCmd := exec.Command("docker", "pull", fullImageName)
	pullOutput, err := pullCmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(pullOutput), "curation service") {
			return extractDigestFromBlockedMessage(string(pullOutput)), nil
		}
		return "", fmt.Errorf("docker pull failed: %s", strings.TrimSpace(string(pullOutput)))
	}
	// IF Image exists locally, we need to get the digest of the image for the specific OS/architecture
	localOS, localArch, err := getLocalPlatform(fullImageName)
	if err != nil {
		return "", err
	}

	return findDigestForPlatform(fullImageName, localOS, localArch)
}

// Retrieves the OS and architecture of a locally pulled Docker image.
func getLocalPlatform(imageName string) (os, arch string, err error) {
	inspectCmd := exec.Command("docker", "inspect", imageName, "--format", "{{.Os}} {{.Architecture}}")
	inspectOutput, inspectErr := inspectCmd.CombinedOutput()
	if inspectErr != nil {
		log.Error(fmt.Sprintf("docker inspect failed: %v", inspectErr))
		return "", "", inspectErr
	}
	parts := strings.Fields(strings.TrimSpace(string(inspectOutput)))
	if len(parts) != 2 {
		return "", "", fmt.Errorf("unexpected inspect output format")
	}
	log.Debug(fmt.Sprintf("Local platform: %s/%s", parts[0], parts[1]))
	return parts[0], parts[1], nil
}

// Retrieves the digest for a specific OS/architecture from the image manifest.
func findDigestForPlatform(imageName, targetOS, targetArch string) (string, error) {
	buildxCmd := exec.Command("docker", "buildx", "imagetools", "inspect", imageName, "--raw")
	buildxOutput, buildxErr := buildxCmd.CombinedOutput()
	if buildxErr != nil {
		return "", fmt.Errorf("docker buildx imagetools inspect failed: %s", strings.TrimSpace(string(buildxOutput)))
	}

	var manifest dockerManifestList
	if err := json.Unmarshal(buildxOutput, &manifest); err != nil {
		log.Error(fmt.Sprintf("Failed to parse manifest JSON: %v", err))
		return "", nil
	}

	for _, m := range manifest.Manifests {
		if m.Platform.OS == targetOS && m.Platform.Architecture == targetArch {
			log.Debug(fmt.Sprintf("Found arch-specific digest: %s", m.Digest))
			return m.Digest, nil
		}
	}

	log.Debug(fmt.Sprintf("No matching manifest found for %s/%s", targetOS, targetArch))
	return "", nil
}

func extractDigestFromBlockedMessage(output string) string {
	if match := hexDigestPattern.FindString(output); match != "" {
		return "sha256:" + match
	}
	return ""
}

func GetDockerRepositoryConfig(imageName string) (*project.RepositoryConfig, error) {
	serverDetails, err := config.GetDefaultServerConf()
	if err != nil {
		return nil, err
	}
	imageInfo, err := ParseDockerImageWithArtifactoryUrl(imageName, serverDetails.Url)
	if err != nil {
		return nil, err
	}
	exists, err := artifactory.IsRepoExists(imageInfo.Repo, serverDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to check if repository '%s' exists on Artifactory '%s': %w", imageInfo.Repo, serverDetails.Url, err)
	}
	if !exists {
		return nil, fmt.Errorf("repository '%s' was not found on Artifactory (%s), ensure the repository exists", imageInfo.Repo, serverDetails.Url)
	}

	repoConfig := &project.RepositoryConfig{}
	repoConfig.SetServerDetails(serverDetails).SetTargetRepo(imageInfo.Repo)
	return repoConfig, nil
}
