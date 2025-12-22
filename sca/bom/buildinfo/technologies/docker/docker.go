package docker

import (
	"encoding/json"
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

	parts := strings.SplitN(imageName, "/", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid docker image format: '%s'", imageName)
	}

	info.Registry = parts[0]
	repo, image := parseRegistryAndExtract(info.Registry, parts[1])
	info.Repo = repo
	info.Image = image

	log.Debug(fmt.Sprintf("Parsed Docker image - Registry: %s, Repo: %s, Image: %s, Tag: %s",
		info.Registry, info.Repo, info.Image, info.Tag))

	return info, nil
}

func parseRegistryAndExtract(registry string, remaining string) (repo, image string) {
	image = remaining

	// SaaS subdomain: <INSTANCE>-<REPO>.jfrog.io/image:tag (repo in subdomain, check first)
	if matches := jfrogSubdomainPattern.FindStringSubmatch(registry); len(matches) > 2 {
		repo = matches[2]
		return
	}

	// Subdomain pattern: <REPO>.<DOMAIN>/image:tag (repo in subdomain, not IP, check first)
	registryParts := strings.Split(registry, ".")
	if len(registryParts) >= 3 && !strings.HasSuffix(registry, ".jfrog.io") && !ipAddressPattern.MatchString(registry) {
		repo = registryParts[0]
		return
	}

	// Repository path: <REGISTRY>/<REPO>/image:tag (repo in path if contains /)
	if strings.Contains(remaining, "/") {
		repo, image, _ = strings.Cut(remaining, "/")
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
	//IF IMAGE EXISTS LOCALLY
	inspectCmd := exec.Command("docker", "inspect", fullImageName, "--format", "{{.Os}} {{.Architecture}}")
	inspectOutput, err := inspectCmd.CombinedOutput()
	if err != nil {
		log.Debug(fmt.Sprintf("docker inspect failed: %s", strings.TrimSpace(string(inspectOutput))))
		return "", nil
	}
	parts := strings.Fields(strings.TrimSpace(string(inspectOutput)))
	if len(parts) != 2 {
		return "", nil
	}
	localOS := parts[0]
	localArch := parts[1]

	log.Debug(fmt.Sprintf("Local platform: %s/%s", localOS, localArch))

	buildxCmd := exec.Command("docker", "buildx", "imagetools", "inspect", fullImageName, "--raw")
	buildxOutput, err := buildxCmd.CombinedOutput()
	if err != nil {
		log.Debug(fmt.Sprintf("docker buildx imagetools inspect failed: %s", strings.TrimSpace(string(buildxOutput))))
		return "", nil
	}

	var manifest dockerManifestList
	if err := json.Unmarshal(buildxOutput, &manifest); err != nil {
		log.Debug(fmt.Sprintf("Failed to parse manifest JSON: %v", err))
		return "", nil
	}

	for _, m := range manifest.Manifests {
		if m.Platform.OS == localOS && m.Platform.Architecture == localArch {
			log.Debug(fmt.Sprintf("Found arch-specific digest: %s", m.Digest))
			return m.Digest, nil
		}
	}

	log.Debug(fmt.Sprintf("No matching manifest found for %s/%s", localOS, localArch))
	return "", nil
}

func extractDigestFromBlockedMessage(output string) string {
	if match := hexDigestPattern.FindString(output); match != "" {
		return "sha256:" + match
	}
	return ""
}

func GetDockerRepositoryConfig(imageName string) (*project.RepositoryConfig, error) {
	imageInfo, err := ParseDockerImage(imageName)
	if err != nil {
		return nil, err
	}

	serverDetails, err := config.GetDefaultServerConf()
	if err != nil {
		return nil, err
	}

	repoConfig := &project.RepositoryConfig{}
	repoConfig.SetServerDetails(serverDetails).SetTargetRepo(imageInfo.Repo)
	return repoConfig, nil
}
