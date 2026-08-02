package packageupdaters

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

var (
	dockerFromLineRegex = regexp.MustCompile(`(?i)^(\s*FROM\s+(?:--\S+\s+)*)(\S+)(\s+AS\s+\S+)?\s*$`)
	dockerHubPrefixes   = []string{"index.docker.io/library/", "docker.io/library/", "index.docker.io/", "docker.io/"}
)

type DockerPackageUpdater struct {
	DockerfilePatterns []string
}

func (d *DockerPackageUpdater) UpdateDependency(fixDetails *FixDetails) error {
	descriptorPaths := d.collectDockerfilePaths(fixDetails)
	if len(descriptorPaths) == 0 {
		return fmt.Errorf("no Dockerfile evidence was found for package %s", fixDetails.ImpactedDependencyName)
	}

	var joinedError error
	for _, path := range descriptorPaths {
		if err := d.updateDockerfile(path, fixDetails); err != nil {
			log.Warn(fmt.Sprintf("failed to update '%s' in '%s': %s", fixDetails.ImpactedDependencyName, path, err.Error()))
			joinedError = errors.Join(joinedError, err)
		}
	}
	return joinedError
}

func (d *DockerPackageUpdater) collectDockerfilePaths(fixDetails *FixDetails) []string {
	pathsSet := datastructures.MakeSet[string]()
	for _, component := range fixDetails.Components {
		for _, evidence := range component.Evidences {
			if evidence.File == "" {
				continue
			}
			if !d.isDockerfilePath(evidence.File) {
				continue
			}
			pathsSet.Add(evidence.File)
		}
	}
	return pathsSet.ToSlice()
}

func (d *DockerPackageUpdater) isDockerfilePath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if len(d.DockerfilePatterns) > 0 {
		for _, pattern := range d.DockerfilePatterns {
			if matched, _ := filepath.Match(strings.ToLower(pattern), base); matched {
				return true
			}
		}
		return false
	}
	return base == "dockerfile" ||
		strings.HasPrefix(base, "dockerfile.") ||
		strings.HasSuffix(base, ".dockerfile")
}

func (d *DockerPackageUpdater) updateDockerfile(path string, fixDetails *FixDetails) error {
	//#nosec G304 -- path comes from descriptor discovery in the scanned repository.
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read '%s': %w", path, err)
	}

	updated, changed, err := rewriteDockerfile(content, fixDetails.ImpactedDependencyName, fixDetails.ImpactedDependencyVersion, fixDetails.SuggestedFixedVersion)
	if err != nil {
		return err
	}
	if !changed {
		return fmt.Errorf("did not find '%s' with version '%s' in '%s'", fixDetails.ImpactedDependencyName, fixDetails.ImpactedDependencyVersion, path)
	}

	//#nosec G306 -- 0644 for checked-out Dockerfile in workspace.
	if err = os.WriteFile(path, updated, 0644); err != nil {
		return fmt.Errorf("failed to write '%s': %w", path, err)
	}
	log.Debug(fmt.Sprintf("Updated '%s' from '%s' to '%s' in '%s'", fixDetails.ImpactedDependencyName, fixDetails.ImpactedDependencyVersion, fixDetails.SuggestedFixedVersion, path))
	return nil
}

func rewriteDockerfile(content []byte, name, oldVersion, newVersion string) ([]byte, bool, error) {
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	changed := false
	for scanner.Scan() {
		line := scanner.Text()
		newLine, matched := rewriteFromLine(line, name, oldVersion, newVersion)
		if matched {
			changed = true
		}
		out.WriteString(newLine)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("failed to scan Dockerfile: %w", err)
	}
	result := out.Bytes()
	if len(content) > 0 && content[len(content)-1] != '\n' {
		result = result[:len(result)-1]
	}
	return result, changed, nil
}

func rewriteFromLine(line, name, oldVersion, newVersion string) (string, bool) {
	if oldVersion == "" {
		return line, false
	}
	matches := dockerFromLineRegex.FindStringSubmatch(line)
	if matches == nil {
		return line, false
	}
	prefix, imageRef, suffix := matches[1], matches[2], matches[3]

	refName, refTag, refDigest := splitImageRef(imageRef)
	if !imageNamesMatch(refName, name) {
		return line, false
	}

	var newImageRef string
	switch {
	case oldVersion == refTag && refTag != "":
		newImageRef = rebuildImageRef(refName, newVersion, refDigest)
	case oldVersion == refDigest && refDigest != "":
		newImageRef = rebuildImageRef(refName, refTag, newVersion)
	default:
		return line, false
	}
	return prefix + newImageRef + suffix, true
}

func splitImageRef(ref string) (name, tag, digest string) {
	if idx := strings.Index(ref, "@"); idx != -1 {
		digest = ref[idx+1:]
		ref = ref[:idx]
	}
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		tag = ref[lastColon+1:]
		ref = ref[:lastColon]
	}
	name = ref
	return
}

func rebuildImageRef(name, tag, digest string) string {
	result := name
	if tag != "" {
		result += ":" + tag
	}
	if digest != "" {
		result += "@" + digest
	}
	return result
}

// Normalizes implicit Docker Hub prefixes so bare "nginx" matches "docker.io/library/nginx".
func imageNamesMatch(refName, componentName string) bool {
	return normalizeImageName(refName) == normalizeImageName(componentName)
}

func normalizeImageName(name string) string {
	name = strings.ToLower(name)
	for _, prefix := range dockerHubPrefixes {
		if strings.HasPrefix(name, prefix) {
			return strings.TrimPrefix(name, prefix)
		}
	}
	return name
}
