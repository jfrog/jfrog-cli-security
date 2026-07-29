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

const DockerfileName = "Dockerfile"

var dockerFromLineRegex = regexp.MustCompile(`(?i)^(\s*FROM\s+(?:--\S+\s+)*)(\S+)(\s+AS\s+\S+)?\s*$`)

type DockerPackageUpdater struct{}

func (d *DockerPackageUpdater) UpdateDependency(fixDetails *FixDetails) error {
	descriptorPaths := collectDockerfilePaths(fixDetails)
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

func collectDockerfilePaths(fixDetails *FixDetails) []string {
	pathsSet := datastructures.MakeSet[string]()
	for _, component := range fixDetails.Components {
		for _, evidence := range component.Evidences {
			if evidence.File == "" {
				continue
			}
			if filepath.Base(evidence.File) != DockerfileName {
				continue
			}
			pathsSet.Add(evidence.File)
		}
	}
	return pathsSet.ToSlice()
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

	refName, refVersion := splitImageRef(imageRef)
	if !strings.EqualFold(refName, name) || refVersion != oldVersion {
		return line, false
	}
	return prefix + refName + separatorFor(newVersion) + newVersion + suffix, true
}

func splitImageRef(ref string) (string, string) {
	if idx := strings.Index(ref, "@"); idx != -1 {
		return ref[:idx], ref[idx+1:]
	}
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:]
	}
	return ref, ""
}

func separatorFor(version string) string {
	if strings.HasPrefix(version, "sha256:") || strings.HasPrefix(version, "sha512:") {
		return "@"
	}
	return ":"
}
