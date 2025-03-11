package npm

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	PackageJson = "package.json"
)

type NpmHandler struct{}

func (nh *NpmHandler) GetTechDependencyLocations(directDependencyName, directDependencyVersion string, filesToSearch ...string) (locations []*sarif.Location, err error) {
	for _, file := range getFilesToSearch(filesToSearch...) {
		fileLocations, err := getDependencyLocations(file, directDependencyName, directDependencyVersion)
		if err != nil {
			return nil, err
		}
		locations = append(locations, fileLocations...)
	}
	return
}

// getFilesToSearch returns the npm related files to search for the dependency
// If no files are provided, the default is to search for package.json at the current directory
func getFilesToSearch(filesToSearch ...string) (out []string) {
	if len(filesToSearch) == 0 {
		if fileutils.IsPathExists(PackageJson, false) {
			out = append(out, PackageJson)
		}
		return
	}
	for _, file := range filesToSearch {
		potentialPath := strings.TrimSuffix(file, "/")
		if strings.HasSuffix(potentialPath, PackageJson) {
			out = append(out, potentialPath)
		}
	}
	return out
}

// getDependencyLocations returns the locations of the dependency in the file
func getDependencyLocations(file, directDependencyName, dependencyVersion string) (locations []*sarif.Location, err error) {
	content, err := fileutils.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s': %v", file, err)
	}

	// Prepare regular expression to match all possible ways to specify a version.
	pattern := fmt.Sprintf(`"%s"\s*:\s*"([~^]?\d+(?:\.\d+)?(?:\.\d+)?)"`, regexp.QuoteMeta(directDependencyName))

	// Compile the regex.
	re := regexp.MustCompile(pattern)

	// Split the contents into lines for processing.
	lines := strings.Split(string(content), "\n")

	for lineNumber, line := range lines {
		// Find all match locations in the line.
		matches := re.FindStringSubmatch(line)
		if matches != nil {
			// Extract detected version from match
			detectedVersion := matches[1]

			// Normalize the given dependency version by allowing optional ~ or ^ prefix
			if dependencyVersion != "" {
				allowedPrefixes := []string{"", "~", "^"}
				matchFound := false
				for _, prefix := range allowedPrefixes {
					if strings.HasPrefix(prefix+dependencyVersion, detectedVersion) {
						matchFound = true
						break
					}
				}
				if !matchFound {
					// Skip if the provided version does not match the detected version
					continue
				}
			}

			// Get the matched snippet
			matchIndex := re.FindStringIndex(line)
			matchedSnippet := line[matchIndex[0]:matchIndex[1]]

			// Rows and Cols values are 1-based. (min value is 1)
			row := lineNumber + 1
			startCol := matchIndex[0] + 1
			locations = append(locations, sarifutils.CreateLocation(file, row, startCol, row, startCol+len(matchedSnippet), matchedSnippet))
		}
	}

	return locations, nil
}
