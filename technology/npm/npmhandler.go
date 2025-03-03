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
		return []string{PackageJson}
	}
	for _, file := range filesToSearch {
		if strings.HasSuffix(strings.TrimSuffix(file, "/"), PackageJson) {
			out = append(out, file)
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
	// Prepare regular expression to match the dependency.
	var pattern string
	if dependencyVersion == "" {
		// If version is not provided, prepare a regex to match all versions.
		pattern = fmt.Sprintf(`"%s"\s*:\s*"([^"]+)"`, regexp.QuoteMeta(directDependencyName))
	} else {
		// If version is provided, match the specific version.
		pattern = fmt.Sprintf(`"%s"\s*:\s*"%s"`, regexp.QuoteMeta(directDependencyName), regexp.QuoteMeta(dependencyVersion))
	}

	// Compile the regex.
	re := regexp.MustCompile(pattern)

	// Split the contents into lines for processing.
	lines := strings.Split(string(content), "\n")

	for lineNumber, line := range lines {
		// Find all match locations in the line.
		matchIndices := re.FindStringIndex(line)
		if matchIndices != nil {
			// Get the matched snippet
			matchedSnippet := line[matchIndices[0]:matchIndices[1]]
			// Rows and Cols are 1-indexed
			row := lineNumber + 1
			startCol := matchIndices[0] + 1
			locations = append(locations, sarifutils.CreateLocation(file, row, startCol, row, startCol+len(matchedSnippet), matchedSnippet))
		}
	}

	return locations, nil
}
