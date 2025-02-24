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

type NpmHandler struct {}

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
func getDependencyLocations(file, directDependencyName, _ string) (locations []*sarif.Location, err error) {
	content, err := fileutils.ReadFile(file)
	if err != nil {
		return nil, err
	}
	text := string(content)
	// Regex pattern to match `"json": "version"`
	pattern := fmt.Sprintf(`"(%s)"\s*:\s*"(.*?)"`, directDependencyName)
	re := regexp.MustCompile(pattern)

	// Find all matches
	matches := re.FindAllStringIndex(text, -1)
	if matches == nil {
		return nil, fmt.Errorf("dependency '%s' not found", directDependencyName)
	}

	for _, match := range matches {
		startIdx := match[0]
		endIdx := match[1]

		// Calculate row and column positions
		startRow := strings.Count(text[:startIdx], "\n") + 1
		lastNewline := strings.LastIndex(text[:startIdx], "\n")
		startCol := startIdx - lastNewline

		endRow := strings.Count(text[:endIdx], "\n") + 1
		lastNewlineEnd := strings.LastIndex(text[:endIdx], "\n")
		endCol := endIdx - lastNewlineEnd

		locations = append(locations, sarifutils.CreateLocation(file, startRow, startCol, endRow, endCol, directDependencyName))
	}

	return locations, nil
}
