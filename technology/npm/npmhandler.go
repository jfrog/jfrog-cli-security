package npm

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	PackageJson = "package.json"
)

type NpmHandler struct {

}

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

// getDependencyLocations returns the locations of the dependency in the file
func getDependencyLocations(file, directDependencyName, _ string) (locations []*sarif.Location, err error) {
	regex := fmt.Sprintf(`"%s":\s*".*?"`, directDependencyName)
	
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
	return filesToSearch
}