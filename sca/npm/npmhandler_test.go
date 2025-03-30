package npm

import (
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"

	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
)

var (
	testDataDir = filepath.Join("..", "..", "tests", "testdata", "projects", "package-managers", "npm")
)

func TestNpmGetTechDependencyLocations(t *testing.T) {
	cleanUp := securityTestUtils.ChangeWDWithCallback(t, filepath.Join(testDataDir, "npm"))
	defer cleanUp()

	testCases := []struct {
		name                    string
		directDependencyName    string
		directDependencyVersion string
		filesToSearch           []string
		expectedLocations       []*sarif.Location
		expectedError           error
	}{
		{
			name:                 "dependency not found",
			directDependencyName: "json",
			filesToSearch:        []string{filepath.Join("..", "npm-scripts", "package.json")},
		},
		{
			name:                 "dependency all versions",
			directDependencyName: "json",
			filesToSearch: []string{
				"package.json",
				filepath.Join("..", "npm-big-tree", "package.json"),
				filepath.Join("..", "npm-no-lock", "package.json"),
			},
			expectedLocations: []*sarif.Location{
				sarifutils.CreateLocation("package.json", 15, 5, 15, 20, "\"json\": \"9.0.6\""),
				sarifutils.CreateLocation(filepath.Join("..", "npm-no-lock", "package.json"), 12, 5, 12, 20, "\"json\": \"9.0.3\""),
			},
		},
		{
			name:                    "dependency specific version",
			directDependencyName:    "json",
			directDependencyVersion: "9.0.6",
			filesToSearch: []string{
				"package.json",
				filepath.Join("..", "npm-scripts", "package.json"),
				filepath.Join("..", "npm-no-lock", "package.json"),
			},
			expectedLocations: []*sarif.Location{
				sarifutils.CreateLocation("package.json", 15, 5, 15, 20, "\"json\": \"9.0.6\""),
			},
		},
		{
			name:                 "search at cwd (no files to search)",
			directDependencyName: "xml",
			expectedLocations: []*sarif.Location{
				sarifutils.CreateLocation("package.json", 12, 5, 12, 19, "\"xml\": \"1.0.1\""),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nh := NpmHandler{}
			locations, err := nh.GetTechDependencyLocations(tc.directDependencyName, tc.directDependencyVersion, tc.filesToSearch...)
			assert.ElementsMatch(t, tc.expectedLocations, locations)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
