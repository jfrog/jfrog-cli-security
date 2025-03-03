package npm

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

var (
	testDataDir = filepath.Join("..", "..", "tests", "testdata", "projects", "package-managers", "npm")
)

func TestNpmGetTechDependencyLocations(t *testing.T) {
	testCases := []struct {
		name                    string
		directDependencyName    string
		directDependencyVersion string
		filesToSearch           []string
		expectedLocations       []*sarif.Location
		expectedError           error
	}{
		{
			name:                 "no dependencies",
			directDependencyName: "json",
			filesToSearch:        []string{filepath.Join(testDataDir, "npm-scripts", "package.json")},
		},
		{
			name:                 "multiple locations",
			directDependencyName: "json",
			filesToSearch: []string{
				filepath.Join(testDataDir, "npm", "package.json"),
				filepath.Join(testDataDir, "npm-scripts", "package.json"),
				filepath.Join(testDataDir, "npm-big-tree", "package.json"),
				filepath.Join(testDataDir, "npm-no-lock", "package.json"),
			},
			expectedLocations: []*sarif.Location{
				sarifutils.CreateLocation(filepath.Join(testDataDir, "npm", "package.json"), 15, 5, 15, 20, "\"json\": \"9.0.6\""),
				sarifutils.CreateLocation(filepath.Join(testDataDir, "npm-no-lock", "package.json"), 12, 5, 12, 20, "\"json\": \"9.0.6\""),
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
