package npm

import (
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

var (
	testDataDir = filepath.Join("..", "..", "tests", "testdata", "projects", "package-managers", "npm")
)

func TestNpmGetTechDependencyLocations(t *testing.T) {
	testCases := []struct {
		name string
		directDependencyName string
		directDependencyVersion string
		filesToSearch []string
		expectedLocations []*sarif.Location
		expectedError error
	}{}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nh := NpmHandler{}
			locations, err := nh.GetTechDependencyLocations(tc.directDependencyName, tc.directDependencyVersion, tc.filesToSearch...)
			assert.Equal(t, tc.expectedLocations, locations)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}