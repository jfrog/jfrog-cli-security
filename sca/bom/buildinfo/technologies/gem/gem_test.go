package gem

import (
	"path/filepath"
	"reflect"
	"testing"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils"
)

var expectedUniqueDeps = []string{"rubygems://puma:5.6.9", "rubygems://nio4r:2.7.5"}

var expectedResult = &xrayUtils.GraphNode{
	Id: "root",
	Nodes: []*xrayUtils.GraphNode{
		{
			Id: "rubygems://puma:5.6.9",
			Nodes: []*xrayUtils.GraphNode{
				{
					Id:    "rubygems://nio4r:2.7.5",
					Nodes: []*xrayUtils.GraphNode{},
				},
			},
		},
	},
}

func TestBuildDependencyTree(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "gem"))
	defer cleanUp()
	params := technologies.BuildInfoBomGeneratorParams{SkipAutoInstall: true}
	actualTopLevelTrees, uniqueDeps, err := BuildDependencyTree(params)
	assert.NoError(t, err, "BuildDependencyTree should not return an error")
	expectedTopLevelTrees := expectedResult.Nodes
	if !reflect.DeepEqual(expectedTopLevelTrees, actualTopLevelTrees) {
		expectedJSON, err := utils.GetAsJsonString(expectedTopLevelTrees, true, false)
		if err != nil {
			t.Fatalf("Failed to marshal expected dependency tree to JSON for error reporting: %v", err)
		}

		actualJSON, err := utils.GetAsJsonString(actualTopLevelTrees, true, false)
		if err != nil {
			t.Fatalf("Failed to marshal actual dependency tree to JSON for error reporting: %v", err)
		}
		t.Errorf("Dependency tree mismatch.\nExpected (JSON):\n%s\nGot (JSON):\n%s", expectedJSON, actualJSON)
	}
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "Unique dependencies mismatch. First is actual, Second is Expected")
}

// expectedUniqueDeps should be defined
// expectedUniqueDeps := []string{"rubygems://puma:5.6.9", "rubygems://nio4r:2.7.5"}
func TestCalculateUniqueDeps(t *testing.T) {
	var input = &xrayUtils.GraphNode{
		Nodes: []*xrayUtils.GraphNode{
			{
				Id: "rubygems://puma:5.6.9",
				Nodes: []*xrayUtils.GraphNode{
					{
						Id:    "rubygems://nio4r:2.7.5",
						Nodes: []*xrayUtils.GraphNode{},
					},
				},
			},
		},
	}
	uniqueDeps := calculateUniqueDependencies(input.Nodes)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
}
