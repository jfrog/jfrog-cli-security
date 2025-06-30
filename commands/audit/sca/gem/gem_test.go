package gem

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/utils"
)

var expectedUniqueDeps = []string{"rubygems://puma:5.6.9", "rubygems://nio4r:2.7.4"}

var expectedResult = &xrayUtils.GraphNode{
	Id: "root",
	Nodes: []*xrayUtils.GraphNode{
		{
			Id: "rubygems://puma:5.6.9",
			Nodes: []*xrayUtils.GraphNode{
				{
					Id:    "rubygems://nio4r:2.7.4",
					Nodes: []*xrayUtils.GraphNode{},
				},
			},
		},
	},
}

func TestBuildDependencyTree(t *testing.T) {
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "gem"))
	defer cleanUp()
	params := &utils.AuditBasicParams{}
	actualTopLevelTrees, uniqueDeps, err := BuildDependencyTree(params)
	assert.NoError(t, err, "BuildDependencyTree should not return an error")
	expectedTopLevelTrees := expectedResult.Nodes
	expectedJSON, err := json.MarshalIndent(expectedTopLevelTrees, "", "  ")
	assert.NoError(t, err, "Failed to marshal expectedTopLevelTrees")
	actualJSON, err := json.MarshalIndent(actualTopLevelTrees, "", "  ")
	assert.NoError(t, err, "Failed to marshal actualTopLevelTrees")
	if !reflect.DeepEqual(expectedTopLevelTrees, actualTopLevelTrees) {
		t.Errorf("Dependency tree mismatch.\nExpected (JSON):\n%s\nGot (JSON):\n%s",
			string(expectedJSON), string(actualJSON))
	}
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "Unique dependencies mismatch. First is actual, Second is Expected")
}

// expectedUniqueDeps should be defined
// expectedUniqueDeps := []string{"rubygems://puma:5.6.9", "rubygems://nio4r:2.7.4"}
func TestCalculateUniqueDeps(t *testing.T) {
	var input = &xrayUtils.GraphNode{
		Id: "root",
		Nodes: []*xrayUtils.GraphNode{
			{
				Id: "rubygems://puma:5.6.9",
				Nodes: []*xrayUtils.GraphNode{
					{
						Id:    "rubygems://nio4r:2.7.4",
						Nodes: []*xrayUtils.GraphNode{},
					},
				},
			},
		},
	}
	uniqueDeps := calculateUniqueDependencies(input.Nodes)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
}
