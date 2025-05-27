package conan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/utils"
)

var expectedResult = &xrayUtils.GraphNode{
	Id: "root",
	Nodes: []*xrayUtils.GraphNode{
		{Id: "conan://zlib:1.3.1"},
		{Id: "conan://openssl:3.0.9", Nodes: []*xrayUtils.GraphNode{{Id: "conan://zlib:1.3.1"}}},
		{Id: "conan://meson:1.4.1", Nodes: []*xrayUtils.GraphNode{{Id: "conan://ninja:1.12.1"}}},
	},
}
var expectedUniqueDeps = []string{"conan://openssl:3.0.9", "conan://zlib:1.3.1", "conan://meson:1.4.1", "conan://ninja:1.12.1"}

func TestParseConanDependencyTree(t *testing.T) {
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("other", "conan"))
	defer cleanUp()
	dependenciesJson, err := os.ReadFile("dependencies.json")
	assert.NoError(t, err)

	var output conanGraphOutput
	err = json.Unmarshal(dependenciesJson, &output)
	assert.NoError(t, err)

	graph, err := parseConanDependencyGraph("0", output.Graph.Nodes)
	assert.NoError(t, err)
	if !tests.CompareTree(expectedResult, graph) {
		t.Errorf("expected %+v, got: %+v", expectedResult.Nodes, graph)
	}
}

func TestBuildDependencyTree(t *testing.T) {
	dir, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "conan"))
	defer cleanUp()
	params := &utils.AuditBasicParams{}
	params.SetConanProfile(filepath.Join(dir, "profile"))
	graph, uniqueDeps, err := BuildDependencyTree(params)
	assert.NoError(t, err)
	if !tests.CompareTree(expectedResult, graph[0]) {
		t.Errorf("expected %+v, got: %+v", expectedResult.Nodes, graph)
	}
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
}

func TestCalculateUniqueDeps(t *testing.T) {
	input := map[string]conanRef{
		"0": {Name: "root node", Version: "please ignore"}, // root node, should be removed
		"1": {Name: "zlib", Version: "1.3.1"},
		"2": {Name: "openssl", Version: "3.0.9"},
		"3": {Name: "meson", Version: "1.4.1"},
		"4": {Name: "ninja", Version: "1.12.1"},
		"5": {Name: "openssl", Version: "3.0.9"}, // duplicate, should be removed
	}

	uniqueDeps := calculateUniqueDependencies(input)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
}
