package _go

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/stretchr/testify/assert"
)

func TestBuildGoDependencyList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "go", "go-project"))
	defer cleanUp()

	err := removeTxtSuffix("go.mod.txt")
	assert.NoError(t, err)
	err = removeTxtSuffix("go.sum.txt")
	assert.NoError(t, err)
	err = removeTxtSuffix("test.go.txt")
	assert.NoError(t, err)

	// Run getModulesDependencyTrees
	server := &config.ServerDetails{
		Url:            "https://api.go.here",
		ArtifactoryUrl: "https://api.go.here/artifactory",
		User:           "user",
		AccessToken:    "sdsdccs2232",
	}
	goVersionID, err := getGoVersionAsDependency()
	assert.NoError(t, err)
	expectedUniqueDeps := []string{
		goPackageTypeIdentifier + "golang.org/x/text:v0.3.3",
		goPackageTypeIdentifier + "rsc.io/quote:v1.5.2",
		goPackageTypeIdentifier + "rsc.io/sampler:v1.3.0",
		goPackageTypeIdentifier + "testGoList",
		goVersionID.Id,
	}

	auditBasicParams := technologies.BuildInfoBomGeneratorParams{ServerDetails: server, DependenciesRepository: "test-remote"}
	rootNode, uniqueDeps, err := BuildDependencyTree(auditBasicParams)
	assert.NoError(t, err)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
	// jfrog-ignore: test case
	assert.Equal(t, "https://user:sdsdccs2232@api.go.here/artifactory/api/go/test-remote|direct", os.Getenv("GOPROXY"))
	assert.NotEmpty(t, rootNode)

	// Check root module
	assert.Equal(t, rootNode[0].Id, goPackageTypeIdentifier+"testGoList")
	assert.Len(t, rootNode[0].Nodes, 3)

	// Test go version node
	goVersion, err := utils.GetParsedGoVersion()
	assert.NoError(t, err)
	tests.GetAndAssertNode(t, rootNode[0].Nodes, strings.ReplaceAll(goVersion.GetVersion(), "go", goSourceCodePrefix))

	// Test child without sub nodes
	child1 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "golang.org/x/text:v0.3.3")
	assert.Len(t, child1.Nodes, 0)

	// Test child with 1 sub node
	child2 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "rsc.io/quote:v1.5.2")
	assert.Len(t, child2.Nodes, 1)
	tests.GetAndAssertNode(t, child2.Nodes, "rsc.io/sampler:v1.3.0")
}

func removeTxtSuffix(txtFileName string) error {
	// go.sum.txt  >> go.sum
	return fileutils.MoveFile(txtFileName, strings.TrimSuffix(txtFileName, ".txt"))
}

// TestGetLocalReplaceModules: go.mod replaces example.com/localmod with a local directory.
// getLocalReplaceModules must report that module path as local.
func TestGetLocalReplaceModules(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "go", "go-local-replace-project"))
	defer cleanUp()

	assert.NoError(t, removeTxtSuffix("go.mod.txt"))

	currentDir, err := os.Getwd()
	assert.NoError(t, err)
	localReplaceModules := getLocalReplaceModules(currentDir)
	assert.Equal(t, map[string]bool{"example.com/localmod": true}, localReplaceModules)
}

// TestPopulateGoDependencyTree_LocalReplace: given a graph/list shaped like real 'go mod graph'/'go list'
// output for a local-replaced module, the tree must tag that module but leave its real dependency and an
// unrelated real dependency untouched.
func TestPopulateGoDependencyTree_LocalReplace(t *testing.T) {
	dependenciesGraph := map[string][]string{
		"testGoLocalReplace": {
			"example.com/localmod:v0.0.0",
			"rsc.io/quote:v1.5.2",
		},
		"example.com/localmod:v0.0.0": {
			"golang.org/x/text:v0.3.3",
		},
		"rsc.io/quote:v1.5.2": {
			"rsc.io/sampler:v1.3.0",
		},
	}
	dependenciesList := map[string]bool{
		"example.com/localmod:v0.0.0": true,
		"golang.org/x/text:v0.3.3":    true,
		"rsc.io/quote:v1.5.2":         true,
		"rsc.io/sampler:v1.3.0":       true,
	}
	localReplaceModules := map[string]bool{"example.com/localmod": true}

	rootNode := &xrayUtils.GraphNode{Id: goPackageTypeIdentifier + "testGoLocalReplace", Nodes: []*xrayUtils.GraphNode{}}
	uniqueDepsSet := datastructures.MakeSet[string]()
	populateGoDependencyTree(rootNode, dependenciesGraph, dependenciesList, uniqueDepsSet, localReplaceModules)

	expectedUniqueDeps := []string{
		goPackageTypeIdentifier + "testGoLocalReplace",
		goPackageTypeIdentifier + "example.com/localmod:v0.0.0" + LocalReplaceMarker,
		goPackageTypeIdentifier + "golang.org/x/text:v0.3.3",
		goPackageTypeIdentifier + "rsc.io/quote:v1.5.2",
		goPackageTypeIdentifier + "rsc.io/sampler:v1.3.0",
	}
	assert.ElementsMatch(t, uniqueDepsSet.ToSlice(), expectedUniqueDeps, "First is actual, Second is Expected")

	// The locally-replaced module is tagged with the marker...
	localReplaceNode := tests.GetAndAssertNode(t, rootNode.Nodes, "example.com/localmod:v0.0.0"+LocalReplaceMarker)
	// ...but its own real, published dependency is still present, walked, and NOT marked.
	assert.Len(t, localReplaceNode.Nodes, 1)
	tests.GetAndAssertNode(t, localReplaceNode.Nodes, "golang.org/x/text:v0.3.3")

	// An unrelated real dependency (and its own transitive dependency) is completely untouched.
	realDep := tests.GetAndAssertNode(t, rootNode.Nodes, "rsc.io/quote:v1.5.2")
	assert.Len(t, realDep.Nodes, 1)
	tests.GetAndAssertNode(t, realDep.Nodes, "rsc.io/sampler:v1.3.0")
}

func Test_handleCurationGoError(t *testing.T) {

	tests := []struct {
		name          string
		err           error
		expectedError error
	}{
		{
			name:          "curation error 403",
			err:           errors.New("package download failed due to 403 forbidden test failure"),
			expectedError: fmt.Errorf(technologies.CurationErrorMsgToUserTemplate, techutils.Go),
		},
		{
			name: "not curation error 500",
			err:  errors.New("package download failed due to 500 internal server error test failure"),
		},
		{
			name: "no error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handleCurationGoError(tt.err)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedError != nil, got)
		})
	}
}
