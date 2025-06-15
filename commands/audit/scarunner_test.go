package audit

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"

	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
)

func TestSetPathsForIssues(t *testing.T) {
	// Create a test dependency tree
	rootNode := &xrayUtils.GraphNode{Id: "root"}
	childNode1 := &xrayUtils.GraphNode{Id: "child1"}
	childNode2 := &xrayUtils.GraphNode{Id: "child2"}
	childNode3 := &xrayUtils.GraphNode{Id: "child3"}
	childNode4 := &xrayUtils.GraphNode{Id: "child4"}
	childNode5 := &xrayUtils.GraphNode{Id: "child5"}
	rootNode.Nodes = []*xrayUtils.GraphNode{childNode1, childNode2, childNode3}
	childNode2.Nodes = []*xrayUtils.GraphNode{childNode4}
	childNode3.Nodes = []*xrayUtils.GraphNode{childNode5}

	// Create a test issues map
	issuesMap := make(map[string][][]services.ImpactPathNode)
	issuesMap["child1"] = [][]services.ImpactPathNode{}
	issuesMap["child4"] = [][]services.ImpactPathNode{}
	issuesMap["child5"] = [][]services.ImpactPathNode{}

	// Call setPathsForIssues with the test data
	setPathsForIssues(rootNode, issuesMap, []services.ImpactPathNode{})

	// Check the results
	assert.Equal(t, issuesMap["child1"][0][0].ComponentId, "root")
	assert.Equal(t, issuesMap["child1"][0][1].ComponentId, "child1")

	assert.Equal(t, issuesMap["child4"][0][0].ComponentId, "root")
	assert.Equal(t, issuesMap["child4"][0][1].ComponentId, "child2")
	assert.Equal(t, issuesMap["child4"][0][2].ComponentId, "child4")

	assert.Equal(t, issuesMap["child5"][0][0].ComponentId, "root")
	assert.Equal(t, issuesMap["child5"][0][1].ComponentId, "child3")
	assert.Equal(t, issuesMap["child5"][0][2].ComponentId, "child5")
}

func TestUpdateVulnerableComponent(t *testing.T) {
	components := map[string]services.Component{
		"dependency1": {
			FixedVersions: []string{"1.0.0"},
			ImpactPaths:   [][]services.ImpactPathNode{},
		},
	}
	dependencyName, issuesMap := "dependency1", map[string][][]services.ImpactPathNode{
		"dependency1": {},
	}

	updateComponentsWithImpactPaths(components, issuesMap)

	// Check the result
	expected := services.Component{
		FixedVersions: []string{"1.0.0"},
		ImpactPaths:   issuesMap[dependencyName],
	}
	assert.Equal(t, expected, components[dependencyName])
}

func TestBuildImpactPaths(t *testing.T) {
	// create sample scan result and dependency trees
	scanResult := []services.ScanResponse{
		{
			Vulnerabilities: []services.Vulnerability{
				{
					Components: map[string]services.Component{
						"dep1": {
							FixedVersions: []string{"1.2.3"},
							Cpes:          []string{"cpe:/o:vendor:product:1.2.3"},
						},
						"dep2": {
							FixedVersions: []string{"3.0.0"},
						},
					},
				},
			},
			Violations: []services.Violation{
				{
					Components: map[string]services.Component{
						"dep2": {
							FixedVersions: []string{"4.5.6"},
							Cpes:          []string{"cpe:/o:vendor:product:4.5.6"},
						},
					},
				},
			},
			Licenses: []services.License{
				{
					Components: map[string]services.Component{
						"dep3": {
							FixedVersions: []string{"7.8.9"},
							Cpes:          []string{"cpe:/o:vendor:product:7.8.9"},
						},
					},
				},
			},
		},
	}
	dependencyTrees := []*xrayUtils.GraphNode{
		{
			Id: "dep1",
			Nodes: []*xrayUtils.GraphNode{
				{
					Id: "dep2",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "dep3",
							Nodes: []*xrayUtils.GraphNode{},
						},
					},
				},
			},
		},
		{
			Id: "dep7",
			Nodes: []*xrayUtils.GraphNode{
				{
					Id: "dep4",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "dep2",
							Nodes: []*xrayUtils.GraphNode{},
						},
						{
							Id:    "dep5",
							Nodes: []*xrayUtils.GraphNode{},
						},
						{
							Id:    "dep6",
							Nodes: []*xrayUtils.GraphNode{},
						},
					},
				},
			},
		},
	}

	scanResult = BuildImpactPathsForScanResponse(scanResult, dependencyTrees)
	// assert that the components were updated with impact paths
	expectedImpactPaths := [][]services.ImpactPathNode{{{ComponentId: "dep1"}}}
	assert.Equal(t, expectedImpactPaths, scanResult[0].Vulnerabilities[0].Components["dep1"].ImpactPaths)
	expectedImpactPaths = [][]services.ImpactPathNode{{{ComponentId: "dep1"}, {ComponentId: "dep2"}}}
	reflect.DeepEqual(expectedImpactPaths, scanResult[0].Vulnerabilities[0].Components["dep2"].ImpactPaths[0])
	expectedImpactPaths = [][]services.ImpactPathNode{{{ComponentId: "dep7"}, {ComponentId: "dep4"}, {ComponentId: "dep2"}}}
	reflect.DeepEqual(expectedImpactPaths, scanResult[0].Vulnerabilities[0].Components["dep2"].ImpactPaths[1])
	expectedImpactPaths = [][]services.ImpactPathNode{{{ComponentId: "dep1"}}}
	reflect.DeepEqual(expectedImpactPaths, scanResult[0].Violations[0].Components["dep1"].ImpactPaths)
	expectedImpactPaths = [][]services.ImpactPathNode{{{ComponentId: "dep1"}, {ComponentId: "dep2"}}}
	reflect.DeepEqual(expectedImpactPaths, scanResult[0].Violations[0].Components["dep2"].ImpactPaths[0])
	expectedImpactPaths = [][]services.ImpactPathNode{{{ComponentId: "dep7"}, {ComponentId: "dep4"}, {ComponentId: "dep2"}}}
	reflect.DeepEqual(expectedImpactPaths, scanResult[0].Violations[0].Components["dep2"].ImpactPaths[1])
	expectedImpactPaths = [][]services.ImpactPathNode{{{ComponentId: "dep7"}, {ComponentId: "dep4"}, {ComponentId: "dep2"}}}
	reflect.DeepEqual(expectedImpactPaths, scanResult[0].Violations[0].Components["dep2"].ImpactPaths)
	expectedImpactPaths = [][]services.ImpactPathNode{{{ComponentId: "dep1"}, {ComponentId: "dep2"}, {ComponentId: "dep3"}}}
	reflect.DeepEqual(expectedImpactPaths, scanResult[0].Licenses[0].Components["dep3"].ImpactPaths)
}

func TestGetDirectDependenciesFromTree(t *testing.T) {
	tests := []struct {
		dependenciesTrees []*xrayUtils.GraphNode
		expectedResult    []string
	}{
		{
			dependenciesTrees: nil,
			expectedResult:    []string{},
		},
		{
			dependenciesTrees: []*xrayUtils.GraphNode{
				{Id: "parent_node_id", Nodes: []*xrayUtils.GraphNode{
					{Id: "issueId_1_direct_dependency", Nodes: []*xrayUtils.GraphNode{{Id: "issueId_1_non_direct_dependency"}}},
					{Id: "issueId_2_direct_dependency", Nodes: nil},
				},
				},
			},
			expectedResult: []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"},
		},
		{
			dependenciesTrees: []*xrayUtils.GraphNode{
				{Id: "parent_node_id", Nodes: []*xrayUtils.GraphNode{
					{Id: "issueId_1_direct_dependency", Nodes: nil},
					{Id: "issueId_2_direct_dependency", Nodes: nil},
				},
				},
			},
			expectedResult: []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"},
		},
	}

	for _, test := range tests {
		result := getDirectDependenciesFromTree(test.dependenciesTrees)
		assert.ElementsMatch(t, test.expectedResult, result)
	}
}

func createTestDir(t *testing.T) (directory string, cleanUp func()) {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)

	// Temp dir structure:
	// tempDir
	// ├── dir
	// │   ├── maven
	// │   │   ├── maven-sub
	// │   │   └── maven-sub
	// │   ├── npm
	// │   └── go
	// ├── yarn
	// │   ├── Pip
	// │   └── Pipenv
	// └── Nuget
	//	   ├── Nuget-sub

	dir := createEmptyDir(t, filepath.Join(tmpDir, "dir"))
	// Maven
	maven := createEmptyDir(t, filepath.Join(dir, "maven"))
	createEmptyFile(t, filepath.Join(maven, "pom.xml"))
	mavenSub := createEmptyDir(t, filepath.Join(maven, "maven-sub"))
	createEmptyFile(t, filepath.Join(mavenSub, "pom.xml"))
	mavenSub2 := createEmptyDir(t, filepath.Join(maven, "maven-sub2"))
	createEmptyFile(t, filepath.Join(mavenSub2, "pom.xml"))
	// Npm
	npm := createEmptyDir(t, filepath.Join(dir, "npm"))
	createEmptyFile(t, filepath.Join(npm, "package.json"))
	createEmptyFile(t, filepath.Join(npm, "package-lock.json"))
	// Go
	goDir := createEmptyDir(t, filepath.Join(dir, "go"))
	createEmptyFile(t, filepath.Join(goDir, "go.mod"))
	// Yarn
	yarn := createEmptyDir(t, filepath.Join(tmpDir, "yarn"))
	createEmptyFile(t, filepath.Join(yarn, "package.json"))
	createEmptyFile(t, filepath.Join(yarn, "yarn.lock"))
	// Pip
	pip := createEmptyDir(t, filepath.Join(yarn, "Pip"))
	createEmptyFile(t, filepath.Join(pip, "requirements.txt"))
	// Pipenv
	pipenv := createEmptyDir(t, filepath.Join(yarn, "Pipenv"))
	createEmptyFile(t, filepath.Join(pipenv, "Pipfile"))
	createEmptyFile(t, filepath.Join(pipenv, "Pipfile.lock"))
	// Nuget
	nuget := createEmptyDir(t, filepath.Join(tmpDir, "Nuget"))
	createEmptyFile(t, filepath.Join(nuget, "project.sln"))
	nugetSub := createEmptyDir(t, filepath.Join(nuget, "Nuget-sub"))
	createEmptyFile(t, filepath.Join(nugetSub, "project.csproj"))

	return tmpDir, func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir), "Couldn't removeAll: "+tmpDir)
	}
}

func createEmptyDir(t *testing.T, path string) string {
	assert.NoError(t, fileutils.CreateDirIfNotExist(path))
	return path
}

func createEmptyFile(t *testing.T, path string) {
	file, err := os.Create(path)
	assert.NoError(t, err)
	assert.NoError(t, file.Close())
}
