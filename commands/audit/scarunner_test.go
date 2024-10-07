package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
)

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
