package pnpm

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/utils"
)

func TestBuildDependencyTree(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "npm", "npm-no-lock"))
	defer cleanUp()

	testCases := []struct {
		name               string
		depType            string
		expectedUniqueDeps []string
		expectedTree       *xrayUtils.GraphNode
	}{
		{
			name:    "All",
			depType: "all",
			expectedUniqueDeps: []string{
				"npm://jfrog-cli-tests:v1.0.0",
				"npm://xml:1.0.1",
				"npm://json:9.0.6",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id: "npm://jfrog-cli-tests:v1.0.0",
				Nodes: []*xrayUtils.GraphNode{
					{Id: "npm://xml:1.0.1"},
					{Id: "npm://json:9.0.6"},
				},
			},
		},
		{
			name:    "Prod",
			depType: "prodOnly",
			expectedUniqueDeps: []string{
				"npm://jfrog-cli-tests:v1.0.0",
				"npm://xml:1.0.1",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id:    "npm://jfrog-cli-tests:v1.0.0",
				Nodes: []*xrayUtils.GraphNode{{Id: "npm://xml:1.0.1"}},
			},
		},
		{
			name:    "Dev",
			depType: "devOnly",
			expectedUniqueDeps: []string{
				"npm://jfrog-cli-tests:v1.0.0",
				"npm://json:9.0.6",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id:    "npm://jfrog-cli-tests:v1.0.0",
				Nodes: []*xrayUtils.GraphNode{{Id: "npm://json:9.0.6"}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Build dependency tree
			params := &utils.AuditBasicParams{}
			rootNode, uniqueDeps, err := BuildDependencyTree(params.SetNpmScope(testCase.depType))
			require.NoError(t, err)
			// Validations
			assert.ElementsMatch(t, uniqueDeps, testCase.expectedUniqueDeps, "First is actual, Second is Expected")
			if assert.Len(t, rootNode, 1) {
				assert.Equal(t, rootNode[0].Id, testCase.expectedTree.Id)
				if !tests.CompareTree(testCase.expectedTree, rootNode[0]) {
					t.Error("expected:", testCase.expectedTree.Nodes, "got:", rootNode[0].Nodes)
				}
			}
		})
	}
}

func TestInstallProjectIfNeeded(t *testing.T) {
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "npm", "npm-no-lock"))
	defer cleanUp()

	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)

	pnpmExecPath, err := getPnpmExecPath()
	assert.NoError(t, err)

	dirForDependenciesCalculation, err := installProjectIfNeeded(pnpmExecPath, currentDir)
	assert.NoError(t, err)
	assert.NotEmpty(t, dirForDependenciesCalculation)

	nodeModulesExist, err := fileutils.IsDirExists(filepath.Join(dirForDependenciesCalculation, "node_modules"), false)
	assert.NoError(t, err)
	assert.True(t, nodeModulesExist)

	nodeModulesExist, err = fileutils.IsDirExists(filepath.Join(currentDir, "node_modules"), false)
	assert.NoError(t, err)
	assert.False(t, nodeModulesExist)
}
