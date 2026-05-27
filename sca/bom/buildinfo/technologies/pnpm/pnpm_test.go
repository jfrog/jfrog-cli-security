package pnpm

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
)

func TestBuildDependencyTreeLimitedDepth(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "npm", "npm-big-tree"))
	defer cleanUp()
	testCases := []struct {
		name               string
		treeDepth          string
		expectedUniqueDeps []string
		expectedTree       *xrayUtils.GraphNode
	}{
		{
			name:      "Only direct dependencies",
			treeDepth: "0",
			expectedUniqueDeps: []string{
				"npm://zen-website:1.0.0",
				"npm://balaganjs:1.0.0",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id:    "npm://zen-website:1.0.0",
				Nodes: []*xrayUtils.GraphNode{{Id: "npm://balaganjs:1.0.0"}},
			},
		},
		{
			name:      "With transitive dependencies",
			treeDepth: "1",
			expectedUniqueDeps: []string{
				"npm://axios:1.17.0",
				"npm://balaganjs:1.0.0",
				"npm://yargs:13.3.0",
				"npm://zen-website:1.0.0",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id: "npm://zen-website:1.0.0",
				Nodes: []*xrayUtils.GraphNode{
					{
						Id:    "npm://balaganjs:1.0.0",
						Nodes: []*xrayUtils.GraphNode{{Id: "npm://axios:1.17.0"}, {Id: "npm://yargs:13.3.0"}},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			params := technologies.BuildInfoBomGeneratorParams{MaxTreeDepth: testCase.treeDepth}
			rootNode, uniqueDeps, err := BuildDependencyTree(params)
			require.NoError(t, err)
			sort.Slice(uniqueDeps, func(i, j int) bool {
				return uniqueDeps[i] < uniqueDeps[j]
			})
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

func TestBuildDependencyTreePnpmLockfile(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "pnpm", "pnpm-project"))
	defer cleanUp()

	testCases := []struct {
		name               string
		depScope           string
		expectedUniqueDeps []string
		expectedTree       *xrayUtils.GraphNode
	}{
		{
			name:     "All dependencies",
			depScope: "all",
			expectedUniqueDeps: []string{
				"npm://pnpm-example:1.0.0",
				"npm://xml:1.0.1",
				"npm://json:9.0.6",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id: "npm://pnpm-example:1.0.0",
				Nodes: []*xrayUtils.GraphNode{
					{Id: "npm://xml:1.0.1"},
					{Id: "npm://json:9.0.6"},
				},
			},
		},
		{
			name:     "Prod only",
			depScope: "prodOnly",
			expectedUniqueDeps: []string{
				"npm://pnpm-example:1.0.0",
				"npm://xml:1.0.1",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id:    "npm://pnpm-example:1.0.0",
				Nodes: []*xrayUtils.GraphNode{{Id: "npm://xml:1.0.1"}},
			},
		},
		{
			name:     "Dev only",
			depScope: "devOnly",
			expectedUniqueDeps: []string{
				"npm://pnpm-example:1.0.0",
				"npm://json:9.0.6",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id:    "npm://pnpm-example:1.0.0",
				Nodes: []*xrayUtils.GraphNode{{Id: "npm://json:9.0.6"}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			params := technologies.BuildInfoBomGeneratorParams{}
			rootNode, uniqueDeps, err := BuildDependencyTree(*params.SetNpmScope(testCase.depScope))
			require.NoError(t, err)
			sort.Slice(uniqueDeps, func(i, j int) bool { return uniqueDeps[i] < uniqueDeps[j] })
			assert.ElementsMatch(t, uniqueDeps, testCase.expectedUniqueDeps)
			if assert.Len(t, rootNode, 1) {
				assert.Equal(t, testCase.expectedTree.Id, rootNode[0].Id)
				if !tests.CompareTree(testCase.expectedTree, rootNode[0]) {
					t.Error("expected:", testCase.expectedTree.Nodes, "got:", rootNode[0].Nodes)
				}
			}
		})
	}
}

func TestEnsureLockfileExisting(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "pnpm", "pnpm-project"))
	defer cleanUp()

	pnpmExecPath, err := getPnpmExecPath()
	require.NoError(t, err)

	// Workspace already contains pnpm-lock.yaml — ensureLockfile should be a no-op.
	err = ensureLockfile(pnpmExecPath, ".")
	assert.NoError(t, err)
}
