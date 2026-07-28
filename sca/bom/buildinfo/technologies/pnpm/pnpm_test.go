package pnpm

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
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
				"npm://axios:1.18.1",
				"npm://balaganjs:1.0.0",
				"npm://yargs:13.3.0",
				"npm://zen-website:1.0.0",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id: "npm://zen-website:1.0.0",
				Nodes: []*xrayUtils.GraphNode{
					{
						Id:    "npm://balaganjs:1.0.0",
						Nodes: []*xrayUtils.GraphNode{{Id: "npm://axios:1.18.1"}, {Id: "npm://yargs:13.3.0"}},
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
			params := technologies.BuildInfoBomGeneratorParams{IsCurationCmd: true}
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

func TestResolveLockfileDirExisting(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "pnpm", "pnpm-project"))
	defer cleanUp()

	pnpmExecPath, _, err := getPnpmExecPath()
	require.NoError(t, err)

	// Workspace already contains an up-to-date pnpm-lock.yaml — resolveLockfileDir
	// should return the working dir itself (no temp copy, no project modification).
	lockfileDir, cleanup, err := resolveLockfileDir(pnpmExecPath, ".")
	require.NoError(t, err)
	defer func() { assert.NoError(t, cleanup()) }()
	assert.Equal(t, ".", lockfileDir)
}

// TestBuildDependencyTree exercises the audit/scan path (pnpm ls --json) which is
// the pre-existing behaviour unmodified by the curation-audit feature.
func TestBuildDependencyTree(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "npm", "npm-no-lock"))
	defer cleanUp()

	testCases := []struct {
		name               string
		depScope           string
		expectedUniqueDeps []string
		expectedTree       *xrayUtils.GraphNode
	}{
		{
			name:     "All",
			depScope: "all",
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
			name:     "Prod",
			depScope: "prodOnly",
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
			name:     "Dev",
			depScope: "devOnly",
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
			// IsCurationCmd is false (default) — exercises the pnpm ls audit path.
			params := technologies.BuildInfoBomGeneratorParams{}
			rootNode, uniqueDeps, err := BuildDependencyTree(*params.SetNpmScope(testCase.depScope))
			require.NoError(t, err)
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

// TestInstallProjectIfNeeded verifies that installProjectIfNeeded creates a temp dir
// with node_modules installed without touching the original project directory.
func TestInstallProjectIfNeeded(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "npm", "npm-no-lock"))
	defer cleanUp()

	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)

	pnpmExecPath, _, err := getPnpmExecPath()
	assert.NoError(t, err)

	dirForDependenciesCalculation, err := installProjectIfNeeded(pnpmExecPath, currentDir)
	assert.NoError(t, err)
	assert.NotEmpty(t, dirForDependenciesCalculation)

	nodeModulesExist, err := fileutils.IsDirExists(filepath.Join(dirForDependenciesCalculation, "node_modules"), false)
	assert.NoError(t, err)
	assert.True(t, nodeModulesExist)

	// Original directory must NOT have node_modules created.
	nodeModulesExist, err = fileutils.IsDirExists(filepath.Join(currentDir, "node_modules"), false)
	assert.NoError(t, err)
	assert.False(t, nodeModulesExist)
}

// TestParsePnpmLSContentNestsWorkspaceMembers verifies that a multi-importer
// workspace is rendered as a single tree rooted at the workspace root, with each
// member nested as a direct child carrying its own dependencies — matching npm.
func TestParsePnpmLSContentNestsWorkspaceMembers(t *testing.T) {
	projects, err := parsePnpmLockFile(viteFixtureDir(t), ".")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	trees, uniqueDeps := parsePnpmLSContent(projects)
	require.Len(t, trees, 1, "workspace must collapse into a single root tree")
	root := trees[0]

	viteMember := findNodeByID(root, getDependencyId("packages/vite", "0.0.0"))
	require.NotNil(t, viteMember, "packages/vite must be a node under the root")
	assert.NotNil(t, findNodeByID(viteMember, getDependencyId("rolldown", "1.0.3")),
		"member's dependency must be nested under the member node")

	createMember := findNodeByID(root, getDependencyId("packages/create-vite", "0.0.0"))
	require.NotNil(t, createMember, "packages/create-vite must be a node under the root")
	assert.NotNil(t, findNodeByID(createMember, getDependencyId("cross-spawn", "7.0.6")),
		"member's dev dependency must be nested under the member node")

	// Local member nodes are local packages, not published artifacts — they must be
	// excluded from the HEAD-check set, while their real dependencies stay in it.
	assert.NotContains(t, uniqueDeps, getDependencyId("packages/vite", "0.0.0"))
	assert.NotContains(t, uniqueDeps, getDependencyId("packages/create-vite", "0.0.0"))
	assert.Contains(t, uniqueDeps, getDependencyId("rolldown", "1.0.3"))
	assert.Contains(t, uniqueDeps, getDependencyId("cross-spawn", "7.0.6"))
}

// TestResolveWorkspaceRoot covers the three cases: a standalone project (no marker),
// the workspace root itself, and a member dir that must resolve up to the root.
func TestResolveWorkspaceRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), []byte("packages:\n  - '.'\n  - 'packages/*'\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"), 0o644))
	member := filepath.Join(root, "packages", "ui")
	require.NoError(t, os.MkdirAll(member, 0o755))

	t.Run("workspace root resolves to itself with '.'", func(t *testing.T) {
		gotRoot, importer := resolveWorkspaceRoot(root)
		assert.Equal(t, root, gotRoot)
		assert.Equal(t, ".", importer)
	})

	t.Run("member resolves up to the root with its relative importer", func(t *testing.T) {
		gotRoot, importer := resolveWorkspaceRoot(member)
		assert.Equal(t, root, gotRoot)
		assert.Equal(t, "packages/ui", importer)
	})

	t.Run("standalone dir with no marker resolves to itself", func(t *testing.T) {
		standalone := t.TempDir()
		gotRoot, importer := resolveWorkspaceRoot(standalone)
		assert.Equal(t, standalone, gotRoot)
		assert.Equal(t, ".", importer)
	})
}

func findNodeByID(node *xrayUtils.GraphNode, id string) *xrayUtils.GraphNode {
	if node == nil {
		return nil
	}
	for _, child := range node.Nodes {
		if child.Id == id {
			return child
		}
	}
	return nil
}

func TestValidateSupportedPnpmVersion(t *testing.T) {
	testCases := []struct {
		name        string
		version     string
		expectError bool
	}{
		{name: "v10 accepted", version: "10.0.0", expectError: false},
		{name: "v10 minor accepted", version: "10.27.0", expectError: false},
		{name: "v9 rejected", version: "9.15.0", expectError: true},
		{name: "v8 rejected", version: "8.15.9", expectError: true},
		{name: "v11 rejected", version: "11.0.0", expectError: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSupportedPnpmVersion(tc.version)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParsePnpmCvsFailedPackages(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []string
	}{
		{
			name: "single package",
			output: " ERR_PNPM_NO_MATCHING_VERSION  No matching version found for lodash@4.99.0\n" +
				"This error happened while installing a direct dependency of /tmp/proj",
			want: []string{"lodash@4.99.0"},
		},
		{
			name: "multiple packages",
			output: "ERR_PNPM_NO_MATCHING_VERSION  No matching version found for lodash@4.99.0\n" +
				"ERR_PNPM_NO_MATCHING_VERSION  No matching version found for express@99.0.0\n",
			want: []string{"lodash@4.99.0", "express@99.0.0"},
		},
		{
			name:   "no matching version lines",
			output: "some unrelated pnpm error output",
			want:   nil,
		},
		{
			name: "deduplication",
			output: "No matching version found for lodash@4.99.0\n" +
				"No matching version found for lodash@4.99.0\n",
			want: []string{"lodash@4.99.0"},
		},
		{
			name:   "scoped package",
			output: "ERR_PNPM_NO_MATCHING_VERSION  No matching version found for @angular/core@18.99.0\n",
			want:   []string{"@angular/core@18.99.0"},
		},
		{
			name: "scoped and unscoped mixed",
			output: "No matching version found for @scope/pkg@1.2.3\n" +
				"No matching version found for express@99.0.0\n",
			want: []string{"@scope/pkg@1.2.3", "express@99.0.0"},
		},
		{
			name:   "trailing text after reference is ignored",
			output: "ERR_PNPM_NO_MATCHING_VERSION  No matching version found for lodash@4.99.99 while fetching it from https://artifactory/api/npm/repo/lodash",
			want:   []string{"lodash@4.99.99"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePnpmCvsFailedPackages(tc.output)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestWrapLockfileRegenError(t *testing.T) {
	const curationPrefix = "Curation audit failed: one or more pinned package versions were unavailable during dependency resolution"
	runErr := errors.New("exit status 1")

	t.Run("ERR_PNPM_NO_MATCHING_VERSION becomes curation message", func(t *testing.T) {
		out := []byte("ERR_PNPM_NO_MATCHING_VERSION  No matching version found for react@18.99.0\n")
		err := wrapLockfileRegenError(out, runErr)
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), curationPrefix),
			"expected curation prefix, got: %s", err.Error())
		assert.Contains(t, err.Error(), "react@18.99.0")
		assert.Contains(t, err.Error(), "Affected package(s):")
	})

	t.Run("multiple blocked packages all listed", func(t *testing.T) {
		out := []byte("ERR_PNPM_NO_MATCHING_VERSION  No matching version found for lodash@4.99.0\n" +
			"ERR_PNPM_NO_MATCHING_VERSION  No matching version found for express@99.0.0\n")
		err := wrapLockfileRegenError(out, runErr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "lodash@4.99.0")
		assert.Contains(t, err.Error(), "express@99.0.0")
	})

	t.Run("scoped blocked package is listed", func(t *testing.T) {
		out := []byte("ERR_PNPM_NO_MATCHING_VERSION  No matching version found for @angular/core@18.99.0\n")
		err := wrapLockfileRegenError(out, runErr)
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), curationPrefix),
			"expected curation prefix, got: %s", err.Error())
		assert.Contains(t, err.Error(), "@angular/core@18.99.0")
		assert.Contains(t, err.Error(), "Affected package(s):")
	})

	t.Run("unrelated failure returns raw output", func(t *testing.T) {
		out := []byte("some unrelated pnpm failure")
		err := wrapLockfileRegenError(out, runErr)
		require.Error(t, err)
		assert.False(t, strings.HasPrefix(err.Error(), curationPrefix),
			"unexpected curation prefix for unrelated error")
		assert.Contains(t, err.Error(), "some unrelated pnpm failure")
	})

	t.Run("ERR_PNPM_NO_MATCHING_VERSION without package line still shows curation header", func(t *testing.T) {
		out := []byte("ERR_PNPM_NO_MATCHING_VERSION  something unusual without the standard line")
		err := wrapLockfileRegenError(out, runErr)
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), curationPrefix),
			"expected curation prefix even without extracted package name")
	})
}
