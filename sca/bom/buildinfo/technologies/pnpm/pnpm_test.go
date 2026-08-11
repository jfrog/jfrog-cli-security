package pnpm

import (
	"encoding/json"
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
				"npm://axios:1.19.0",
				"npm://balaganjs:1.0.0",
				"npm://yargs:13.3.0",
				"npm://zen-website:1.0.0",
			},
			expectedTree: &xrayUtils.GraphNode{
				Id: "npm://zen-website:1.0.0",
				Nodes: []*xrayUtils.GraphNode{
					{
						Id:    "npm://balaganjs:1.0.0",
						Nodes: []*xrayUtils.GraphNode{{Id: "npm://axios:1.19.0"}, {Id: "npm://yargs:13.3.0"}},
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

// TestParsePnpmLSContentUsesRealNameForAliases asserts that an aliased dependency is
// identified by its real registry package name rather than the alias. 'pnpm ls --json'
// reports the real name in "from" while keying the map by the alias, and the lockfile
// parser resolves it the same way. Using the alias produces a component ID for a package
// that does not exist, which 404s the curation HEAD-check and makes Xray find no
// vulnerabilities for it.
func TestParsePnpmLSContentUsesRealNameForAliases(t *testing.T) {
	project := pnpmLsProject{
		Name:    "alias-project",
		Version: "1.0.0",
		Dependencies: map[string]pnpmLsDependency{
			"strip-ansi-cjs": {From: "strip-ansi", Version: "6.0.1"},
			"my-babel":       {From: "@babel/code-frame", Version: "7.29.7"},
			"strip-ansi":     {From: "strip-ansi", Version: "7.2.0"},
		},
		DevDependencies: map[string]pnpmLsDependency{
			"wrap-ansi-cjs": {From: "wrap-ansi", Version: "7.0.0"},
		},
	}
	trees, uniqueDeps := parsePnpmLSContent([]pnpmLsProject{project})
	require.Len(t, trees, 1)

	assert.Contains(t, uniqueDeps, getDependencyId("strip-ansi", "6.0.1"))
	assert.Contains(t, uniqueDeps, getDependencyId("@babel/code-frame", "7.29.7"))
	assert.Contains(t, uniqueDeps, getDependencyId("wrap-ansi", "7.0.0"))
	assert.Contains(t, uniqueDeps, getDependencyId("strip-ansi", "7.2.0"))

	// The alias itself must never reach Artifactory or Xray.
	assert.NotContains(t, uniqueDeps, getDependencyId("strip-ansi-cjs", "6.0.1"))
	assert.NotContains(t, uniqueDeps, getDependencyId("my-babel", "7.29.7"))
	assert.NotContains(t, uniqueDeps, getDependencyId("wrap-ansi-cjs", "7.0.0"))

	assert.NotNil(t, findNodeByID(trees[0], getDependencyId("strip-ansi", "6.0.1")),
		"the aliased package must appear in the tree under its real name")
}

// TestParsePnpmLSContentAliasedTransitive asserts the real name is also used for
// transitive dependencies, which are attached through a separate code path.
func TestParsePnpmLSContentAliasedTransitive(t *testing.T) {
	project := pnpmLsProject{
		Name:    "alias-project",
		Version: "1.0.0",
		Dependencies: map[string]pnpmLsDependency{
			"parent": {From: "parent", Version: "1.0.0", Dependencies: map[string]pnpmLsDependency{
				"strip-ansi-cjs": {From: "strip-ansi", Version: "6.0.1"},
			}},
		},
	}
	trees, uniqueDeps := parsePnpmLSContent([]pnpmLsProject{project})
	require.Len(t, trees, 1)

	assert.Contains(t, uniqueDeps, getDependencyId("strip-ansi", "6.0.1"))
	assert.NotContains(t, uniqueDeps, getDependencyId("strip-ansi-cjs", "6.0.1"))

	parent := findNodeByID(trees[0], getDependencyId("parent", "1.0.0"))
	require.NotNil(t, parent)
	assert.NotNil(t, findNodeByID(parent, getDependencyId("strip-ansi", "6.0.1")),
		"the aliased transitive must be nested under its parent under the real name")
}

// TestPnpmLockfileAliasEndToEnd exercises the full curation pipeline for an aliased dependency —
// pnpm-lock.yaml -> parsePnpmLockFile -> parsePnpmLSContent -> uniqueDeps — using the exact
// lockfile shape pnpm 10 writes for "strip-ansi-cjs": "npm:strip-ansi@^6.0.1" (verified against a
// real `pnpm install`). The two stages are covered individually elsewhere (pnpmlock_test.go
// asserts From is set; pnpm_test.go asserts IDs from a hand-built pnpmLsProject), but neither
// proves the two are actually wired together. A regression here — e.g. resolveRefName stops
// setting From, or dependencyName stops reading it — would silently reintroduce the alias bug
// this pipeline exists to fix, without failing either narrower test.
func TestPnpmLockfileAliasEndToEnd(t *testing.T) {
	dir := t.TempDir()
	lock := "lockfileVersion: '9.0'\n" +
		"importers:\n" +
		"  .:\n" +
		"    dependencies:\n" +
		"      strip-ansi:\n" +
		"        specifier: ^7.0.1\n" +
		"        version: 7.2.0\n" +
		"      strip-ansi-cjs:\n" +
		"        specifier: npm:strip-ansi@^6.0.1\n" +
		"        version: strip-ansi@6.0.1\n" +
		"snapshots:\n" +
		"  strip-ansi@7.2.0:\n" +
		"    dependencies:\n" +
		"      ansi-regex: 6.2.2\n" +
		"  strip-ansi@6.0.1:\n" +
		"    dependencies:\n" +
		"      ansi-regex: 5.0.1\n" +
		"  ansi-regex@6.2.2: {}\n" +
		"  ansi-regex@5.0.1: {}\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lock), 0o644))

	projects, err := parsePnpmLockFile(dir, ".")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	trees, uniqueDeps := parsePnpmLSContent(projects)
	require.Len(t, trees, 1)

	assert.Contains(t, uniqueDeps, getDependencyId("strip-ansi", "6.0.1"),
		"the aliased direct dependency must reach uniqueDeps under its real name")
	assert.Contains(t, uniqueDeps, getDependencyId("ansi-regex", "5.0.1"),
		"the aliased dependency's own transitive must reach uniqueDeps")
	assert.NotContains(t, uniqueDeps, getDependencyId("strip-ansi-cjs", "6.0.1"),
		"the alias itself must never reach Artifactory or Xray")

	aliasedNode := findNodeByID(trees[0], getDependencyId("strip-ansi", "6.0.1"))
	require.NotNil(t, aliasedNode, "the aliased package must appear in the tree under its real name")
	assert.NotNil(t, findNodeByID(aliasedNode, getDependencyId("ansi-regex", "5.0.1")),
		"the aliased transitive must be nested under the aliased package's real-name node")
}

// TestPnpmLsJSONAliasEndToEnd exercises the JSON half of the curation pipeline for an aliased
// dependency — a literal `pnpm ls --json` payload -> json.Unmarshal into []pnpmLsProject ->
// parsePnpmLSContent -> uniqueDeps — using the same field shape calculateDependencies unmarshals
// in production (pnpm.go:161-163). TestPnpmLockfileAliasEndToEnd covers the equivalent YAML/
// lockfile boundary via a real yaml.Unmarshal; this is its JSON counterpart. The fix hinges on
// the `json:"from"` struct tag on pnpmLsDependency — a test that builds pnpmLsProject/
// pnpmLsDependency directly in Go, as the narrower alias tests do, would keep passing even if
// that tag were wrong, since it never exercises encoding/json at all.
func TestPnpmLsJSONAliasEndToEnd(t *testing.T) {
	// Field names and nesting match real `pnpm ls --depth Infinity --json --long` output,
	// captured against pnpm 10 for "strip-ansi-cjs": "npm:strip-ansi@^6.0.1". Extra fields
	// pnpm emits (resolved, path, ...) are included to prove they don't interfere with
	// unmarshalling into the narrower pnpmLsProject/pnpmLsDependency shape.
	lsJSON := `[
	  {
	    "name": "alias-json-project",
	    "version": "1.0.0",
	    "dependencies": {
	      "strip-ansi": {
	        "from": "strip-ansi",
	        "version": "7.2.0",
	        "resolved": "https://registry.npmjs.org/strip-ansi/-/strip-ansi-7.2.0.tgz",
	        "dependencies": {
	          "ansi-regex": {"from": "ansi-regex", "version": "6.2.2"}
	        }
	      },
	      "strip-ansi-cjs": {
	        "from": "strip-ansi",
	        "version": "6.0.1",
	        "resolved": "https://registry.npmjs.org/strip-ansi/-/strip-ansi-6.0.1.tgz",
	        "dependencies": {
	          "ansi-regex": {"from": "ansi-regex", "version": "5.0.1"}
	        }
	      }
	    }
	  }
	]`

	var projects []pnpmLsProject
	require.NoError(t, json.Unmarshal([]byte(lsJSON), &projects))
	require.Len(t, projects, 1)
	require.Contains(t, projects[0].Dependencies, "strip-ansi-cjs")
	assert.Equal(t, "strip-ansi", projects[0].Dependencies["strip-ansi-cjs"].From,
		"json:\"from\" must unmarshal into the From field")

	trees, uniqueDeps := parsePnpmLSContent(projects)
	require.Len(t, trees, 1)

	assert.Contains(t, uniqueDeps, getDependencyId("strip-ansi", "6.0.1"),
		"the aliased direct dependency must reach uniqueDeps under its real name")
	assert.Contains(t, uniqueDeps, getDependencyId("ansi-regex", "5.0.1"),
		"the aliased dependency's own transitive must reach uniqueDeps")
	assert.NotContains(t, uniqueDeps, getDependencyId("strip-ansi-cjs", "6.0.1"),
		"the alias itself must never reach Artifactory or Xray")

	aliasedNode := findNodeByID(trees[0], getDependencyId("strip-ansi", "6.0.1"))
	require.NotNil(t, aliasedNode, "the aliased package must appear in the tree under its real name")
	assert.NotNil(t, findNodeByID(aliasedNode, getDependencyId("ansi-regex", "5.0.1")),
		"the aliased transitive must be nested under the aliased package's real-name node")
}

// TestParsePnpmLSContentDuplicateSiblingOnAliasCollision covers two aliases resolving to the
// same real name+version (e.g. a CJS/ESM split like "strip-ansi-cjs"/"strip-ansi-esm" both
// pointing at "npm:strip-ansi@6.0.1"). Both keys survive dependencyName resolution as the same
// dependency ID, so appending both unconditionally produces two identical sibling GraphNodes
// under the same parent — the tree misrepresents the package as installed twice.
func TestParsePnpmLSContentDuplicateSiblingOnAliasCollision(t *testing.T) {
	project := pnpmLsProject{
		Name:    "alias-collision-project",
		Version: "1.0.0",
		Dependencies: map[string]pnpmLsDependency{
			"strip-ansi-cjs": {From: "strip-ansi", Version: "6.0.1"},
			"strip-ansi-esm": {From: "strip-ansi", Version: "6.0.1"},
		},
	}
	trees, uniqueDeps := parsePnpmLSContent([]pnpmLsProject{project})
	require.Len(t, trees, 1)

	realID := getDependencyId("strip-ansi", "6.0.1")
	assert.Contains(t, uniqueDeps, realID)

	var childIDs []string
	for _, c := range trees[0].Nodes {
		childIDs = append(childIDs, c.Id)
	}
	assert.Len(t, childIDs, 1, "expected one deduped sibling, got: %v", childIDs)
}

// TestAppendTransitiveDependenciesDuplicateSiblingOnAliasCollision covers the same collision
// one level down: two aliased transitives of the same parent resolving to the same real
// name+version must not produce duplicate sibling nodes under that parent either.
func TestAppendTransitiveDependenciesDuplicateSiblingOnAliasCollision(t *testing.T) {
	project := pnpmLsProject{
		Name:    "alias-collision-transitive",
		Version: "1.0.0",
		Dependencies: map[string]pnpmLsDependency{
			"parent": {From: "parent", Version: "1.0.0", Dependencies: map[string]pnpmLsDependency{
				"strip-ansi-cjs": {From: "strip-ansi", Version: "6.0.1"},
				"strip-ansi-esm": {From: "strip-ansi", Version: "6.0.1"},
			}},
		},
	}
	trees, _ := parsePnpmLSContent([]pnpmLsProject{project})
	require.Len(t, trees, 1)

	parent := findNodeByID(trees[0], getDependencyId("parent", "1.0.0"))
	require.NotNil(t, parent)
	assert.Len(t, parent.Nodes, 1, "expected one deduped sibling under parent, got: %v", parent.Nodes)
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
		{name: "v11 accepted", version: "11.0.0", expectError: false},
		{name: "v12 accepted (open-ended floor)", version: "12.0.0", expectError: false},
		{name: "v9 rejected", version: "9.15.0", expectError: true},
		{name: "v8 rejected", version: "8.15.9", expectError: true},
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

	t.Run("unrelated failure wraps runErr only, raw output excluded", func(t *testing.T) {
		// Raw output is already log.Debug'd by the caller; embedding it here too would print it twice.
		out := []byte("some unrelated pnpm failure")
		err := wrapLockfileRegenError(out, runErr)
		require.Error(t, err)
		assert.False(t, strings.HasPrefix(err.Error(), curationPrefix),
			"unexpected curation prefix for unrelated error")
		assert.NotContains(t, err.Error(), "some unrelated pnpm failure",
			"raw output must not be embedded in the returned error — it's already in the debug log")
		assert.Contains(t, err.Error(), runErr.Error())
	})

	t.Run("ERR_PNPM_NO_MATCHING_VERSION without package line still shows curation header", func(t *testing.T) {
		out := []byte("ERR_PNPM_NO_MATCHING_VERSION  something unusual without the standard line")
		err := wrapLockfileRegenError(out, runErr)
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), curationPrefix),
			"expected curation prefix even without extracted package name")
	})
}

// Pins the fix: the marker alone isn't enough to conclude a package was named — the probe must still run without it.
func TestCurationNoLockfileErrorProbesWhenNoPackageNamed(t *testing.T) {
	// Repository set and ServerDetails nil keep this test fully offline (no pnpm subprocess, no network).
	params := technologies.BuildInfoBomGeneratorParams{DependenciesRepository: "dummy-repo"}
	workspaceRoot := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(workspaceRoot, "package.json"), []byte(`{"name":"root"}`), 0o644))

	t.Run("marker without affected-packages list still runs the probe", func(t *testing.T) {
		resolveErr := errors.New(formatPnpmCvsBlockedMessage(nil))
		err := curationNoLockfileError(params, workspaceRoot, ".", resolveErr)
		require.Error(t, err)
		assert.NotEqual(t, resolveErr.Error(), err.Error(),
			"must not short-circuit to the generic CVS message when no package was actually named — the probe should run instead")
		assert.Contains(t, err.Error(), "Probing the declared direct dependencies did not surface the blocked package")
	})

	t.Run("marker with affected-packages list still short-circuits", func(t *testing.T) {
		resolveErr := errors.New(formatPnpmCvsBlockedMessage([]string{"lodash@4.99.0"}))
		err := curationNoLockfileError(params, workspaceRoot, ".", resolveErr)
		require.Error(t, err)
		assert.Equal(t, resolveErr.Error(), err.Error(),
			"a genuine CVS-blocked-version message must still short-circuit — the probe would only add noise")
	})
}

func TestExpandPnpmWorkspaceDirs(t *testing.T) {
	root := t.TempDir()

	mkDir := func(rel string) {
		assert.NoError(t, os.MkdirAll(filepath.Join(root, rel), 0755))
	}
	mkPkgJson := func(rel, contents string) {
		path := filepath.Join(root, rel, "package.json")
		mkDir(rel)
		assert.NoError(t, os.WriteFile(path, []byte(contents), 0644))
	}

	assert.NoError(t, os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"),
		[]byte("packages:\n  - \"packages/*\"\n  - \"tools/*\"\n"), 0644))
	mkPkgJson("packages/admin-ui", `{"name": "admin-ui", "dependencies": {"express": "^3.0.1"}}`)
	mkPkgJson("packages/web", `{"name": "web"}`)
	mkPkgJson("tools/builder", `{"name": "builder"}`)
	// A glob-matching file that is NOT a directory must be filtered out:
	assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "stray.txt"), []byte("x"), 0644))
	// A non-matching folder must not leak in:
	mkPkgJson("vendor/third-party", `{"name": "third-party"}`)

	dirs := expandPnpmWorkspaceDirs(root)

	got := map[string]bool{}
	for _, d := range dirs {
		got[d] = true
	}
	assert.True(t, got[filepath.Join(root, "packages", "admin-ui")], "packages/admin-ui must be expanded")
	assert.True(t, got[filepath.Join(root, "packages", "web")], "packages/web must be expanded")
	assert.True(t, got[filepath.Join(root, "tools", "builder")], "tools/builder must be expanded")
	assert.False(t, got[filepath.Join(root, "vendor", "third-party")], "non-matching folder must not be expanded")
	assert.False(t, got[filepath.Join(root, "packages", "stray.txt")], "non-directory glob match must be filtered out")
	assert.Equal(t, 3, len(dirs), "expected exactly 3 workspace dirs, got: %v", dirs)
}

func TestExpandPnpmWorkspaceDirsNoWorkspaces(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{name: "missing pnpm-workspace.yaml", yaml: ""},
		{name: "empty packages list", yaml: "packages: []\n"},
		{name: "missing packages key", yaml: "foo: bar\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.yaml != "" {
				assert.NoError(t, os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), []byte(tc.yaml), 0644))
			}
			dirs := expandPnpmWorkspaceDirs(root)
			assert.Nil(t, dirs)
		})
	}
}

func TestCollectDeclaredPnpmDirectDepsAcrossWorkspaces(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "admin-ui"), 0755))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"),
		[]byte("packages:\n  - \"packages/*\"\n"), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
		"name": "root",
		"dependencies": {"express": "^5.2.1", "lodash": "4.17.23"}
	}`), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "admin-ui", "package.json"), []byte(`{
		"name": "admin-ui",
		"dependencies": {"express": "^3.0.1"},
		"devDependencies": {"jsdom": "^26.0.0"}
	}`), 0644))

	declared := collectDeclaredPnpmDirectDeps(root, "")

	assert.Equal(t, "^3.0.1", declared["express"], "workspace member's spec wins over root's for the same package name")
	assert.Equal(t, "4.17.23", declared["lodash"], "root-only dep must be present")
	assert.Equal(t, "^26.0.0", declared["jsdom"], "workspace member's dep must be merged into the root scope")
	assert.Len(t, declared, 3, "got: %v", declared)
}

func TestCollectDeclaredPnpmDirectDepsForMember(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "admin-ui"), 0755))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"),
		[]byte("packages:\n  - \"packages/*\"\n"), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
		"name": "root",
		"dependencies": {"lodash": "4.17.23"}
	}`), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "admin-ui", "package.json"), []byte(`{
		"name": "admin-ui",
		"dependencies": {"express": "^3.0.1"}
	}`), 0644))

	t.Run("empty memberRel merges deps across the whole workspace", func(t *testing.T) {
		declared := collectDeclaredPnpmDirectDeps(root, "")
		assert.Equal(t, "4.17.23", declared["lodash"])
		assert.Equal(t, "^3.0.1", declared["express"])
	})

	t.Run("memberRel scopes to that member only", func(t *testing.T) {
		declared := collectDeclaredPnpmDirectDeps(root, filepath.Join("packages", "admin-ui"))
		assert.Equal(t, "^3.0.1", declared["express"])
		_, hasRootDep := declared["lodash"]
		assert.False(t, hasRootDep, "root-only dep must not leak into a member-scoped result")
	})

	t.Run("missing member package.json yields empty map", func(t *testing.T) {
		declared := collectDeclaredPnpmDirectDeps(root, filepath.Join("packages", "does-not-exist"))
		assert.Empty(t, declared)
	})
}
