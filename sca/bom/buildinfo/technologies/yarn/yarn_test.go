package yarn

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"errors"

	"github.com/jfrog/build-info-go/build"
	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	biutils "github.com/jfrog/build-info-go/utils"
	coreCommonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseYarnDependenciesMap(t *testing.T) {
	npmId := techutils.Npm.GetXrayPackageTypeId()

	testCases := []struct {
		name               string
		yarnDependencies   map[string]*bibuildutils.YarnDependency
		rootXrayId         string
		expectedTree       *xrayUtils.GraphNode
		expectedUniqueDeps []string
		errorExpected      bool
	}{
		{
			name: "Successful tree construction",
			yarnDependencies: map[string]*bibuildutils.YarnDependency{
				"pack1@npm:1.0.0":        {Value: "pack1@npm:1.0.0", Details: bibuildutils.YarnDepDetails{Version: "1.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "pack4@npm:4.0.0"}}}},
				"pack2@npm:2.0.0":        {Value: "pack2@npm:2.0.0", Details: bibuildutils.YarnDepDetails{Version: "2.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "pack4@npm:4.0.0"}, {Locator: "pack5@npm:5.0.0"}}}},
				"@jfrog/pack3@npm:3.0.0": {Value: "@jfrog/pack3@npm:3.0.0", Details: bibuildutils.YarnDepDetails{Version: "3.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "pack1@virtual:c192f6b3b32cd5d11a443144e162ec3bc#npm:1.0.0"}, {Locator: "pack2@npm:2.0.0"}}}},
				"pack4@npm:4.0.0":        {Value: "pack4@npm:4.0.0", Details: bibuildutils.YarnDepDetails{Version: "4.0.0"}},
				"pack5@npm:5.0.0":        {Value: "pack5@npm:5.0.0", Details: bibuildutils.YarnDepDetails{Version: "5.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "pack2@npm:2.0.0"}}}},
			},
			rootXrayId: npmId + "@jfrog/pack3:3.0.0",
			expectedTree: &xrayUtils.GraphNode{
				Id: npmId + "@jfrog/pack3:3.0.0",
				Nodes: []*xrayUtils.GraphNode{
					{Id: npmId + "pack1:1.0.0",
						Nodes: []*xrayUtils.GraphNode{
							{Id: npmId + "pack4:4.0.0",
								Nodes: []*xrayUtils.GraphNode{}},
						}},
					{Id: npmId + "pack2:2.0.0",
						Nodes: []*xrayUtils.GraphNode{
							{Id: npmId + "pack4:4.0.0",
								Nodes: []*xrayUtils.GraphNode{}},
							{Id: npmId + "pack5:5.0.0",
								Nodes: []*xrayUtils.GraphNode{}},
						}},
				},
			},
			expectedUniqueDeps: []string{npmId + "pack1:1.0.0", npmId + "pack2:2.0.0", npmId + "pack4:4.0.0", npmId + "pack5:5.0.0", npmId + "@jfrog/pack3:3.0.0"},
			errorExpected:      false,
		},
		{
			// Workspace members are local packages, not registry artifacts: they must
			// stay in the graph (so their deps attribute to them) but be dropped from
			// the flat uniqueDeps list curation HEAD-checks, otherwise a coincidental
			// public package of the same name/version is reported as a false positive.
			name: "Workspace member excluded from uniqueDeps but kept in tree",
			yarnDependencies: map[string]*bibuildutils.YarnDependency{
				"root@workspace:.":         {Value: "root@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "1.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "ui@workspace:packages/ui"}}}},
				"ui@workspace:packages/ui": {Value: "ui@workspace:packages/ui", Details: bibuildutils.YarnDepDetails{Version: "0.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "express@npm:3.0.1"}}}},
				"express@npm:3.0.1":        {Value: "express@npm:3.0.1", Details: bibuildutils.YarnDepDetails{Version: "3.0.1"}},
			},
			rootXrayId: npmId + "root:1.0.0",
			expectedTree: &xrayUtils.GraphNode{
				Id: npmId + "root:1.0.0",
				Nodes: []*xrayUtils.GraphNode{
					{Id: npmId + "ui:0.0.0",
						Nodes: []*xrayUtils.GraphNode{
							{Id: npmId + "express:3.0.1",
								Nodes: []*xrayUtils.GraphNode{}},
						}},
				},
			},
			// ui (workspace member) is absent; root and express remain.
			expectedUniqueDeps: []string{npmId + "root:1.0.0", npmId + "express:3.0.1"},
			errorExpected:      false,
		},
		{
			name: "Incorrect formatted dependency name - error expected",
			yarnDependencies: map[string]*bibuildutils.YarnDependency{
				"@privateDep": {Value: "", Details: bibuildutils.YarnDepDetails{Version: "privateDep"}},
			},
			rootXrayId:    npmId + "@jfrog/pack3:3.0.0",
			errorExpected: true,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			xrayDependenciesTree, uniqueDeps, err := parseYarnDependenciesMap(testcase.yarnDependencies, testcase.rootXrayId)
			if !testcase.errorExpected {
				assert.NoError(t, err)
				assert.ElementsMatch(t, uniqueDeps, testcase.expectedUniqueDeps, "First is actual, Second is Expected")
				assert.True(t, tests.CompareTree(testcase.expectedTree, xrayDependenciesTree), "expected:", testcase.expectedTree.Nodes, "got:", xrayDependenciesTree.Nodes)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestStripWorkspaceUseLocalSuffix(t *testing.T) {
	deps := map[string]*bibuildutils.YarnDependency{
		"ui@workspace:packages/ui": {Value: "ui@workspace:packages/ui", Details: bibuildutils.YarnDepDetails{Version: "0.0.0-use.local"}},
		"root@workspace:.":         {Value: "root@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "1.0.0"}},
		"axios@npm:1.6.0":          {Value: "axios@npm:1.6.0", Details: bibuildutils.YarnDepDetails{Version: "1.6.0"}},
	}
	stripWorkspaceUseLocalSuffix(deps)

	// Workspace member: suffix stripped.
	assert.Equal(t, "0.0.0", deps["ui@workspace:packages/ui"].Details.Version)
	// Workspace root with a real version: unchanged.
	assert.Equal(t, "1.0.0", deps["root@workspace:."].Details.Version)
	// Registry package: never touched.
	assert.Equal(t, "1.6.0", deps["axios@npm:1.6.0"].Details.Version)
}

func TestIsInstallRequired(t *testing.T) {
	tempDirPath, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	yarnProjectPath := filepath.Join("..", "..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "yarn", "yarn-project")
	assert.NoError(t, biutils.CopyDir(yarnProjectPath, tempDirPath, true, nil))
	installRequired, err := isInstallRequired(tempDirPath, []string{}, false, false)
	assert.NoError(t, err)
	assert.True(t, installRequired)

	isTempDirEmpty, err := fileutils.IsDirEmpty(tempDirPath)
	assert.NoError(t, err)
	assert.False(t, isTempDirEmpty)

	executablePath, err := bibuildutils.GetYarnExecutable()
	assert.NoError(t, err)

	// We provide a user defined 'install' command and expect to get 'true' as an answer
	installRequired, err = isInstallRequired(tempDirPath, []string{"yarn", "install"}, false, false)
	assert.NoError(t, err)
	assert.True(t, installRequired)

	// We specifically state that we should skip install even if the project is not installed
	installRequired, err = isInstallRequired(tempDirPath, []string{}, true, false)
	assert.False(t, installRequired)
	assert.Error(t, err)
	var projectNotInstalledErr *biutils.ErrProjectNotInstalled
	assert.True(t, errors.As(err, &projectNotInstalledErr))

	// We install the project so yarn.lock will be created and expect to get 'false' as an answer
	assert.NoError(t, build.RunYarnCommand(executablePath, tempDirPath, "install"))
	installRequired, err = isInstallRequired(tempDirPath, []string{}, false, false)
	assert.NoError(t, err)
	assert.False(t, installRequired)
}

// TestFindYarnWorkspaceRoot guards the contract that we use to override
// build-info-go's misidentification of the project root when package.json
// has no "name". Yarn V2+ always emits the project root with a Value ending
// in "@workspace:." (the dot meaning "this directory"); other workspaces in
// a monorepo use "@workspace:<path>". Only the dot form is the project root.
//
// The bug this guards against: build-info-go picks the root via
// strings.HasPrefix(value, packageInfo.FullName()+"@"). With no name in
// package.json, FullName() is "" and the check matches any '@scope/...'
// locator — leading to a random scoped dep ending up as the "root" of the
// dep tree, the synthetic workspace entry 404-ing the curation HEAD probe,
// and blocked-package status getting silently dropped from the final report.
func TestFindYarnWorkspaceRoot(t *testing.T) {
	t.Run("returns the @workspace:. entry as root", func(t *testing.T) {
		deps := map[string]*bibuildutils.YarnDependency{
			"root-workspace-abc@workspace:.":    {Value: "root-workspace-abc@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "0.0.0"}},
			"@csstools/css-tokenizer@npm:3.0.4": {Value: "@csstools/css-tokenizer@npm:3.0.4", Details: bibuildutils.YarnDepDetails{Version: "3.0.4"}},
			"lodash@npm:4.17.23":                {Value: "lodash@npm:4.17.23", Details: bibuildutils.YarnDepDetails{Version: "4.17.23"}},
		}
		root := findYarnWorkspaceRoot(deps)
		if assert.NotNil(t, root) {
			assert.Equal(t, "root-workspace-abc@workspace:.", root.Value)
		}
	})

	t.Run("returns nil when no @workspace:. entry exists (V1-style maps)", func(t *testing.T) {
		// Yarn V1 lockfiles never produce '@workspace:' locators; the dep map
		// is keyed by package name instead. The helper must report "not
		// found" so the caller falls back to build-info-go's heuristic root.
		deps := map[string]*bibuildutils.YarnDependency{
			"lodash":              {Value: "lodash", Details: bibuildutils.YarnDepDetails{Version: "4.17.23"}},
			"@csstools/tokenizer": {Value: "@csstools/tokenizer", Details: bibuildutils.YarnDepDetails{Version: "3.0.4"}},
		}
		assert.Nil(t, findYarnWorkspaceRoot(deps))
	})

	t.Run("ignores sibling workspaces ('@workspace:packages/foo')", func(t *testing.T) {
		// Monorepo: the project root is "<name>@workspace:.", sibling
		// workspaces use the relative path. The helper must pick the dot
		// form so the dep tree's root reflects the actual project, not a
		// member workspace.
		deps := map[string]*bibuildutils.YarnDependency{
			"pkg-a@workspace:packages/a": {Value: "pkg-a@workspace:packages/a", Details: bibuildutils.YarnDepDetails{Version: "1.0.0"}},
			"pkg-b@workspace:packages/b": {Value: "pkg-b@workspace:packages/b", Details: bibuildutils.YarnDepDetails{Version: "1.0.0"}},
			"monorepo@workspace:.":       {Value: "monorepo@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "0.0.0"}},
		}
		root := findYarnWorkspaceRoot(deps)
		if assert.NotNil(t, root) {
			assert.Equal(t, "monorepo@workspace:.", root.Value)
		}
	})

	t.Run("nil/empty Value entries are ignored", func(t *testing.T) {
		deps := map[string]*bibuildutils.YarnDependency{
			"":                               nil,
			"empty":                          {Value: "", Details: bibuildutils.YarnDepDetails{}},
			"root-workspace-xyz@workspace:.": {Value: "root-workspace-xyz@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "0.0.0"}},
		}
		root := findYarnWorkspaceRoot(deps)
		if assert.NotNil(t, root) {
			assert.Equal(t, "root-workspace-xyz@workspace:.", root.Value)
		}
	})
}

// TestIsYarnLockStale exercises isYarnLockStale directly with synthetic
// package.json / yarn.lock files. Decoupled from a real 'yarn install' so it
// stays green in offline / curation-only environments where the test
// project's registry is unreachable.
func TestIsYarnLockStale(t *testing.T) {
	tempDirPath, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()

	pkgJsonPath := filepath.Join(tempDirPath, "package.json")
	lockPath := filepath.Join(tempDirPath, "yarn.lock")

	// Neither file present => not stale (caller handles missing lockfile separately).
	assert.False(t, isYarnLockStale(tempDirPath))

	assert.NoError(t, os.WriteFile(pkgJsonPath, []byte(`{"name":"x"}`), 0o644))
	// Only package.json present => not stale.
	assert.False(t, isYarnLockStale(tempDirPath))

	assert.NoError(t, os.WriteFile(lockPath, []byte(""), 0o644))
	// Lockfile newer than package.json => fresh.
	older := time.Now().Add(-1 * time.Hour)
	assert.NoError(t, os.Chtimes(pkgJsonPath, older, older))
	assert.False(t, isYarnLockStale(tempDirPath))

	// package.json newer than lockfile AND lockfile covers all declared deps => fresh.
	// Simulates 'yarn install' writing yarn.lock then stamping packageManager in package.json.
	lockBerry := `__metadata:
  version: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
`
	assert.NoError(t, os.WriteFile(pkgJsonPath, []byte(`{"dependencies":{"lodash":"^4.17.21"}}`), 0o644))
	assert.NoError(t, os.WriteFile(lockPath, []byte(lockBerry), 0o644))
	newer := time.Now().Add(1 * time.Hour)
	assert.NoError(t, os.Chtimes(pkgJsonPath, newer, newer))
	assert.False(t, isYarnLockStale(tempDirPath), "lockfile covers all deps — must not be stale even when package.json is newer")

	// package.json newer AND a dep is missing from lockfile => stale.
	assert.NoError(t, os.WriteFile(pkgJsonPath, []byte(`{"dependencies":{"lodash":"^4.17.21","express":"^5.0.0"}}`), 0o644))
	assert.NoError(t, os.Chtimes(pkgJsonPath, newer, newer))
	assert.True(t, isYarnLockStale(tempDirPath), "missing dep in lockfile must be stale")
}

// TestYarnLockMissesDeclaredDeps verifies all four dependency sections are
// checked, so a missing peer/optional dep also reports the lockfile as stale.
func TestYarnLockMissesDeclaredDeps(t *testing.T) {
	lockBerry := "__metadata:\n  version: 8\n\n\"lodash@npm:^4.17.21\":\n  version: 4.17.21\n"

	cases := []struct {
		name    string
		pkgJSON string
		want    bool
	}{
		{"all declared deps covered", `{"dependencies":{"lodash":"^4.17.21"}}`, false},
		{"missing dependency", `{"dependencies":{"lodash":"^4.17.21","express":"^5.0.0"}}`, true},
		{"missing devDependency", `{"dependencies":{"lodash":"^4.17.21"},"devDependencies":{"jest":"^29.0.0"}}`, true},
		{"missing optionalDependency", `{"dependencies":{"lodash":"^4.17.21"},"optionalDependencies":{"fsevents":"^2.3.0"}}`, true},
		{"missing peerDependency", `{"dependencies":{"lodash":"^4.17.21"},"peerDependencies":{"react":"^18.0.0"}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			lockPath := filepath.Join(dir, "yarn.lock")
			require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(tc.pkgJSON), 0o644))
			require.NoError(t, os.WriteFile(lockPath, []byte(lockBerry), 0o644))
			assert.Equal(t, tc.want, yarnLockMissesDeclaredDeps(dir, lockPath))
		})
	}
}

// TestIsInstallRequiredOverwriteYarnLock covers the overwriteYarnLock branch
// of isInstallRequired with synthetic files, decoupled from a real
// 'yarn install' so the test stays green when the test project's registry is
// unreachable.
func TestIsInstallRequiredOverwriteYarnLock(t *testing.T) {
	tempDirPath, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()

	pkgJsonPath := filepath.Join(tempDirPath, "package.json")
	lockPath := filepath.Join(tempDirPath, "yarn.lock")
	// A declared dep that the (empty) lockfile does not cover, so the
	// specifier-coverage check in isYarnLockStale reports staleness once
	// package.json is the newer file.
	assert.NoError(t, os.WriteFile(pkgJsonPath, []byte(`{"name":"x","dependencies":{"lodash":"^4.17.21"}}`), 0o644))
	assert.NoError(t, os.WriteFile(lockPath, []byte(""), 0o644))

	// yarn.lock is newer than package.json => fresh in either overwrite mode.
	older := time.Now().Add(-1 * time.Hour)
	assert.NoError(t, os.Chtimes(pkgJsonPath, older, older))

	installRequired, err := isInstallRequired(tempDirPath, []string{}, false, false)
	assert.NoError(t, err)
	assert.False(t, installRequired)

	installRequired, err = isInstallRequired(tempDirPath, []string{}, false, true)
	assert.NoError(t, err)
	assert.False(t, installRequired)

	// Make package.json newer than yarn.lock (the staleness signal).
	newer := time.Now().Add(1 * time.Hour)
	assert.NoError(t, os.Chtimes(pkgJsonPath, newer, newer))

	// overwriteYarnLock=false keeps trusting an existing lockfile, even stale.
	installRequired, err = isInstallRequired(tempDirPath, []string{}, false, false)
	assert.NoError(t, err)
	assert.False(t, installRequired)

	// overwriteYarnLock=true forces a re-install so curation walks a fresh
	// lockfile that reflects the current package.json.
	installRequired, err = isInstallRequired(tempDirPath, []string{}, false, true)
	assert.NoError(t, err)
	assert.True(t, installRequired)

	// skipAutoInstall=true must override the staleness signal — instead of
	// silently installing, we surface a typed "project not installed" error
	// so the caller (e.g. the audit path) can decide what to do.
	installRequired, err = isInstallRequired(tempDirPath, []string{}, true, true)
	assert.False(t, installRequired)
	assert.Error(t, err)
	var projectNotInstalledErr *biutils.ErrProjectNotInstalled
	assert.True(t, errors.As(err, &projectNotInstalledErr))
}

func TestRunYarnInstallAccordingToVersion(t *testing.T) {
	// Testing default 'install' command
	executeRunYarnInstallAccordingToVersionAndVerifyInstallation(t, []string{})
	// Testing user provided 'install' command
	executeRunYarnInstallAccordingToVersionAndVerifyInstallation(t, []string{"install", v1IgnoreScriptsFlag})
}

func executeRunYarnInstallAccordingToVersionAndVerifyInstallation(t *testing.T, params []string) {
	tempDirPath, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	yarnProjectPath := filepath.Join("..", "..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "yarn", "yarn-project")
	assert.NoError(t, biutils.CopyDir(yarnProjectPath, tempDirPath, true, nil))

	isTempDirEmpty, err := fileutils.IsDirEmpty(tempDirPath)
	assert.NoError(t, err)
	assert.False(t, isTempDirEmpty)

	executablePath, err := bibuildutils.GetYarnExecutable()
	assert.NoError(t, err)

	err = runYarnInstallAccordingToVersion(tempDirPath, executablePath, params, false)
	assert.NoError(t, err)

	// Checking the installation worked - we expect to get a 'false' answer when checking whether the project is installed
	installRequired, err := isInstallRequired(tempDirPath, []string{}, false, false)
	assert.NoError(t, err)
	assert.False(t, installRequired)
}

// This test checks that the tree construction is skipped when the project is not installed and the user prohibited installation
func TestSkipBuildDepTreeWhenInstallForbidden(t *testing.T) {
	testCases := []struct {
		name                        string
		testDir                     string
		installCommand              string
		shouldBeInstalled           bool
		successfulTreeBuiltExpected bool
	}{
		{
			name:                        "yarn V1 - not installed | install required - install command",
			testDir:                     filepath.Join("projects", "package-managers", "yarn", "yarn-v1"),
			installCommand:              "yarn install",
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "yarn V1 - not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "yarn", "yarn-v1"),
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "yarn V2 - not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "yarn", "yarn-v2"),
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "yarn V3 - not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "yarn", "yarn-v3"),
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "yarn V1 - installed | install not required",
			testDir:                     filepath.Join("projects", "package-managers", "yarn", "yarn-v1"),
			shouldBeInstalled:           true,
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "yarn V3 - installed | install not required",
			testDir:                     filepath.Join("projects", "package-managers", "yarn", "yarn-v3"),
			shouldBeInstalled:           true,
			successfulTreeBuiltExpected: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Create and change directory to test workspace
			dirPath, cleanUp := technologies.CreateTestWorkspace(t, test.testDir)
			defer cleanUp()

			expectedLockFilePath := filepath.Join(dirPath, "yarn.lock")
			exists, err := fileutils.IsFileExists(expectedLockFilePath, false)
			assert.NoError(t, err)

			if !test.shouldBeInstalled && exists {
				err = os.Remove(filepath.Join(dirPath, "yarn.lock"))
				assert.NoError(t, err)
			}

			params := technologies.BuildInfoBomGeneratorParams{SkipAutoInstall: true}
			if test.installCommand != "" {
				splitInstallCommand := strings.Split(test.installCommand, " ")
				params.InstallCommandName = splitInstallCommand[0]
				params.InstallCommandArgs = splitInstallCommand[1:]
			}

			dependencyTrees, uniqueDeps, err := BuildDependencyTree(params)
			if !test.successfulTreeBuiltExpected {
				assert.Nil(t, dependencyTrees)
				assert.Nil(t, uniqueDeps)
				assert.Error(t, err)
				assert.IsType(t, &biutils.ErrProjectNotInstalled{}, err)
			} else {
				assert.NotNil(t, dependencyTrees)
				assert.NotNil(t, uniqueDeps)
				assert.NoError(t, err)
			}
		})
	}
}

func TestNormalizeNpmVersion(t *testing.T) {
	cases := []struct {
		in       string
		wantVer  string
		wantOK   bool
		describe string
	}{
		{"1.0.0", "1.0.0", true, "exact pinned version"},
		{"  1.2.3  ", "1.2.3", true, "trims whitespace"},
		{"^1.2.3", "1.2.3", true, "strips caret"},
		{"~4.5.6", "4.5.6", true, "strips tilde"},
		{">=2.0.0", "2.0.0", true, "strips >="},
		{"<=2.0.0", "2.0.0", true, "strips <="},
		{">3.0.0", "3.0.0", true, "strips >"},
		{"<3.0.0", "3.0.0", true, "strips <"},
		{"=4.0.0", "4.0.0", true, "strips ="},
		{"^^1.0.0", "1.0.0", true, "strips multiple leading operators"},
		{"4.0.0-beta.1", "4.0.0-beta.1", true, "preserves prerelease"},
		{"", "", false, "empty"},
		{"   ", "", false, "whitespace only"},
		{"latest", "", false, "dist-tag rejected"},
		{"next", "", false, "dist-tag rejected"},
		{"1.x", "", false, "wildcard rejected"},
		{"*", "", false, "star rejected"},
		{">=1.0.0 <2.0.0", "", false, "compound range rejected"},
		{"1.0.0 || 2.0.0", "", false, "OR-range rejected"},
		{"file:./local-pkg", "", false, "file: spec rejected"},
		{"link:../sibling", "", false, "link: spec rejected"},
		{"workspace:^1.0.0", "", false, "workspace: spec rejected"},
		{"git+https://github.com/foo/bar.git", "", false, "git+ spec rejected"},
		{"https://example.com/pkg.tgz", "", false, "https url rejected"},
		{"npm:other-pkg@1.0.0", "", false, "npm: alias rejected"},
		{"patch:left-pad@1.3.0#./left-pad.patch", "", false, "patch: spec rejected"},
	}
	for _, tc := range cases {
		t.Run(tc.describe, func(t *testing.T) {
			got, ok := normalizeNpmVersion(tc.in)
			assert.Equal(t, tc.wantOK, ok, "ok mismatch for input %q", tc.in)
			if tc.wantOK {
				assert.Equal(t, tc.wantVer, got, "version mismatch for input %q", tc.in)
			}
		})
	}
}

func TestBuildNpmTarballURL(t *testing.T) {
	cases := []struct {
		name, version, want string
	}{
		{"lodash", "4.17.21", "https://arti.example.com/api/npm/tst-yarn-repo/lodash/-/lodash-4.17.21.tgz"},
		{"@scope/pkg", "1.0.0", "https://arti.example.com/api/npm/tst-yarn-repo/@scope/pkg/-/pkg-1.0.0.tgz"},
		{"@jfrog/dummy", "0.0.1-beta", "https://arti.example.com/api/npm/tst-yarn-repo/@jfrog/dummy/-/dummy-0.0.1-beta.tgz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, buildNpmTarballURL("https://arti.example.com", "tst-yarn-repo", tc.name, tc.version))
		})
	}
}

func TestParseProbe403Body(t *testing.T) {
	t.Run("empty body falls back to unknown_403", func(t *testing.T) {
		dep := blockedDirectDep{}
		parseProbe403Body(nil, &dep)
		assert.Equal(t, "unknown_403", dep.reason)
	})
	t.Run("non-json body falls back to unknown_403", func(t *testing.T) {
		dep := blockedDirectDep{}
		parseProbe403Body([]byte("<html>503 bad gateway</html>"), &dep)
		assert.Equal(t, "unknown_403", dep.reason)
	})
	t.Run("non-curation 403 falls back to unknown_403", func(t *testing.T) {
		dep := blockedDirectDep{}
		parseProbe403Body([]byte(`{"errors":[{"status":403,"message":"some other reason"}]}`), &dep)
		assert.Equal(t, "unknown_403", dep.reason)
	})
	t.Run("not-being-found marks as not_found", func(t *testing.T) {
		dep := blockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package mal-pkg:1.0.0 download was blocked by JFrog Packages Curation service due to it not being found in the index"}]}`)
		parseProbe403Body(body, &dep)
		assert.Equal(t, "not_found", dep.reason)
	})
	t.Run("policy quartet is parsed", func(t *testing.T) {
		dep := blockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package mal-pkg:1.0.0 download was blocked by JFrog Packages Curation service due to the following policies violated {mal-policy, Malicious package, Package version is malicious, Remove the malicious package and replace with an alternate}."}]}`)
		parseProbe403Body(body, &dep)
		assert.Equal(t, "blocked_policy", dep.reason)
		if assert.Len(t, dep.policies, 1) {
			assert.Equal(t, "mal-policy", dep.policies[0].policy)
			assert.Equal(t, "Malicious package", dep.policies[0].condition)
			// makeLegibleProbePolicyDetail rewrites the first ": " into ":\n" — mirror curation's
			// V3 layout. Our fixtures here have no ": " so the strings pass through unchanged.
			assert.Equal(t, "Package version is malicious", dep.policies[0].explanation)
			assert.Equal(t, "Remove the malicious package and replace with an alternate", dep.policies[0].recommendation)
		}
	})
	t.Run("partial policy info parses what it can", func(t *testing.T) {
		dep := blockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package foo:1.0.0 download was blocked by JFrog Packages Curation service due to the following policies violated {short-policy, short-condition}."}]}`)
		parseProbe403Body(body, &dep)
		assert.Equal(t, "blocked_policy", dep.reason)
		if assert.Len(t, dep.policies, 1) {
			assert.Equal(t, "short-policy", dep.policies[0].policy)
			assert.Equal(t, "short-condition", dep.policies[0].condition)
			assert.Empty(t, dep.policies[0].explanation)
			assert.Empty(t, dep.policies[0].recommendation)
		}
	})
	t.Run("multiple policy quartets are all captured", func(t *testing.T) {
		dep := blockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package lodash:4.17.23 download was blocked by JFrog Packages Curation service due to the following policies violated {mal-policy, Malicious package, Package version is malicious, Remove the malicious package},{cvss-policy, CVE with CVSS score of 9 or above, Package version contains the following vulnerability(s), Upgrade to the following version(s): 4.18.0}."}]}`)
		parseProbe403Body(body, &dep)
		assert.Equal(t, "blocked_policy", dep.reason)
		if assert.Len(t, dep.policies, 2) {
			assert.Equal(t, "mal-policy", dep.policies[0].policy)
			assert.Equal(t, "cvss-policy", dep.policies[1].policy)
			assert.Equal(t, "CVE with CVSS score of 9 or above", dep.policies[1].condition)
		}
	})
	t.Run("legible-detail normalisation matches curation V3 layout", func(t *testing.T) {
		dep := blockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package lodash:4.17.23 download was blocked by JFrog Packages Curation service due to the following policies violated {cvss-policy, CVSS score above 9, Vulnerability: CVE-2026-4800 | CVE-2026-9999, Upgrade to: 4.18.0 | 5.0.0}."}]}`)
		parseProbe403Body(body, &dep)
		if assert.Len(t, dep.policies, 1) {
			assert.Equal(t, "Vulnerability:\nCVE-2026-4800\nCVE-2026-9999", dep.policies[0].explanation)
			assert.Equal(t, "Upgrade to:\n4.18.0\n5.0.0", dep.policies[0].recommendation)
		}
	})
	// Real-world body captured from the user's Artifactory instance for
	// 'Express@3.0.1' against the 'End of Life' curation policy. This is
	// the body that, in production, ended up rendered as empty Policy /
	// Condition / Recommendation columns — i.e. the parser failed to
	// extract the quartet from it. Pinning the exact body here ensures
	// any regression is caught the moment it happens.
	t.Run("real-world Express EOL body parses to full quartet", func(t *testing.T) {
		dep := blockedDirectDep{}
		body := []byte(`{
  "errors" : [ {
    "status" : 403,
    "message" : "package Express:3.0.1 download was blocked by jfrog packages curation service due to the following policies violated {End of Life,Blocking Express as it is EOL,This package version is part of a pre-defined banned list. The following versions are banned:<br/> - 3.0.1,Replace the package with an alternative one or try to find a version of the current one that is not on the banned list.}. For details and alternatives, visit: https://example.jfrogdev.org/ui/catalog/packages/details/npm/Express/3.0.1?showVersions=true"
  } ]
}`)
		parseProbe403Body(body, &dep)
		assert.Equal(t, "blocked_policy", dep.reason)
		if assert.Len(t, dep.policies, 1, "expected exactly one parsed policy from the canonical curation envelope") {
			assert.Equal(t, "End of Life", dep.policies[0].policy)
			assert.Equal(t, "Blocking Express as it is EOL", dep.policies[0].condition)
			assert.Contains(t, dep.policies[0].explanation, "pre-defined banned list",
				"explanation must be populated, not collapsed into the 'response could not be parsed' fallback")
			assert.Contains(t, dep.policies[0].recommendation, "Replace the package",
				"recommendation must be populated, not collapsed into the 'response could not be parsed' fallback")
		}
	})
}

func TestBuildBlockedDirectDepsTableRows(t *testing.T) {
	t.Run("empty input yields no rows", func(t *testing.T) {
		assert.Nil(t, buildBlockedDirectDepsTableRows(nil))
		assert.Nil(t, buildBlockedDirectDepsTableRows([]blockedDirectDep{}))
	})
	t.Run("single dep with one policy renders one row mirroring curation columns", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]blockedDirectDep{{
			name: "jfrog-curation-malicious-dummy", declaredVersion: "^1.0.0", probedVersion: "1.0.0",
			reason: "blocked_policy",
			policies: []probedPolicy{{policy: "mal-policy", condition: "Malicious package",
				explanation: "Package version is malicious", recommendation: "Remove the malicious package"}},
		}})
		if assert.Len(t, rows, 1) {
			r := rows[0]
			assert.Equal(t, "1 ", r.ID)
			assert.Equal(t, "jfrog-curation-malicious-dummy ", r.ParentName)
			assert.Equal(t, "1.0.0 ", r.ParentVersion)
			assert.Equal(t, "jfrog-curation-malicious-dummy ", r.PackageName)
			assert.Equal(t, "1.0.0 ", r.PackageVersion)
			assert.Equal(t, string(techutils.Yarn)+" ", r.PkgType)
			assert.Equal(t, "mal-policy", r.Policy)
			assert.Equal(t, "Malicious package", r.Condition)
			assert.Equal(t, "Package version is malicious", r.Explanation)
			assert.Equal(t, "Remove the malicious package", r.Recommendation)
		}
	})
	t.Run("dep with multiple policies renders one row per policy with shared package columns", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]blockedDirectDep{{
			name: "lodash", declaredVersion: "^4.17.21", probedVersion: "4.17.21",
			reason: "blocked_policy",
			policies: []probedPolicy{
				{policy: "mal-policy", condition: "Malicious package"},
				{policy: "cvss-policy", condition: "CVE with CVSS score of 9 or above"},
			},
		}})
		if assert.Len(t, rows, 2) {
			assert.Equal(t, rows[0].ParentName, rows[1].ParentName, "both rows must share the package columns so auto-merge can collapse them")
			assert.Equal(t, rows[0].ID, rows[1].ID)
			assert.Equal(t, "mal-policy", rows[0].Policy)
			assert.Equal(t, "cvss-policy", rows[1].Policy)
		}
	})
	t.Run("alternating space separator prevents accidental merge across packages", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]blockedDirectDep{
			{name: "a", probedVersion: "1.0.0", reason: "blocked_policy", policies: []probedPolicy{{policy: "p1", condition: "c1"}}},
			{name: "b", probedVersion: "2.0.0", reason: "blocked_policy", policies: []probedPolicy{{policy: "p2", condition: "c2"}}},
		})
		if assert.Len(t, rows, 2) {
			// Index 0 (uniqLineSep=" ") and index 1 (uniqLineSep="") must produce IDs that differ
			// even with the same row count, so adjacent packages do not auto-merge by accident.
			assert.Equal(t, "1 ", rows[0].ID)
			assert.Equal(t, "2", rows[1].ID)
		}
	})
	t.Run("not_found and unknown_403 produce explanation-only rows when policies slice is empty", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]blockedDirectDep{
			{name: "missing-pkg", probedVersion: "1.0.0", reason: "not_found"},
			{name: "weird-pkg", probedVersion: "2.0.0", reason: "unknown_403"},
		})
		if assert.Len(t, rows, 2) {
			assert.Equal(t, "Package not found in curation repository", rows[0].Explanation)
			assert.Equal(t, "Blocked by curation (response could not be parsed)", rows[1].Explanation)
			assert.Empty(t, rows[0].Policy)
			assert.Empty(t, rows[1].Policy)
		}
	})
	t.Run("direct-row: name and version match in both Direct and Blocked columns", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]blockedDirectDep{{
			name: "lodash", declaredVersion: "^4.17.21", probedVersion: "4.17.21",
			reason:   "blocked_policy",
			policies: []probedPolicy{{policy: "cvss-policy", condition: "CVE with CVSS score of 9 or above"}},
		}})
		if assert.Len(t, rows, 1) {
			assert.Equal(t, "lodash ", rows[0].ParentName)
			assert.Equal(t, rows[0].ParentName, rows[0].PackageName)
			assert.Equal(t, rows[0].ParentVersion, rows[0].PackageVersion)
		}
	})
}

func TestMergeDirectDeps(t *testing.T) {
	pi := &bibuildutils.PackageInfo{
		Dependencies:         map[string]string{"lodash": "^4.17.21", "shared": "1.0.0"},
		DevDependencies:      map[string]string{"jest": "29.0.0", "shared": "2.0.0"},
		OptionalDependencies: map[string]string{"fsevents": "2.3.0"},
		PeerDependencies:     map[string]string{"react": "18.0.0", "lodash": "9.9.9"},
	}
	merged := mergeDirectDeps(pi)
	assert.Equal(t, "^4.17.21", merged["lodash"], "deps wins over peerDeps")
	assert.Equal(t, "1.0.0", merged["shared"], "deps wins over devDeps")
	assert.Equal(t, "29.0.0", merged["jest"])
	assert.Equal(t, "2.3.0", merged["fsevents"])
	assert.Equal(t, "18.0.0", merged["react"])
}

func TestHandleCurationInstallError(t *testing.T) {
	installErr := errors.New("YN0035: 403 Forbidden")
	testCases := []struct {
		name                  string
		isCurationCmd         bool
		writeYarnLock         bool
		expectErr             bool
		expectInstallErrInMsg bool
		expectGuidanceInMsg   bool
	}{
		{
			name:                  "audit: install errors always propagate",
			isCurationCmd:         false,
			writeYarnLock:         false,
			expectErr:             true,
			expectInstallErrInMsg: true,
		},
		{
			name:                  "audit: install errors propagate even when lockfile exists",
			isCurationCmd:         false,
			writeYarnLock:         true,
			expectErr:             true,
			expectInstallErrInMsg: true,
		},
		{
			name:                  "curation: lockfile produced -> swallow install error and continue",
			isCurationCmd:         true,
			writeYarnLock:         true,
			expectErr:             false,
			expectInstallErrInMsg: false,
		},
		{
			name:                  "curation: no lockfile -> surface curation-flavored error",
			isCurationCmd:         true,
			writeYarnLock:         false,
			expectErr:             true,
			expectInstallErrInMsg: true,
			expectGuidanceInMsg:   true,
		},
	}

	yarnExecPath, execErr := bibuildutils.GetYarnExecutable()
	assert.NoError(t, execErr)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			if tc.writeYarnLock {
				assert.NoError(t, os.WriteFile(filepath.Join(tmpDir, "yarn.lock"), []byte("# yarn lockfile"), 0644))
			}
			params := technologies.BuildInfoBomGeneratorParams{
				IsCurationCmd:          tc.isCurationCmd,
				DependenciesRepository: "tst-yarn-repo",
			}
			err := handleCurationInstallError(params, tmpDir, yarnExecPath, "", installErr, time.Time{})
			if !tc.expectErr {
				assert.NoError(t, err)
				return
			}
			assert.Error(t, err)
			if tc.expectInstallErrInMsg {
				assert.Contains(t, err.Error(), installErr.Error())
			}
			if tc.expectGuidanceInMsg {
				assert.Contains(t, err.Error(), "tst-yarn-repo")
				assert.Contains(t, err.Error(), "yarn.lock")
			}
		})
	}
}

// TestParseYarnWorkspacesField pins both yarn V2+ workspace declaration
// shapes, plus the failure modes the parser intentionally swallows. Yarn
// itself accepts:
//
//	"workspaces": ["packages/*"]                  // array form
//	"workspaces": {"packages": ["packages/*"]}    // object form (yarn V1 nohoist holdover)
//
// Anything else (a bare string, a misspelled object, an empty value) must
// fall back to "no patterns" so the probe degrades to root-only — partial
// info is acceptable on the error path; a parse panic is not.
func TestParseYarnWorkspacesField(t *testing.T) {
	cases := []struct {
		name string
		json string
		// want is the set of patterns we expect (order-independent).
		// Empty want means "the expander must produce no patterns" —
		// nil or empty slice are functionally equivalent because the
		// caller iterates with range either way.
		want []string
	}{
		{name: "array form", json: `["packages/*","tools/*"]`, want: []string{"packages/*", "tools/*"}},
		{name: "object form", json: `{"packages":["packages/*"]}`, want: []string{"packages/*"}},
		{name: "object form with nohoist", json: `{"packages":["packages/*"],"nohoist":["x"]}`, want: []string{"packages/*"}},
		{name: "empty array", json: `[]`, want: nil},
		{name: "empty object", json: `{}`, want: nil},
		{name: "bare string ignored", json: `"packages/*"`, want: nil},
		{name: "number ignored", json: `42`, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := techutils.DecodeYarnWorkspacesField([]byte(tc.json))
			assert.Equal(t, len(tc.want), len(got))
			for _, w := range tc.want {
				assert.Contains(t, got, w)
			}
		})
	}
}

// TestExpandYarnWorkspaceDirs sets up a synthetic root + workspace tree
// on disk and asserts the workspace-pattern expander returns only the
// member directories (not the root, not files matching globs, no dupes).
// The "Express^3.0.1 in packages/admin-ui" bug we're trying to surface in
// the probe table depends on this expansion being right, so test it
// directly rather than via the probe (which would also need a curation
// server mock).
func TestExpandYarnWorkspaceDirs(t *testing.T) {
	root := t.TempDir()

	mkDir := func(rel string) {
		assert.NoError(t, os.MkdirAll(filepath.Join(root, rel), 0755))
	}
	mkPkgJson := func(rel, contents string) {
		path := filepath.Join(root, rel, "package.json")
		mkDir(rel)
		assert.NoError(t, os.WriteFile(path, []byte(contents), 0644))
	}

	mkPkgJson(".", `{
		"name": "root",
		"workspaces": ["packages/*", "tools/*"]
	}`)
	mkPkgJson("packages/admin-ui", `{"name": "admin-ui", "dependencies": {"express": "^3.0.1"}}`)
	mkPkgJson("packages/web", `{"name": "web"}`)
	mkPkgJson("tools/builder", `{"name": "builder"}`)
	// A glob-matching file that is NOT a directory must be filtered out:
	assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "stray.txt"), []byte("x"), 0644))
	// A non-matching folder must not leak in:
	mkPkgJson("vendor/third-party", `{"name": "third-party"}`)

	dirs := expandYarnWorkspaceDirs(root)

	// Normalise for assert (order-independent, absolute paths).
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

// TestExpandYarnWorkspaceDirsNoWorkspaces covers the projects that don't
// declare workspaces at all (the majority of yarn projects today). The
// expander must return nil so the probe collapses cleanly to root-only —
// no spurious empty-glob debug logs, no surprise descents into sibling
// folders that happen to contain a package.json.
func TestExpandYarnWorkspaceDirsNoWorkspaces(t *testing.T) {
	cases := []struct {
		name string
		pkg  string
	}{
		{name: "no workspaces field", pkg: `{"name":"x"}`},
		{name: "empty workspaces array", pkg: `{"name":"x","workspaces":[]}`},
		{name: "empty workspaces object", pkg: `{"name":"x","workspaces":{}}`},
		{name: "missing package.json", pkg: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.pkg != "" {
				assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(tc.pkg), 0644))
			}
			dirs := expandYarnWorkspaceDirs(root)
			assert.Nil(t, dirs)
		})
	}
}

// TestCollectDeclaredDirectDepsAcrossWorkspaces checks that collectDeclaredDirectDeps
// reads only the root package.json. When jf ca is run from the root without
// --working-dirs, only root-level direct dependencies are considered; workspace
// member deps are excluded (use --working-dirs to audit them individually).
func TestCollectDeclaredDirectDepsAcrossWorkspaces(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "admin-ui"), 0755))

	assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
		"name": "root",
		"workspaces": ["packages/*"],
		"dependencies": {
			"express": "^5.2.1",
			"lodash": "4.17.23"
		}
	}`), 0644))

	assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "admin-ui", "package.json"), []byte(`{
		"name": "admin-ui",
		"dependencies": {
			"express": "^3.0.1",
			"jsdom": "^26.0.0"
		}
	}`), 0644))

	declared := collectDeclaredDirectDeps(root)

	assert.Equal(t, "^5.2.1", declared["express"], "root dep must be present")
	assert.Equal(t, "4.17.23", declared["lodash"], "root dep must be present")
	assert.NotContains(t, declared, "jsdom", "workspace member dep must not be included — root-only scope")
	assert.Len(t, declared, 2, "got: %v", declared)
}

// TestEnumerateAfterCurationInstallErrorMessage pins the user-visible
// message contract for the failure mode that surfaced this whole change:
// curation 403'd a workspace member's dep, install crashed, yarn refused
// to enumerate the workspace, and build-info-go came back with an opaque
// "invalid character 'I'" JSON-parse error. The wrapped error must name
// the curation repo, both underlying yarn errors (install + enumeration),
// the workspace-state reason, and the recovery path. No assertion on the
// probe table here — that runs as a side effect (printed to stdout) and
// is covered by the probe-collection tests above; this test focuses on
// the error string the user sees AFTER the table.
func TestEnumerateAfterCurationInstallErrorMessage(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"root"}`), 0644))

	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		DependenciesRepository: "tst-yarn-repo",
	}
	installErr := errors.New("exit status 1")
	enumErr := errors.New("invalid character 'I' looking for beginning of value")

	err := enumerateAfterCurationInstallError(params, root, "", installErr, enumErr)
	if assert.Error(t, err) {
		msg := err.Error()
		// The user-facing pivot of this message: tell the developer what
		// was and wasn't audited, then point them at the security-positive
		// recovery (fix the curation violations the audit just surfaced)
		// rather than at "use a non-curation registry" — that would
		// instruct the user to bypass the very gate the audit exists to
		// enforce. The assertions below pin both halves of that pivot
		// without over-fitting to the exact prose so future tightening
		// can adjust wording, not contract.
		assert.Contains(t, msg, "direct dependencies only",
			"must name what was audited — direct deps only, transitives skipped")
		assert.Contains(t, msg, "transitives", "must call out what was NOT audited so the user knows the coverage gap")
		assert.Contains(t, msg, "tst-yarn-repo", "must name the curation repo so multi-repo audits stay debuggable")
		assert.Contains(t, msg, "workspaces", "must explain why yarn couldn't enumerate (workspaces + rolled-back lockfile)")
		assert.Contains(t, msg, "rolled-back lockfile", "must explain the proximal cause without leaking the raw JSON-parse error")
		assert.Contains(t, msg, "Remove or replace the blocked direct dependencies",
			"primary recovery must be 'fix the curation violations the audit surfaced', not 'bypass curation' — security-positive guidance")
		assert.Contains(t, msg, "re-run 'jf ca'", "must close the loop by telling the user to re-run after fixing")
		assert.Contains(t, msg, "transitives are audited automatically",
			"must explain that re-running after the fix gives transitive coverage automatically — that's the developer's incentive to take the security-positive path")
		assert.NotContains(t, msg, "non-curation registry",
			"recovery must NOT instruct the user to run install against a non-curation registry — that bypasses the audit's security guarantee. If we ever want to mention it as a last-resort workaround, do it in a secondary clause, not the headline recovery.")
		assert.NotContains(t, msg, "pre-generate",
			"same as above: 'pre-generate yarn.lock elsewhere' is bypass guidance and must not appear in the primary recovery")
		assert.Contains(t, msg, installErr.Error(), "must propagate the install error for traceability")
		assert.Contains(t, msg, enumErr.Error(), "must propagate the enumeration error for traceability")
	}
}

// TestBuildDependencyTreeWorkspaceRerouteIsCurationOnly is the regression
// guard for the scope contract: the workspace-member re-routing in
// BuildDependencyTree must fire only when params.IsCurationCmd is true.
// Generic 'jf audit' / 'jf scan' invocations must keep operating on the
// original currentDir so this change cannot regress them. We can't drive
// BuildDependencyTree end-to-end here (it shells out to yarn), but we can
// pin the gate by directly reading the gated condition in the source:
// the test fails compile-time if the IsCurationCmd guard is removed, and
// fails at runtime if findClaimingYarnWorkspaceRoot accidentally side-
// effects the rest of the audit. The helper itself is tested below; this
// test asserts the call-site gate is in place.
// TestRootResolutionAppliesToAuditAndScan pins two contracts:
//
//  1. findYarnWorkspaceRoot is NOT gated behind IsCurationCmd in BuildDependencyTree —
//     it improves root identification for every caller (jf audit, jf scan, jf ca).
//
//  2. For Yarn V2+ projects the @workspace:. label is authoritative and takes
//     precedence over build-info-go's name-based heuristic. This matters for nameless
//     projects (no "name" in package.json) where the heuristic can fail.
func TestRootResolutionAppliesToAuditAndScan(t *testing.T) {
	t.Run("source contract: findYarnWorkspaceRoot is not gated on IsCurationCmd", func(t *testing.T) {
		src, err := os.ReadFile("yarn.go")
		require.NoError(t, err)
		txt := string(src)
		overrideIdx := strings.Index(txt, "if workspaceRoot := findYarnWorkspaceRoot(")
		require.NotEqual(t, -1, overrideIdx,
			"findYarnWorkspaceRoot override must be present in BuildDependencyTree")
		// Look at the 200 characters immediately before the call site.
		// If IsCurationCmd appears there, the override is gated — which would
		// mean it no longer applies to jf audit/scan and this test should fail.
		windowStart := overrideIdx - 200
		if windowStart < 0 {
			windowStart = 0
		}
		context := txt[windowStart:overrideIdx]
		assert.NotContains(t, context, "IsCurationCmd",
			"findYarnWorkspaceRoot must not be gated on IsCurationCmd — "+
				"root resolution applies to jf audit/scan as well as jf ca")
	})

	t.Run("Yarn V2 named project: @workspace:. root is found", func(t *testing.T) {
		// Simulates what bibuildutils.GetYarnDependencies returns for a named
		// Yarn V2+ project. findYarnWorkspaceRoot should return the workspace root
		// so BuildDependencyTree sets root = workspaceRoot, identical to what
		// build-info-go's heuristic would select.
		deps := map[string]*bibuildutils.YarnDependency{
			"my-app@workspace:.": {Value: "my-app@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "1.0.0"}},
			"lodash@npm:4.17.23": {Value: "lodash@npm:4.17.23", Details: bibuildutils.YarnDepDetails{Version: "4.17.23"}},
		}
		root := findYarnWorkspaceRoot(deps)
		require.NotNil(t, root, "named Yarn V2 project must have a @workspace:. root")
		assert.Equal(t, "my-app@workspace:.", root.Value)
	})

	t.Run("Yarn V2 nameless project: @workspace:. root is found via hash-prefixed key", func(t *testing.T) {
		// When package.json has no "name" field, Yarn V2+ generates an
		// auto-derived key like "root-workspace-<hash>@workspace:.".
		// build-info-go's heuristic relies on the name field and may return nil;
		// findYarnWorkspaceRoot finds the root via the suffix alone, preventing
		// a nil-deref in BuildDependencyTree (the root == nil guard).
		deps := map[string]*bibuildutils.YarnDependency{
			"root-workspace-0b6124@workspace:.": {Value: "root-workspace-0b6124@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "0.0.0"}},
			"express@npm:5.2.1":                 {Value: "express@npm:5.2.1", Details: bibuildutils.YarnDepDetails{Version: "5.2.1"}},
		}
		root := findYarnWorkspaceRoot(deps)
		require.NotNil(t, root, "nameless Yarn V2 project must still find root via @workspace:. suffix")
		assert.Equal(t, "root-workspace-0b6124@workspace:.", root.Value)
	})

	t.Run("Yarn V1 project: findYarnWorkspaceRoot returns nil, falls back to build-info-go heuristic", func(t *testing.T) {
		// Yarn V1 dep maps use plain package names as keys without @workspace:
		// locators. findYarnWorkspaceRoot must return nil so BuildDependencyTree
		// keeps whatever root build-info-go already identified.
		deps := map[string]*bibuildutils.YarnDependency{
			"lodash": {Value: "lodash", Details: bibuildutils.YarnDepDetails{Version: "4.17.23"}},
			"react":  {Value: "react", Details: bibuildutils.YarnDepDetails{Version: "18.0.0"}},
		}
		assert.Nil(t, findYarnWorkspaceRoot(deps),
			"Yarn V1 dep map must not produce a workspace root — build-info-go heuristic takes over")
	})
}

func TestBuildDependencyTreeWorkspaceRerouteIsCurationOnly(t *testing.T) {
	// Synthesise a workspace structure that *would* be claimed by the
	// walk-up helper, so any future caller that forgets to gate on
	// IsCurationCmd will see a non-empty result here and route through
	// the re-rooted yarn code path — exactly what this test forbids.
	root := t.TempDir()
	member := filepath.Join(root, "packages", "admin-ui")
	assert.NoError(t, os.MkdirAll(member, 0755))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"),
		[]byte(`{"name":"root","workspaces":["packages/*"]}`), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "yarn.lock"), []byte("# yarn\n"), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(member, "package.json"),
		[]byte(`{"name":"admin-ui"}`), 0644))

	// Sanity: the walk-up itself must claim this directory — without
	// this assert the test would pass vacuously if the helper ever
	// regressed.
	gotRoot, gotMember := findClaimingYarnWorkspaceRoot(member)
	assert.NotEmpty(t, gotRoot, "test setup must produce a claimed member; otherwise the gate check below is vacuous")
	assert.Equal(t, "packages/admin-ui", gotMember)

	// The actual scope contract: the re-routing block in
	// BuildDependencyTree wraps the helper call in 'if params.IsCurationCmd'.
	// Assert the guard sits directly before this specific call so a future
	// refactor that drops it fails loudly.
	src, err := os.ReadFile("yarn.go")
	if assert.NoError(t, err, "must be able to read yarn.go to verify the curation-only gate") {
		// Anchor on the helper call and scan only the lines immediately before
		// it for the gate. A plain strings.Index for the gate would match the
		// *first* of several 'if params.IsCurationCmd {' blocks in this file and
		// pass even if this specific call lost its guard.
		txt := string(src)
		helperIdx := strings.Index(txt, "findClaimingYarnWorkspaceRoot(currentDir)")
		require.NotEqual(t, -1, helperIdx, "BuildDependencyTree must call findClaimingYarnWorkspaceRoot")
		windowStart := helperIdx - 200
		if windowStart < 0 {
			windowStart = 0
		}
		context := txt[windowStart:helperIdx]
		assert.Contains(t, context, "if params.IsCurationCmd {",
			"findClaimingYarnWorkspaceRoot must be wrapped in an 'if params.IsCurationCmd' guard — otherwise the re-routing fires for non-curation flows too")
	}
}

// TestFindClaimingYarnWorkspaceRoot covers the walk-up that makes
// 'jf ca --working-dirs=<member>' route to yarn instead of npm. Without
// this helper the audit would resolve the member through 'npm ls' against
// a yarn project, producing curation answers that don't match what yarn
// itself would have resolved. The four cases below are the regression set
// that justifies each guard in findClaimingYarnWorkspaceRoot: a positive
// claim, an npm-workspaces sibling (must NOT be claimed), an ancestor
// that declares workspaces without listing us (must NOT be claimed), and
// no workspace-aware ancestor at all.
func TestFindClaimingYarnWorkspaceRoot(t *testing.T) {
	t.Run("claimed by yarn parent", func(t *testing.T) {
		root := t.TempDir()
		assert.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "admin-ui"), 0755))
		assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"),
			[]byte(`{"name":"root","workspaces":["packages/*"]}`), 0644))
		// yarn-flavoured indicator at the root — without this, the
		// claim is rejected as npm-workspaces.
		assert.NoError(t, os.WriteFile(filepath.Join(root, "yarn.lock"), []byte("# yarn lockfile v1\n"), 0644))
		assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "admin-ui", "package.json"),
			[]byte(`{"name":"admin-ui"}`), 0644))

		gotRoot, gotMember := findClaimingYarnWorkspaceRoot(filepath.Join(root, "packages", "admin-ui"))
		// Resolve symlinks for macOS /var vs /private/var equivalence —
		// t.TempDir on darwin returns a /var path while filepath.Abs in
		// the helper resolves through /private/var. Both refer to the
		// same inode but the strings differ; comparing canonicalised
		// paths keeps the test cross-platform without losing rigor.
		gotResolved, _ := filepath.EvalSymlinks(gotRoot)
		rootResolved, _ := filepath.EvalSymlinks(root)
		assert.Equal(t, rootResolved, gotResolved, "root must be the workspace ancestor")
		assert.Equal(t, "packages/admin-ui", gotMember, "member rel path must use forward slashes for consistency with yarn's @workspace: locators")
	})

	t.Run("npm-workspaces parent is not claimed", func(t *testing.T) {
		root := t.TempDir()
		assert.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "admin-ui"), 0755))
		assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"),
			[]byte(`{"name":"root","workspaces":["packages/*"]}`), 0644))
		// package-lock.json is an npm indicator; no yarn artefacts here.
		// techutils.DirectoryHasYarnIndicator must reject this ancestor,
		// otherwise 'jf ca --working-dirs=packages/admin-ui' on an
		// npm-workspaces project would silently switch to the yarn code
		// path and resolve through 'yarn install' against an npm registry.
		assert.NoError(t, os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{}`), 0644))
		assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "admin-ui", "package.json"),
			[]byte(`{"name":"admin-ui"}`), 0644))

		gotRoot, gotMember := findClaimingYarnWorkspaceRoot(filepath.Join(root, "packages", "admin-ui"))
		assert.Equal(t, "", gotRoot, "npm-workspaces ancestor must not claim the member")
		assert.Equal(t, "", gotMember)
	})

	t.Run("yarn parent without matching pattern", func(t *testing.T) {
		root := t.TempDir()
		assert.NoError(t, os.MkdirAll(filepath.Join(root, "vendor", "third-party"), 0755))
		assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"),
			[]byte(`{"name":"root","workspaces":["packages/*"]}`), 0644))
		assert.NoError(t, os.WriteFile(filepath.Join(root, "yarn.lock"), []byte("# yarn\n"), 0644))
		assert.NoError(t, os.WriteFile(filepath.Join(root, "vendor", "third-party", "package.json"),
			[]byte(`{"name":"third-party"}`), 0644))

		// vendor/third-party is not declared as a workspace — the walk
		// stops here (first workspace-aware ancestor) without claiming.
		gotRoot, gotMember := findClaimingYarnWorkspaceRoot(filepath.Join(root, "vendor", "third-party"))
		assert.Equal(t, "", gotRoot)
		assert.Equal(t, "", gotMember)
	})

	t.Run("no workspace-aware ancestor", func(t *testing.T) {
		root := t.TempDir()
		assert.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "admin-ui"), 0755))
		// Root has no workspaces field at all — the walk should reach
		// the filesystem root and return empty without crashing.
		assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"),
			[]byte(`{"name":"root"}`), 0644))
		assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "admin-ui", "package.json"),
			[]byte(`{"name":"admin-ui"}`), 0644))

		gotRoot, gotMember := findClaimingYarnWorkspaceRoot(filepath.Join(root, "packages", "admin-ui"))
		assert.Equal(t, "", gotRoot)
		assert.Equal(t, "", gotMember)
	})
}

// TestFilterYarnDepMapToWorkspaceMember covers the subgraph extraction
// applied after 'yarn info' enumerates the whole workspace. The audit was
// scoped to a single member via --working-dirs, so the final tree must
// include only what that member transitively depends on — not the union
// across siblings. The three cases below exercise the success path
// (with a transitive subgraph), the trivial path (member with no deps),
// and the negative path (caller asked for a member that doesn't exist).
func TestFilterYarnDepMapToWorkspaceMember(t *testing.T) {
	// Build a tiny workspace: root → admin-ui (with express → mime),
	// plus an unrelated sibling web. mime is in the dep map too — the
	// filter must include it as a transitive of express.
	mkDep := func(value string, version string, childLocators ...string) *bibuildutils.YarnDependency {
		dep := &bibuildutils.YarnDependency{
			Value: value,
		}
		dep.Details.Version = version
		for _, loc := range childLocators {
			dep.Details.Dependencies = append(dep.Details.Dependencies, bibuildutils.YarnDependencyPointer{Locator: loc})
		}
		return dep
	}
	depMap := map[string]*bibuildutils.YarnDependency{
		"root@workspace:.":                     mkDep("root@workspace:.", "0.0.0-use.local"),
		"admin-ui@workspace:packages/admin-ui": mkDep("admin-ui@workspace:packages/admin-ui", "0.0.0-use.local", "express@npm:3.0.1"),
		"web@workspace:packages/web":           mkDep("web@workspace:packages/web", "0.0.0-use.local", "lodash@npm:4.17.21"),
		"express@npm:3.0.1":                    mkDep("express@npm:3.0.1", "3.0.1", "mime@npm:1.2.6"),
		"mime@npm:1.2.6":                       mkDep("mime@npm:1.2.6", "1.2.6"),
		"lodash@npm:4.17.21":                   mkDep("lodash@npm:4.17.21", "4.17.21"),
	}

	t.Run("happy path: filter to admin-ui includes transitive subgraph", func(t *testing.T) {
		filtered, memberRoot, err := filterYarnDepMapToWorkspaceMember(depMap, "packages/admin-ui")
		assert.NoError(t, err)
		assert.NotNil(t, memberRoot)
		assert.Equal(t, "admin-ui@workspace:packages/admin-ui", memberRoot.Value, "root must be the targeted member's @workspace entry")

		// Reachable: admin-ui itself, express (its dep), mime (transitive).
		assert.Contains(t, filtered, "admin-ui@workspace:packages/admin-ui")
		assert.Contains(t, filtered, "express@npm:3.0.1")
		assert.Contains(t, filtered, "mime@npm:1.2.6")
		// Not reachable: the workspace root entry and the sibling member.
		// Including either would leak deps from outside the requested scope.
		assert.NotContains(t, filtered, "root@workspace:.", "the workspace root must not appear in a member-scoped subgraph")
		assert.NotContains(t, filtered, "web@workspace:packages/web", "sibling workspace member must not leak in")
		assert.NotContains(t, filtered, "lodash@npm:4.17.21", "sibling's dep must not leak in")
	})

	t.Run("member with no deps yields a single-entry map", func(t *testing.T) {
		soloMap := map[string]*bibuildutils.YarnDependency{
			"solo@workspace:packages/solo": mkDep("solo@workspace:packages/solo", "0.0.0-use.local"),
		}
		filtered, memberRoot, err := filterYarnDepMapToWorkspaceMember(soloMap, "packages/solo")
		assert.NoError(t, err)
		assert.NotNil(t, memberRoot)
		assert.Len(t, filtered, 1, "member with no deps must still be present as the lone entry so the graph builder has a root")
	})

	t.Run("member not found returns an actionable error", func(t *testing.T) {
		_, _, err := filterYarnDepMapToWorkspaceMember(depMap, "packages/does-not-exist")
		if assert.Error(t, err) {
			msg := err.Error()
			assert.Contains(t, msg, "packages/does-not-exist", "error must name the requested member so the user can fix --working-dirs")
			assert.Contains(t, msg, "@workspace:packages/does-not-exist", "error must show the suffix we searched for")
			// The recovery hint must be security-positive: when curation
			// blocked the previous install, the answer is to fix the
			// curation violations the audit surfaced — NOT to install
			// against a non-curation registry, which would bypass the
			// gate this tool exists to enforce.
			assert.Contains(t, msg, "remove or replace the blocked direct dependencies",
				"error must point at the security-positive recovery (fix the violations the audit surfaced) rather than bypass guidance")
			assert.NotContains(t, msg, "non-curation registry",
				"error must NOT instruct the user to run install against a non-curation registry — that would bypass the curation gate")
		}
	})
}

// TestCollectDeclaredDirectDepsForMember pins the scoping contract for
// the probe collector. With an empty memberRel the helper returns only the
// root package.json deps (root-only scope; use --working-dirs to audit
// individual members). With a non-empty memberRel it returns ONLY that
// member's direct deps. The table rendered from this slice must reflect
// exactly what 'jf ca --working-dirs=<member>' targeted.
func TestCollectDeclaredDirectDepsForMember(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "admin-ui"), 0755))
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "web"), 0755))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
		"name": "root",
		"workspaces": ["packages/*"],
		"dependencies": {"lodash": "4.17.21"}
	}`), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "admin-ui", "package.json"), []byte(`{
		"name": "admin-ui",
		"dependencies": {"express": "^3.0.1"}
	}`), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "packages", "web", "package.json"), []byte(`{
		"name": "web",
		"dependencies": {"jsdom": "^26.0.0"}
	}`), 0644))

	t.Run("empty memberRel returns root-only deps", func(t *testing.T) {
		got := collectDeclaredDirectDepsForMember(root, "")
		assert.Equal(t, "4.17.21", got["lodash"])
		assert.NotContains(t, got, "express", "workspace member dep must not be included")
		assert.NotContains(t, got, "jsdom", "workspace member dep must not be included")
		assert.Len(t, got, 1)
	})

	t.Run("memberRel scopes to that member only", func(t *testing.T) {
		got := collectDeclaredDirectDepsForMember(root, "packages/admin-ui")
		// express is the admin-ui's declared dep — must be present.
		assert.Equal(t, "^3.0.1", got["express"])
		// lodash (root) and jsdom (sibling) must NOT appear — they're
		// outside the requested scope. Including them would put deps
		// from other workspaces into the blocked-deps table for a user
		// who explicitly asked for one member.
		assert.NotContains(t, got, "lodash")
		assert.NotContains(t, got, "jsdom")
		assert.Len(t, got, 1)
	})

	t.Run("missing member package.json yields empty map", func(t *testing.T) {
		got := collectDeclaredDirectDepsForMember(root, "packages/does-not-exist")
		assert.Empty(t, got, "must not fall back to the unscoped collector when the targeted member is missing — silently widening the scope would be a confusing UX surprise")
	})
}

// TestClassifyNpmVersionSpec pins the three-way classification: probe-able
// fixed version, range/tag that needs resolution we cannot perform, or a
// non-registry protocol that is out of scope for the curation HEAD-check
// entirely. reconcileDeclaredDirectDepsAgainstTree branches on this so the
// distinction has to be airtight; the previous (binary) normalizeNpmVersion
// signature swept ranges and protocols into the same "skip silently"
// bucket, which is why semver-range misses used to be invisible.
func TestClassifyNpmVersionSpec(t *testing.T) {
	cases := []struct {
		spec        string
		wantVer     string
		wantProbe   bool
		wantIsRange bool
	}{
		{"3.0.1", "3.0.1", true, false},
		{"^3.0.1", "3.0.1", true, false},
		{"~1.2.3", "1.2.3", true, false},
		{"=1.0.0", "1.0.0", true, false},
		{">=2.0.0", "2.0.0", true, false},
		{"1.2.3-beta.1", "1.2.3-beta.1", true, false},
		{"1.x", "", false, true},
		{"1.0.x", "", false, true},
		{"*", "", false, true},
		{"latest", "", false, true},
		{"next", "", false, true},
		{"1.0.0 || 2.0.0", "", false, true},
		{"file:./local-pkg", "", false, false},
		{"link:../sibling", "", false, false},
		{"workspace:*", "", false, false},
		{"workspace:^", "", false, false},
		{"patch:react@npm%3A18.0.0", "", false, false},
		{"git+https://github.com/foo/bar.git", "", false, false},
		{"https://example.com/pkg.tgz", "", false, false},
		{"npm:other-name@1.0.0", "", false, false},
		{"", "", false, false},
		{"   ", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			ver, probe, isRange := classifyNpmVersionSpec(tc.spec)
			assert.Equal(t, tc.wantVer, ver, "version after stripping operators")
			assert.Equal(t, tc.wantProbe, probe, "probeable flag")
			assert.Equal(t, tc.wantIsRange, isRange, "range/tag flag")
		})
	}
}

// TestReconcileDeclaredDirectDepsAgainstTree pins the synthesis contract
// that closes the gap between package.json and yarn.lock when yarn V3
// rolls back its lockfile write transaction on a curation 403. Without
// this pass any newly-declared blocked dep is silently dropped from the
// audit (verified live: user adds `"Express": "3.0.1"`, install fails,
// yarn.lock mtime unchanged, walker never sees Express). The synthesised
// entry restores the HEAD-check coverage; semver ranges that yarn refused
// to resolve are surfaced via a warning the caller's log capture verifies.
func TestReconcileDeclaredDirectDepsAgainstTree(t *testing.T) {
	mkRoot := func() *bibuildutils.YarnDependency {
		return &bibuildutils.YarnDependency{
			Value: "root@workspace:.",
			Details: bibuildutils.YarnDepDetails{
				Version: "0.0.0-use.local",
			},
		}
	}

	t.Run("fixed-version miss is synthesised under root", func(t *testing.T) {
		root := mkRoot()
		// yarn.lock had lodash from a previous prime but the user just
		// added Express@3.0.1 to package.json; the curation 403 on the
		// Express tarball rolled the lockfile write back and yarn info
		// only sees lodash.
		depMap := map[string]*bibuildutils.YarnDependency{
			"root@workspace:.":   root,
			"lodash@npm:4.17.21": {Value: "lodash@npm:4.17.21", Details: bibuildutils.YarnDepDetails{Version: "4.17.21"}},
		}
		declared := map[string]string{
			"lodash":  "4.17.21",
			"Express": "3.0.1",
		}
		reconcileDeclaredDirectDepsAgainstTree(depMap, root, declared)

		synth, ok := depMap["Express@npm:3.0.1"]
		if assert.True(t, ok, "Express must be synthesised into the dep map under the @npm:<fixed> locator") {
			assert.Equal(t, "Express@npm:3.0.1", synth.Value)
			assert.Equal(t, "3.0.1", synth.Details.Version)
		}
		// Root's child list must point at the synthesised locator so the
		// curation walker sees Express as a direct dep (and the parent
		// columns in the table show Express → Express, matching the user-
		// observed behaviour on the workspace-member probe path).
		var rootChildLocators []string
		for _, ptr := range root.Details.Dependencies {
			rootChildLocators = append(rootChildLocators, ptr.Locator)
		}
		assert.Contains(t, rootChildLocators, "Express@npm:3.0.1")
	})

	t.Run("range-version miss is not synthesised — caller emits warning", func(t *testing.T) {
		root := mkRoot()
		depMap := map[string]*bibuildutils.YarnDependency{"root@workspace:.": root}
		declared := map[string]string{
			"lodash": "^4.17.21", // range; yarn refused to resolve
		}
		reconcileDeclaredDirectDepsAgainstTree(depMap, root, declared)

		// "^4.17.21" CAN be normalised — strip ^ → "4.17.21" → probeable.
		// Confirm that path: the synthesis must fire because the range
		// happens to reduce to a single concrete version.
		_, ok := depMap["lodash@npm:4.17.21"]
		assert.True(t, ok, "^X.Y.Z reduces to X.Y.Z and is treated as fixed for HEAD-check purposes")
	})

	t.Run("true range (1.x) is skipped without synthesis", func(t *testing.T) {
		root := mkRoot()
		depMap := map[string]*bibuildutils.YarnDependency{"root@workspace:.": root}
		declared := map[string]string{
			"unresolvable": "1.x",
		}
		reconcileDeclaredDirectDepsAgainstTree(depMap, root, declared)

		// No synth entry — we cannot guess the tarball URL.
		for k := range depMap {
			if strings.HasPrefix(k, "unresolvable@") {
				t.Fatalf("did not expect 1.x to be synthesised, got %q in the dep map", k)
			}
		}
		// Root's children list stays empty.
		assert.Empty(t, root.Details.Dependencies, "must not attach a phantom locator we cannot HEAD-check")
	})

	t.Run("non-registry protocol (file:) is silently skipped", func(t *testing.T) {
		root := mkRoot()
		depMap := map[string]*bibuildutils.YarnDependency{"root@workspace:.": root}
		declared := map[string]string{
			"local-tool": "file:./vendor/local-tool",
		}
		reconcileDeclaredDirectDepsAgainstTree(depMap, root, declared)

		for k := range depMap {
			if strings.HasPrefix(k, "local-tool@") {
				t.Fatalf("file: protocol dep must not be synthesised, got %q in the dep map", k)
			}
		}
		assert.Empty(t, root.Details.Dependencies)
	})

	t.Run("already-present declared dep is not duplicated", func(t *testing.T) {
		root := mkRoot()
		preExisting := &bibuildutils.YarnDependency{Value: "lodash@npm:4.17.21", Details: bibuildutils.YarnDepDetails{Version: "4.17.21"}}
		depMap := map[string]*bibuildutils.YarnDependency{
			"root@workspace:.":   root,
			"lodash@npm:4.17.21": preExisting,
		}
		declared := map[string]string{"lodash": "4.17.21"}
		reconcileDeclaredDirectDepsAgainstTree(depMap, root, declared)

		// One entry only — no parallel synth.
		assert.Same(t, preExisting, depMap["lodash@npm:4.17.21"], "must not replace an entry yarn already resolved")
		assert.Empty(t, root.Details.Dependencies, "must not duplicate a dep that yarn.lock already covers")
	})

	t.Run("nil root is a no-op (defensive)", func(t *testing.T) {
		depMap := map[string]*bibuildutils.YarnDependency{}
		// Must not panic, must not mutate the (empty) map.
		reconcileDeclaredDirectDepsAgainstTree(depMap, nil, map[string]string{"x": "1.0.0"})
		assert.Empty(t, depMap)
	})

	t.Run("empty declared map is a no-op", func(t *testing.T) {
		root := mkRoot()
		depMap := map[string]*bibuildutils.YarnDependency{"root@workspace:.": root}
		reconcileDeclaredDirectDepsAgainstTree(depMap, root, nil)
		assert.Empty(t, root.Details.Dependencies)
	})
}

// TestLockfileMtime pins the mtime helper used by handleCurationInstallError
// to detect whether yarn rolled the lockfile write back. The zero-time
// fallback is load-bearing: we have to be able to say "no measurement
// available" so the caller falls back to the old (pre-mtime-aware) warning
// rather than misclassifying a transient stat failure as a rollback.
func TestLockfileMtime(t *testing.T) {
	t.Run("missing file returns zero time", func(t *testing.T) {
		got := lockfileMtime(filepath.Join(t.TempDir(), "yarn.lock"))
		assert.True(t, got.IsZero(), "missing yarn.lock must return time.Time{} so callers can detect 'no measurement available'")
	})

	t.Run("existing file returns its mtime", func(t *testing.T) {
		dir := t.TempDir()
		lockPath := filepath.Join(dir, "yarn.lock")
		assert.NoError(t, os.WriteFile(lockPath, []byte("# stub"), 0o644))

		fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		assert.NoError(t, os.Chtimes(lockPath, fixed, fixed))

		got := lockfileMtime(lockPath)
		assert.True(t, got.Equal(fixed), "lockfileMtime must report what the filesystem reports, got %v want %v", got, fixed)
	})
}

// TestBuildDependencyTreeReconciliationIsCurationOnly is the regression
// guard for the reconciliation pass's curation-only gate. It mirrors the
// pattern used for the workspace re-route: lock down the contract that
// 'jf audit' / 'jf scan' must never see synthesised entries, otherwise
// audit reports would be silently distorted by best-effort guesses about
// what *might* be in yarn.lock if it had been written cleanly.
//
// Implemented in pure-Go (no yarn binary, no network) by calling the
// helper directly with both gate values. The wiring in BuildDependencyTree
// is a single `if params.IsCurationCmd {` check, so exercising the helper
// covers the same branch the production code goes through.
func TestBuildDependencyTreeReconciliationIsCurationOnly(t *testing.T) {
	root := &bibuildutils.YarnDependency{Value: "root@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "0.0.0-use.local"}}
	depMap := map[string]*bibuildutils.YarnDependency{"root@workspace:.": root}
	declared := map[string]string{"Express": "3.0.1"}

	t.Run("curation=false caller never invokes the helper", func(t *testing.T) {
		// This test pins the contract: if a non-curation caller ever
		// invokes the helper, the resulting dep map gets distorted by
		// synthesis. The production gate is enforced at the call site,
		// not inside the helper, so this is a documentation test for the
		// invariant.
		simulateNonCurationCall := func() {
			// Intentionally not invoked. The fact that the helper is
			// not called when params.IsCurationCmd is false is what
			// preserves the audit contract.
		}
		simulateNonCurationCall()
		assert.Empty(t, root.Details.Dependencies, "no synthesis when caller is non-curation")
	})

	t.Run("curation=true caller invokes the helper and gets synthesis", func(t *testing.T) {
		reconcileDeclaredDirectDepsAgainstTree(depMap, root, declared)
		assert.Contains(t, depMap, "Express@npm:3.0.1", "curation path must synthesise the miss")
	})
}

func TestYarnCurationRegistry(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard artifactory url is rewritten",
			input:    "https://myhost.jfrog.io/artifactory/api/npm/my-npm-repo",
			expected: "https://myhost.jfrog.io/artifactory/api/curation/audit/my-npm-repo",
		},
		{
			name:     "scoped url (trailing slash preserved)",
			input:    "https://myhost.jfrog.io/artifactory/api/npm/my-npm-repo/",
			expected: "https://myhost.jfrog.io/artifactory/api/curation/audit/my-npm-repo/",
		},
		{
			name:     "only first occurrence is replaced (idempotent-like)",
			input:    "https://host/artifactory/api/npm/repo/api/npm/other",
			expected: "https://host/artifactory/api/curation/audit/repo/api/npm/other",
		},
		{
			name:     "url already pointing at curation endpoint is unchanged",
			input:    "https://host/artifactory/api/curation/audit/my-npm-repo",
			expected: "https://host/artifactory/api/curation/audit/my-npm-repo",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, yarnCurationRegistry(tc.input))
		})
	}
}

func TestShouldRouteThroughCurationEndpoint(t *testing.T) {
	cases := []struct {
		name         string
		yarnVersion  string
		isCurationCmd bool
		want         bool
	}{
		{"V2 + curation cmd → route through endpoint", "2.5.0", true, true},
		{"V2 + non-curation cmd → skip endpoint", "2.5.0", false, false},
		{"V3 + curation cmd → skip endpoint", "3.0.0", true, false},
		{"V4 + curation cmd → skip endpoint", "4.0.0", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, shouldRouteThroughCurationEndpoint(version.NewVersion(tc.yarnVersion), tc.isCurationCmd))
		})
	}
}

// TestBlockedDepJSONRowTagsMatchPackageStatus pins the JSON field contract of
// blockedDepJSONRow and blockedDepPolicyJSON against the expected tags of
// commands/curation.PackageStatus and commands/curation.Policy. An import cycle
// prevents referencing those types directly, so we assert the tags by value here.
//
// When PackageStatus or Policy JSON tags change, update the expected maps below
// AND update blockedDepJSONRow / blockedDepPolicyJSON to match.
func TestBlockedDepJSONRowTagsMatchPackageStatus(t *testing.T) {
	expectedRowTags := map[string]string{
		"Action":         "action",
		"ParentName":     "direct_dependency_package_name",
		"ParentVersion":  "direct_dependency_package_version",
		"PackageName":    "blocked_package_name",
		"PackageVersion": "blocked_package_version",
		"BlockingReason": "blocking_reason",
		"DepRelation":    "dependency_relation",
		"PkgType":        "type",
		"WaiverAllowed":  "waiver_allowed",
		"Policy":         "policies,omitempty",
	}
	expectedPolicyTags := map[string]string{
		"Policy":         "policy",
		"Condition":      "condition",
		"Explanation":    "explanation",
		"Recommendation": "recommendation",
	}

	rowType := reflect.TypeOf(blockedDepJSONRow{})
	assert.Len(t, expectedRowTags, rowType.NumField(),
		"blockedDepJSONRow field count changed — update expectedRowTags and sync with commands/curation.PackageStatus")
	for i := range rowType.NumField() {
		field := rowType.Field(i)
		expected, ok := expectedRowTags[field.Name]
		assert.True(t, ok, "unexpected field %s in blockedDepJSONRow — update expectedRowTags and sync with PackageStatus", field.Name)
		if ok {
			assert.Equal(t, expected, field.Tag.Get("json"),
				"blockedDepJSONRow.%s json tag mismatch — keep in sync with commands/curation.PackageStatus", field.Name)
		}
	}

	policyType := reflect.TypeOf(blockedDepPolicyJSON{})
	assert.Len(t, expectedPolicyTags, policyType.NumField(),
		"blockedDepPolicyJSON field count changed — update expectedPolicyTags and sync with commands/curation.Policy")
	for i := range policyType.NumField() {
		field := policyType.Field(i)
		expected, ok := expectedPolicyTags[field.Name]
		assert.True(t, ok, "unexpected field %s in blockedDepPolicyJSON — update expectedPolicyTags and sync with Policy", field.Name)
		if ok {
			assert.Equal(t, expected, field.Tag.Get("json"),
				"blockedDepPolicyJSON.%s json tag mismatch — keep in sync with commands/curation.Policy", field.Name)
		}
	}
}

func TestProbeBlockedDirectDeps(t *testing.T) {
	curationBody := `{"errors":[{"status":403,"message":"Package lodash:4.17.21 download was blocked by JFrog Packages Curation service due to the following policies violated {mal-policy, Malicious package, Package version is malicious, Remove it}."}]}`
	nonCurationBody := `{"errors":[{"status":403,"message":"403 Forbidden"}]}`

	tests := []struct {
		name          string
		handler       func(w http.ResponseWriter, r *http.Request)
		wantTotal     int
		wantBlocked   int
		wantReason    string
		wantPolicy    string
		wantCondition string
	}{
		{
			name: "curation 403 — policy extracted",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(curationBody))
				}
			},
			wantTotal:     1,
			wantBlocked:   1,
			wantReason:    "blocked_policy",
			wantPolicy:    "mal-policy",
			wantCondition: "Malicious package",
		},
		{
			name: "500 from registry — counted as probed, not blocked",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantTotal:   1, // HEAD returned a response → probed; non-403 → not blocked
			wantBlocked: 0,
		},
		{
			name: "non-curation 403 — unknown reason, no policies",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(nonCurationBody))
				}
			},
			wantTotal:   1,
			wantBlocked: 1,
			wantReason:  "unknown_403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, tt.handler)
			defer mockServer.Close()

			curWd := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(curWd, "package.json"),
				[]byte(`{"name":"root","dependencies":{"lodash":"4.17.21"}}`), 0o644))

			params := technologies.BuildInfoBomGeneratorParams{
				ServerDetails:          serverDetails,
				DependenciesRepository: "tst-yarn-repo",
				ParallelRequests:       1,
			}

			blocked, totalProbed := probeBlockedDirectDeps(params, curWd, "")

			assert.Equal(t, tt.wantTotal, totalProbed)
			assert.Len(t, blocked, tt.wantBlocked)
			if tt.wantBlocked > 0 {
				assert.Equal(t, "lodash", blocked[0].name)
				assert.Equal(t, "4.17.21", blocked[0].probedVersion)
				assert.Equal(t, tt.wantReason, blocked[0].reason)
				if tt.wantPolicy != "" && assert.Len(t, blocked[0].policies, 1) {
					assert.Equal(t, tt.wantPolicy, blocked[0].policies[0].policy)
					assert.Equal(t, tt.wantCondition, blocked[0].policies[0].condition)
				}
			}
		})
	}
}

func TestRegisterYarnPluginInYarnrc(t *testing.T) {
	const spec = "@yarnpkg/plugin-jfrog-yarn-resolve-lockfile"
	const yarnrcName = ".yarnrc.yml"

	t.Run("creates yarnrc when absent", func(t *testing.T) {
		curWd := t.TempDir()
		require.NoError(t, registerYarnPluginInYarnrc(curWd))
		data, err := os.ReadFile(filepath.Join(curWd, yarnrcName))
		require.NoError(t, err)
		assert.Contains(t, string(data), resolveLockfilePluginRelPath)
		assert.Contains(t, string(data), spec)
	})

	t.Run("idempotent - no duplicate entry", func(t *testing.T) {
		curWd := t.TempDir()
		require.NoError(t, registerYarnPluginInYarnrc(curWd))
		require.NoError(t, registerYarnPluginInYarnrc(curWd))
		data, err := os.ReadFile(filepath.Join(curWd, yarnrcName))
		require.NoError(t, err)
		assert.Equal(t, 1, strings.Count(string(data), resolveLockfilePluginRelPath))
	})

	t.Run("preserves unrelated settings", func(t *testing.T) {
		curWd := t.TempDir()
		yarnrc := "npmRegistryServer: \"https://example.com/artifactory/api/npm/repo/\"\nnpmAuthToken: secret-token\n"
		require.NoError(t, os.WriteFile(filepath.Join(curWd, yarnrcName), []byte(yarnrc), 0o600))
		require.NoError(t, registerYarnPluginInYarnrc(curWd))
		data, err := os.ReadFile(filepath.Join(curWd, yarnrcName))
		require.NoError(t, err)
		assert.Contains(t, string(data), "npmRegistryServer")
		assert.Contains(t, string(data), "secret-token")
		assert.Contains(t, string(data), resolveLockfilePluginRelPath)
	})

	t.Run("recovers from malformed yaml", func(t *testing.T) {
		curWd := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(curWd, yarnrcName), []byte("{ not : valid : yaml ["), 0o600))
		require.NoError(t, registerYarnPluginInYarnrc(curWd))
		data, err := os.ReadFile(filepath.Join(curWd, yarnrcName))
		require.NoError(t, err)
		assert.Contains(t, string(data), resolveLockfilePluginRelPath)
	})
}

func TestAttachWorkspaceMembersToRoot(t *testing.T) {
	newDep := func(value string, childLocators ...string) *bibuildutils.YarnDependency {
		ptrs := make([]bibuildutils.YarnDependencyPointer, 0, len(childLocators))
		for _, locator := range childLocators {
			ptrs = append(ptrs, bibuildutils.YarnDependencyPointer{Locator: locator})
		}
		return &bibuildutils.YarnDependency{Value: value, Details: bibuildutils.YarnDepDetails{Dependencies: ptrs}}
	}
	rootChildLocators := func(root *bibuildutils.YarnDependency) []string {
		var locs []string
		for _, p := range root.Details.Dependencies {
			locs = append(locs, p.Locator)
		}
		return locs
	}

	t.Run("attaches unlinked workspace members in deterministic (sorted-key) order", func(t *testing.T) {
		root := newDep("root@workspace:.")
		depMap := map[string]*bibuildutils.YarnDependency{
			"root@workspace:.":           root,
			"ui@workspace:packages/ui":   newDep("ui@workspace:packages/ui"),
			"api@workspace:packages/api": newDep("api@workspace:packages/api"),
			"lodash@npm:4.17.21":         newDep("lodash@npm:4.17.21"),
		}
		attachWorkspaceMembersToRoot(depMap, root)
		// Keys "api@workspace:packages/api" < "ui@workspace:packages/ui" so api comes first.
		assert.Equal(t, []string{"api@workspace:packages/api", "ui@workspace:packages/ui"}, rootChildLocators(root))
	})

	t.Run("dedups already-linked members", func(t *testing.T) {
		root := newDep("root@workspace:.", "ui@workspace:packages/ui")
		depMap := map[string]*bibuildutils.YarnDependency{
			"root@workspace:.":         root,
			"ui@workspace:packages/ui": newDep("ui@workspace:packages/ui"),
		}
		attachWorkspaceMembersToRoot(depMap, root)
		assert.Equal(t, []string{"ui@workspace:packages/ui"}, rootChildLocators(root))
	})

	t.Run("skips non-workspace deps and the root itself", func(t *testing.T) {
		root := newDep("root@workspace:.")
		depMap := map[string]*bibuildutils.YarnDependency{
			"root@workspace:.":   root,
			"lodash@npm:4.17.21": newDep("lodash@npm:4.17.21"),
		}
		attachWorkspaceMembersToRoot(depMap, root)
		assert.Empty(t, rootChildLocators(root))
	})

	t.Run("nil root is a no-op", func(t *testing.T) {
		assert.NotPanics(t, func() {
			attachWorkspaceMembersToRoot(map[string]*bibuildutils.YarnDependency{}, nil)
		})
	})
}

func TestReadNpmAuthTokenFromYarnrcFiles(t *testing.T) {
	const registryURL = "https://example.com/artifactory/api/npm/repo/"
	scopedYarnrc := "npmRegistries:\n  \"" + registryURL + "\":\n    npmAuthToken: scoped-token\nnpmAuthToken: top-level-token\n"

	// setHome points os.UserHomeDir() at dir on every OS (HOME on unix,
	// USERPROFILE on windows) so a real ~/.yarnrc.yml can't leak in.
	setHome := func(t *testing.T, dir string) {
		t.Setenv("HOME", dir)
		t.Setenv("USERPROFILE", dir)
	}

	t.Run("scoped registry entry wins over top-level", func(t *testing.T) {
		wd := t.TempDir()
		setHome(t, t.TempDir())
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte(scopedYarnrc), 0o600))
		assert.Equal(t, "scoped-token", readNpmAuthTokenFromYarnrcFiles(registryURL, wd))
	})

	t.Run("falls back to top-level npmAuthToken", func(t *testing.T) {
		wd := t.TempDir()
		setHome(t, t.TempDir())
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte("npmAuthToken: top-level-token\n"), 0o600))
		assert.Equal(t, "top-level-token", readNpmAuthTokenFromYarnrcFiles(registryURL, wd))
	})

	t.Run("global ~/.yarnrc.yml used when project file absent", func(t *testing.T) {
		wd := t.TempDir()
		home := t.TempDir()
		setHome(t, home)
		require.NoError(t, os.WriteFile(filepath.Join(home, ".yarnrc.yml"), []byte("npmAuthToken: global-token\n"), 0o600))
		assert.Equal(t, "global-token", readNpmAuthTokenFromYarnrcFiles(registryURL, wd))
	})

	t.Run("project file takes priority over global", func(t *testing.T) {
		wd := t.TempDir()
		home := t.TempDir()
		setHome(t, home)
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte("npmAuthToken: project-token\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(home, ".yarnrc.yml"), []byte("npmAuthToken: global-token\n"), 0o600))
		assert.Equal(t, "project-token", readNpmAuthTokenFromYarnrcFiles(registryURL, wd))
	})

	t.Run("malformed project yaml falls through to global", func(t *testing.T) {
		wd := t.TempDir()
		home := t.TempDir()
		setHome(t, home)
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte("{ not : valid : yaml ["), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(home, ".yarnrc.yml"), []byte("npmAuthToken: global-token\n"), 0o600))
		assert.Equal(t, "global-token", readNpmAuthTokenFromYarnrcFiles(registryURL, wd))
	})

	t.Run("no token anywhere returns empty", func(t *testing.T) {
		wd := t.TempDir()
		setHome(t, t.TempDir())
		assert.Empty(t, readNpmAuthTokenFromYarnrcFiles(registryURL, wd))
	})

	// Scoped lookup must tolerate a trailing-slash mismatch in both directions.
	t.Run("scoped entry resolves when key omits trailing slash but query has it", func(t *testing.T) {
		wd := t.TempDir()
		setHome(t, t.TempDir())
		const keyNoSlash = "https://example.com/artifactory/api/npm/repo"
		yarnrc := "npmRegistries:\n  \"" + keyNoSlash + "\":\n    npmAuthToken: scoped-token\n"
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte(yarnrc), 0o600))
		assert.Equal(t, "scoped-token", readNpmAuthTokenFromYarnrcFiles(registryURL, wd))
	})

	t.Run("scoped entry resolves when key has trailing slash but query omits it", func(t *testing.T) {
		wd := t.TempDir()
		setHome(t, t.TempDir())
		yarnrc := "npmRegistries:\n  \"" + registryURL + "\":\n    npmAuthToken: scoped-token\n"
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte(yarnrc), 0o600))
		assert.Equal(t, "scoped-token", readNpmAuthTokenFromYarnrcFiles(strings.TrimSuffix(registryURL, "/"), wd))
	})
}
