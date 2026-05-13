package yarn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"errors"

	"github.com/jfrog/build-info-go/build"
	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
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

func TestIsInstallRequired(t *testing.T) {
	tempDirPath, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	yarnProjectPath := filepath.Join("..", "..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "yarn", "yarn-project")
	assert.NoError(t, biutils.CopyDir(yarnProjectPath, tempDirPath, true, nil))
	installRequired, err := isInstallRequired(tempDirPath, []string{}, false)
	assert.NoError(t, err)
	assert.True(t, installRequired)

	isTempDirEmpty, err := fileutils.IsDirEmpty(tempDirPath)
	assert.NoError(t, err)
	assert.False(t, isTempDirEmpty)

	executablePath, err := bibuildutils.GetYarnExecutable()
	assert.NoError(t, err)

	// We provide a user defined 'install' command and expect to get 'true' as an answer
	installRequired, err = isInstallRequired(tempDirPath, []string{"yarn", "install"}, false)
	assert.NoError(t, err)
	assert.True(t, installRequired)

	// We specifically state that we should skip install even if the project is not installed
	installRequired, err = isInstallRequired(tempDirPath, []string{}, true)
	assert.False(t, installRequired)
	assert.Error(t, err)
	var projectNotInstalledErr *biutils.ErrProjectNotInstalled
	assert.True(t, errors.As(err, &projectNotInstalledErr))

	// We install the project so yarn.lock will be created and expect to get 'false' as an answer
	assert.NoError(t, build.RunYarnCommand(executablePath, tempDirPath, "install"))
	installRequired, err = isInstallRequired(tempDirPath, []string{}, false)
	assert.NoError(t, err)
	assert.False(t, installRequired)
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
	installRequired, err := isInstallRequired(tempDirPath, []string{}, false)
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
			err := handleCurationInstallError(params, tmpDir, yarnExecPath, installErr)
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
