package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	buildinfo "github.com/jfrog/build-info-go/entities"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNpmDependenciesList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("other", "npm"))
	defer cleanUp()
	dependenciesJson, err := os.ReadFile("dependencies.json")
	assert.NoError(t, err)
	var dependencies []buildinfo.Dependency
	err = json.Unmarshal(dependenciesJson, &dependencies)
	assert.NoError(t, err)
	packageInfo := &bibuildutils.PackageInfo{Name: "npmexmaple", Version: "0.1.0"}
	looseEnvifyJsTokens := []*xrayUtils.GraphNode{{Id: "npm://loose-envify:1.4.0", Nodes: []*xrayUtils.GraphNode{{Id: "npm://js-tokens:4.0.0"}}}}
	expectedTree := &xrayUtils.GraphNode{
		Id: "npm://npmexmaple:0.1.0",
		Nodes: []*xrayUtils.GraphNode{
			{Id: "npm://next-auth:4.22.1",
				Nodes: []*xrayUtils.GraphNode{
					{Id: "npm://react-dom:18.2.0", Nodes: []*xrayUtils.GraphNode{
						{Id: "npm://react:18.2.0", Nodes: looseEnvifyJsTokens},
						{Id: "npm://loose-envify:1.4.0", Nodes: []*xrayUtils.GraphNode{{Id: "npm://js-tokens:4.0.0"}}},
						{Id: "npm://scheduler:0.23.0", Nodes: looseEnvifyJsTokens},
					}},
					{Id: "npm://jose:4.14.4", Nodes: []*xrayUtils.GraphNode{}},
					{Id: "npm://react:18.2.0", Nodes: looseEnvifyJsTokens},
					{Id: "npm://uuid:8.3.2", Nodes: []*xrayUtils.GraphNode{}},
					{Id: "npm://openid-client:5.4.2", Nodes: []*xrayUtils.GraphNode{
						{Id: "npm://jose:4.14.4"},
						{Id: "npm://lru-cache:6.0.0", Nodes: []*xrayUtils.GraphNode{{Id: "npm://yallist:4.0.0"}}},
						{Id: "npm://oidc-token-hash:5.0.3", Nodes: []*xrayUtils.GraphNode{}},
						{Id: "npm://object-hash:2.2.0", Nodes: []*xrayUtils.GraphNode{}},
					}},
					{Id: "npm://next:12.0.10", Nodes: []*xrayUtils.GraphNode{
						{Id: "npm://react-dom:18.2.0", Nodes: []*xrayUtils.GraphNode{
							{Id: "npm://react:18.2.0", Nodes: looseEnvifyJsTokens},
							{Id: "npm://loose-envify:1.4.0", Nodes: []*xrayUtils.GraphNode{{Id: "npm://js-tokens:4.0.0"}}},
							{Id: "npm://scheduler:0.23.0", Nodes: looseEnvifyJsTokens}}},
						{Id: "npm://styled-jsx:5.0.0"},
						{Id: "npm://@next/swc-darwin-arm64:12.0.10"},
						{Id: "npm://react:18.2.0", Nodes: looseEnvifyJsTokens},
						{Id: "npm://@next/env:12.0.10"},
						{Id: "npm://caniuse-lite:1.0.30001486"},
						{Id: "npm://postcss:8.4.5", Nodes: []*xrayUtils.GraphNode{
							{Id: "npm://picocolors:1.0.0"},
							{Id: "npm://source-map-js:1.0.2"},
							{Id: "npm://nanoid:3.3.6"},
						}},
						{Id: "npm://use-subscription:1.5.1", Nodes: []*xrayUtils.GraphNode{
							{Id: "npm://object-assign:4.1.1"},
						}},
					}},
					{Id: "npm://@panva/hkdf:1.1.1"},
					{Id: "npm://preact-render-to-string:5.2.6", Nodes: []*xrayUtils.GraphNode{
						{Id: "npm://pretty-format:3.8.0"},
						{Id: "npm://preact:10.13.2"},
					}},
					{Id: "npm://preact:10.13.2"},
					{Id: "npm://@babel/runtime:7.21.5", Nodes: []*xrayUtils.GraphNode{
						{Id: "npm://regenerator-runtime:0.13.11"},
					}},
					{Id: "npm://cookie:0.5.0"},
					{Id: "npm://oauth:0.9.15"},
				}},
			{Id: "npm://next:12.0.10", Nodes: []*xrayUtils.GraphNode{
				{Id: "npm://react-dom:18.2.0", Nodes: []*xrayUtils.GraphNode{
					{Id: "npm://react:18.2.0"},
					{Id: "npm://scheduler:0.23.0"}}},
				{Id: "npm://styled-jsx:5.0.0"},
				{Id: "npm://@next/swc-darwin-arm64:12.0.10"},
				{Id: "npm://react:18.2.0"},
				{Id: "npm://@next/env:12.0.10"},
				{Id: "npm://caniuse-lite:1.0.30001486"},
				{Id: "npm://postcss:8.4.5", Nodes: []*xrayUtils.GraphNode{
					{Id: "npm://picocolors:1.0.0"},
					{Id: "npm://source-map-js:1.0.2"},
					{Id: "npm://nanoid:3.3.6"},
				}},
				{Id: "npm://use-subscription:1.5.1", Nodes: []*xrayUtils.GraphNode{
					{Id: "npm://object-assign:4.1.1"},
				}},
			}},
		},
	}

	xrayDependenciesTree, uniqueDeps := parseNpmDependenciesList(dependencies, packageInfo)
	equals := tests.CompareTree(expectedTree, xrayDependenciesTree)
	if !equals {
		t.Error("expected:", expectedTree.Nodes, "got:", xrayDependenciesTree.Nodes)
	}
	expectedUniqueDeps := []string{xrayDependenciesTree.Id}
	for _, dep := range dependencies {
		expectedUniqueDeps = append(expectedUniqueDeps, techutils.Npm.GetXrayPackageTypeId()+dep.Id)
	}
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")

}

func TestIgnoreScripts(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "npm", "npm-scripts"))
	defer cleanUp()

	// The package.json file contain a postinstall script running an "exit 1" command.
	// Without the "--ignore-scripts" flag, the test will fail.
	_, _, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{})
	assert.NoError(t, err)
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
			name:                        "not installed | install required - install command",
			testDir:                     filepath.Join("projects", "package-managers", "npm", "npm-no-lock"),
			installCommand:              "npm install",
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "npm", "npm-no-lock"),
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "installed | install not required",
			testDir:                     filepath.Join("projects", "package-managers", "npm", "npm-project"),
			shouldBeInstalled:           true,
			successfulTreeBuiltExpected: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			dirPath, cleanUp := technologies.CreateTestWorkspace(t, test.testDir)
			defer cleanUp()

			exists, err := fileutils.IsFileExists(filepath.Join(dirPath, "package-lock.json"), false)
			assert.NoError(t, err)

			if !test.shouldBeInstalled && exists {
				err = os.Remove(filepath.Join(dirPath, "package-lock.json"))
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

func TestBuildNpmAuthTokenKey(t *testing.T) {
	testCases := []struct {
		name        string
		registryUrl string
		expectedKey string
		expectErr   bool
		errContains string
	}{
		{
			name:        "https artifactory registry with trailing slash",
			registryUrl: "https://myrt.jfrog.io/artifactory/api/npm/my-repo/",
			expectedKey: "//myrt.jfrog.io/artifactory/api/npm/my-repo/:_authToken",
		},
		{
			name:        "http artifactory registry without trailing slash",
			registryUrl: "http://myrt.jfrog.io/artifactory/api/npm/my-repo",
			expectedKey: "//myrt.jfrog.io/artifactory/api/npm/my-repo:_authToken",
		},
		{
			name:        "reverse-proxy registry without /artifactory context root",
			registryUrl: "https://npm.company.com/api/npm/my-repo/",
			expectedKey: "//npm.company.com/api/npm/my-repo/:_authToken",
		},
		{
			name:        "registry with port",
			registryUrl: "https://myrt.jfrog.io:8443/artifactory/api/npm/my-repo/",
			expectedKey: "//myrt.jfrog.io:8443/artifactory/api/npm/my-repo/:_authToken",
		},
		{
			name:        "missing scheme separator",
			registryUrl: "myrt.jfrog.io/artifactory/api/npm/my-repo/",
			expectErr:   true,
			errContains: "expected a scheme-prefixed URL",
		},
		{
			name:        "scheme separator only — no host",
			registryUrl: "https://",
			expectErr:   true,
			errContains: "missing host",
		},
		{
			name:        "empty registry",
			registryUrl: "",
			expectErr:   true,
			errContains: "expected a scheme-prefixed URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authKey, err := BuildNpmAuthTokenKey(tc.registryUrl)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				assert.Empty(t, authKey)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedKey, authKey)
		})
	}
}

// NpmForceLogsMax, when set, must be appended last so an earlier user-supplied flag can't
// shadow it — but it must never be forced just because IsCurationCmd is true, since that
// would override (and prune) a user's own already-nonzero logs-max retention setting.
func TestCreateTreeDepsParam_ForceLogsMaxOnlyWhenExplicitlySet(t *testing.T) {
	tests := []struct {
		name         string
		params       *technologies.BuildInfoBomGeneratorParams
		wantLogsMax  string
		wantArgsTail []string
	}{
		{
			name:        "forced with no other install args",
			params:      &technologies.BuildInfoBomGeneratorParams{IsCurationCmd: true, NpmForceLogsMax: "1"},
			wantLogsMax: "1",
		},
		{
			name: "forced with pre-existing install args",
			params: &technologies.BuildInfoBomGeneratorParams{
				IsCurationCmd:      true,
				NpmForceLogsMax:    "1",
				InstallCommandArgs: []string{"--registry", "https://example.com"},
			},
			wantLogsMax:  "1",
			wantArgsTail: []string{"--registry", "https://example.com"},
		},
		{
			name:        "curation without NpmForceLogsMax does not force logs-max",
			params:      &technologies.BuildInfoBomGeneratorParams{IsCurationCmd: true},
			wantLogsMax: "",
		},
		{
			name:        "non-curation does not force logs-max",
			params:      &technologies.BuildInfoBomGeneratorParams{IsCurationCmd: false},
			wantLogsMax: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createTreeDepsParam(tt.params)
			if tt.wantLogsMax != "" {
				require.GreaterOrEqual(t, len(got.InstallCommandArgs), 2)
				last := got.InstallCommandArgs[len(got.InstallCommandArgs)-2:]
				assert.Equal(t, []string{"--logs-max", tt.wantLogsMax}, last)
				for i, arg := range tt.wantArgsTail {
					assert.Equal(t, arg, got.InstallCommandArgs[i])
				}
			} else {
				assert.NotContains(t, got.InstallCommandArgs, "--logs-max")
			}
		})
	}
}

func TestNpmConfigGetArgsDisableWorkspaces(t *testing.T) {
	assert.Equal(t, []string{"config", "get", "registry", disableWorkspacesFlag}, npmConfigGetArgs("registry", true))
	assert.Equal(t, []string{"config", "get", "registry"}, npmConfigGetArgs("registry", false))
}

func TestNpmConfigGetRegistryFromWorkspacePackage(t *testing.T) {
	npmVersion, npmExecPath, err := bibuildutils.GetNpmVersionAndExecPath(&biutils.NullLog{})
	if err != nil {
		t.Skipf("npm executable is unavailable: %v", err)
	}
	if !npmVersion.AtLeast("7.0.0") {
		t.Skipf("npm workspaces require npm 7 or newer, got %s", npmVersion.GetVersion())
	}

	rootDir := t.TempDir()
	workspaceDir := filepath.Join(rootDir, "containers", "backend")
	assert.NoError(t, os.MkdirAll(workspaceDir, 0o755))
	assert.NoError(t, os.WriteFile(filepath.Join(rootDir, "package.json"), []byte(`{"private":true,"workspaces":["containers/backend"]}`), 0o644))
	assert.NoError(t, os.WriteFile(filepath.Join(workspaceDir, "package.json"), []byte(`{"name":"backend","version":"1.0.0"}`), 0o644))
	// This should work because we are in a workspace package and workspaces are disabled
	registryData, _, err := bibuildutils.RunNpmCmd(npmExecPath, workspaceDir, npmConfigGetArgs("registry", true), &biutils.NullLog{})
	assert.NoError(t, err)
	assert.NotEmpty(t, strings.TrimSpace(string(registryData)))
	// npm 9+ rejects `npm config get` inside workspace packages unless workspaces are disabled.
	// npm 7-8 only emit a warning and still succeed (CI uses Node 16 / npm 8).
	if npmVersion.AtLeast("9.0.0") {
		_, _, err = bibuildutils.RunNpmCmd(npmExecPath, workspaceDir, npmConfigGetArgs("registry", false), &biutils.NullLog{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not support workspaces")
	}
}

func TestParseArtifactoryNpmRegistryUrl(t *testing.T) {
	testCases := []struct {
		name          string
		registryUrl   string
		expectedRtUrl string
		expectedRepo  string
		expectErr     bool
		errContains   string
	}{
		{
			name:          "standard artifactory registry with trailing slash",
			registryUrl:   "https://myrt.jfrog.io/artifactory/api/npm/my-repo/",
			expectedRtUrl: "https://myrt.jfrog.io/artifactory/",
			expectedRepo:  "my-repo",
		},
		{
			name:          "standard artifactory registry without trailing slash",
			registryUrl:   "https://myrt.jfrog.io/artifactory/api/npm/my-repo",
			expectedRtUrl: "https://myrt.jfrog.io/artifactory/",
			expectedRepo:  "my-repo",
		},
		{
			name:          "reverse-proxy registry without /artifactory context root",
			registryUrl:   "https://npm.company.com/api/npm/my-repo/",
			expectedRtUrl: "https://npm.company.com/",
			expectedRepo:  "my-repo",
		},
		{
			name:          "registry with sub-path after repo (e.g. scoped lookup) ignores extra segments",
			registryUrl:   "https://myrt.jfrog.io/artifactory/api/npm/my-repo/-/foo",
			expectedRtUrl: "https://myrt.jfrog.io/artifactory/",
			expectedRepo:  "my-repo",
		},
		{
			name:        "non-artifactory npm registry",
			registryUrl: "https://registry.npmjs.org/",
			expectErr:   true,
			errContains: "does not appear to be an Artifactory npm registry",
		},
		{
			name:        "artifactory api/npm path with empty repository",
			registryUrl: "https://myrt.jfrog.io/artifactory/api/npm/",
			expectErr:   true,
			errContains: "could not extract repository name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rtUrl, repo, err := ParseArtifactoryNpmRegistryUrl(tc.registryUrl)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				assert.Empty(t, rtUrl)
				assert.Empty(t, repo)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRtUrl, rtUrl)
			assert.Equal(t, tc.expectedRepo, repo)
		})
	}
}

// Tests below cover curationprobe.go, moved here from yarn_test.go when the probe was shared with pnpm.

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

// Pins the three-way classification (fixed/range/non-registry) that reconcileDeclaredDirectDepsAgainstTree branches on.
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
			ver, probe, isRange := ClassifyNpmVersionSpec(tc.spec)
			assert.Equal(t, tc.wantVer, ver, "version after stripping operators")
			assert.Equal(t, tc.wantProbe, probe, "probeable flag")
			assert.Equal(t, tc.wantIsRange, isRange, "range/tag flag")
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
		dep := BlockedDirectDep{}
		ParseProbe403Body(nil, &dep)
		assert.Equal(t, "unknown_403", dep.Reason)
	})
	t.Run("non-json body falls back to unknown_403", func(t *testing.T) {
		dep := BlockedDirectDep{}
		ParseProbe403Body([]byte("<html>503 bad gateway</html>"), &dep)
		assert.Equal(t, "unknown_403", dep.Reason)
	})
	t.Run("non-curation 403 falls back to unknown_403", func(t *testing.T) {
		dep := BlockedDirectDep{}
		ParseProbe403Body([]byte(`{"errors":[{"status":403,"message":"some other reason"}]}`), &dep)
		assert.Equal(t, "unknown_403", dep.Reason)
	})
	t.Run("not-being-found marks as not_found", func(t *testing.T) {
		dep := BlockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package mal-pkg:1.0.0 download was blocked by JFrog Packages Curation service due to it not being found in the index"}]}`)
		ParseProbe403Body(body, &dep)
		assert.Equal(t, "not_found", dep.Reason)
	})
	t.Run("policy quartet is parsed", func(t *testing.T) {
		dep := BlockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package mal-pkg:1.0.0 download was blocked by JFrog Packages Curation service due to the following policies violated {mal-policy, Malicious package, Package version is malicious, Remove the malicious package and replace with an alternate}."}]}`)
		ParseProbe403Body(body, &dep)
		assert.Equal(t, "blocked_policy", dep.Reason)
		if assert.Len(t, dep.Policies, 1) {
			assert.Equal(t, "mal-policy", dep.Policies[0].Policy)
			assert.Equal(t, "Malicious package", dep.Policies[0].Condition)
			// makeLegibleProbePolicyDetail rewrites the first ": " into ":\n" — mirror curation's
			// success-path layout. Our fixtures here have no ": " so the strings pass through unchanged.
			assert.Equal(t, "Package version is malicious", dep.Policies[0].Explanation)
			assert.Equal(t, "Remove the malicious package and replace with an alternate", dep.Policies[0].Recommendation)
		}
	})
	t.Run("partial policy info parses what it can", func(t *testing.T) {
		dep := BlockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package foo:1.0.0 download was blocked by JFrog Packages Curation service due to the following policies violated {short-policy, short-condition}."}]}`)
		ParseProbe403Body(body, &dep)
		assert.Equal(t, "blocked_policy", dep.Reason)
		if assert.Len(t, dep.Policies, 1) {
			assert.Equal(t, "short-policy", dep.Policies[0].Policy)
			assert.Equal(t, "short-condition", dep.Policies[0].Condition)
			assert.Empty(t, dep.Policies[0].Explanation)
			assert.Empty(t, dep.Policies[0].Recommendation)
		}
	})
	t.Run("multiple policy quartets are all captured", func(t *testing.T) {
		dep := BlockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package lodash:4.17.23 download was blocked by JFrog Packages Curation service due to the following policies violated {mal-policy, Malicious package, Package version is malicious, Remove the malicious package},{cvss-policy, CVE with CVSS score of 9 or above, Package version contains the following vulnerability(s), Upgrade to the following version(s): 4.18.0}."}]}`)
		ParseProbe403Body(body, &dep)
		assert.Equal(t, "blocked_policy", dep.Reason)
		if assert.Len(t, dep.Policies, 2) {
			assert.Equal(t, "mal-policy", dep.Policies[0].Policy)
			assert.Equal(t, "cvss-policy", dep.Policies[1].Policy)
			assert.Equal(t, "CVE with CVSS score of 9 or above", dep.Policies[1].Condition)
		}
	})
	t.Run("legible-detail normalisation matches curation success-path layout", func(t *testing.T) {
		dep := BlockedDirectDep{}
		body := []byte(`{"errors":[{"status":403,"message":"Package lodash:4.17.23 download was blocked by JFrog Packages Curation service due to the following policies violated {cvss-policy, CVSS score above 9, Vulnerability: CVE-2026-4800 | CVE-2026-9999, Upgrade to: 4.18.0 | 5.0.0}."}]}`)
		ParseProbe403Body(body, &dep)
		if assert.Len(t, dep.Policies, 1) {
			assert.Equal(t, "Vulnerability:\nCVE-2026-4800\nCVE-2026-9999", dep.Policies[0].Explanation)
			assert.Equal(t, "Upgrade to:\n4.18.0\n5.0.0", dep.Policies[0].Recommendation)
		}
	})
	// Real body from production where Policy/Condition/Recommendation parsed as empty for Express@3.0.1.
	t.Run("real-world Express EOL body parses to full quartet", func(t *testing.T) {
		dep := BlockedDirectDep{}
		body := []byte(`{
  "errors" : [ {
    "status" : 403,
    "message" : "package Express:3.0.1 download was blocked by jfrog packages curation service due to the following policies violated {End of Life,Blocking Express as it is EOL,This package version is part of a pre-defined banned list. The following versions are banned:<br/> - 3.0.1,Replace the package with an alternative one or try to find a version of the current one that is not on the banned list.}. For details and alternatives, visit: https://example.jfrogdev.org/ui/catalog/packages/details/npm/Express/3.0.1?showVersions=true"
  } ]
}`)
		ParseProbe403Body(body, &dep)
		assert.Equal(t, "blocked_policy", dep.Reason)
		if assert.Len(t, dep.Policies, 1, "expected exactly one parsed policy from the canonical curation envelope") {
			assert.Equal(t, "End of Life", dep.Policies[0].Policy)
			assert.Equal(t, "Blocking Express as it is EOL", dep.Policies[0].Condition)
			assert.Contains(t, dep.Policies[0].Explanation, "pre-defined banned list",
				"explanation must be populated, not collapsed into the 'response could not be parsed' fallback")
			assert.Contains(t, dep.Policies[0].Recommendation, "Replace the package",
				"recommendation must be populated, not collapsed into the 'response could not be parsed' fallback")
		}
	})
}

func TestBuildBlockedDirectDepsTableRows(t *testing.T) {
	t.Run("empty input yields no rows", func(t *testing.T) {
		assert.Nil(t, buildBlockedDirectDepsTableRows(nil, techutils.Yarn))
		assert.Nil(t, buildBlockedDirectDepsTableRows([]BlockedDirectDep{}, techutils.Yarn))
	})
	t.Run("single dep with one policy renders one row mirroring curation columns", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]BlockedDirectDep{{
			Name: "jfrog-curation-malicious-dummy", DeclaredVersion: "^1.0.0", ProbedVersion: "1.0.0",
			Reason: "blocked_policy",
			Policies: []ProbedPolicy{{Policy: "mal-policy", Condition: "Malicious package",
				Explanation: "Package version is malicious", Recommendation: "Remove the malicious package"}},
		}}, techutils.Yarn)
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
		rows := buildBlockedDirectDepsTableRows([]BlockedDirectDep{{
			Name: "lodash", DeclaredVersion: "^4.17.21", ProbedVersion: "4.17.21",
			Reason: "blocked_policy",
			Policies: []ProbedPolicy{
				{Policy: "mal-policy", Condition: "Malicious package"},
				{Policy: "cvss-policy", Condition: "CVE with CVSS score of 9 or above"},
			},
		}}, techutils.Yarn)
		if assert.Len(t, rows, 2) {
			assert.Equal(t, rows[0].ParentName, rows[1].ParentName, "both rows must share the package columns so auto-merge can collapse them")
			assert.Equal(t, rows[0].ID, rows[1].ID)
			assert.Equal(t, "mal-policy", rows[0].Policy)
			assert.Equal(t, "cvss-policy", rows[1].Policy)
		}
	})
	t.Run("alternating space separator prevents accidental merge across packages", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]BlockedDirectDep{
			{Name: "a", ProbedVersion: "1.0.0", Reason: "blocked_policy", Policies: []ProbedPolicy{{Policy: "p1", Condition: "c1"}}},
			{Name: "b", ProbedVersion: "2.0.0", Reason: "blocked_policy", Policies: []ProbedPolicy{{Policy: "p2", Condition: "c2"}}},
		}, techutils.Yarn)
		if assert.Len(t, rows, 2) {
			// Index 0 (uniqLineSep=" ") and index 1 (uniqLineSep="") must produce IDs that differ
			// even with the same row count, so adjacent packages do not auto-merge by accident.
			assert.Equal(t, "1 ", rows[0].ID)
			assert.Equal(t, "2", rows[1].ID)
		}
	})
	t.Run("not_found and unknown_403 produce explanation-only rows when policies slice is empty", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]BlockedDirectDep{
			{Name: "missing-pkg", ProbedVersion: "1.0.0", Reason: "not_found"},
			{Name: "weird-pkg", ProbedVersion: "2.0.0", Reason: "unknown_403"},
		}, techutils.Yarn)
		if assert.Len(t, rows, 2) {
			assert.Equal(t, "Package not found in curation repository", rows[0].Explanation)
			assert.Equal(t, "Blocked by curation (response could not be parsed)", rows[1].Explanation)
			assert.Empty(t, rows[0].Policy)
			assert.Empty(t, rows[1].Policy)
		}
	})
	t.Run("direct-row: name and version match in both Direct and Blocked columns", func(t *testing.T) {
		rows := buildBlockedDirectDepsTableRows([]BlockedDirectDep{{
			Name: "lodash", DeclaredVersion: "^4.17.21", ProbedVersion: "4.17.21",
			Reason:   "blocked_policy",
			Policies: []ProbedPolicy{{Policy: "cvss-policy", Condition: "CVE with CVSS score of 9 or above"}},
		}}, techutils.Yarn)
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
	merged := MergeDirectDeps(pi)
	assert.Equal(t, "^4.17.21", merged["lodash"], "deps wins over peerDeps")
	assert.Equal(t, "1.0.0", merged["shared"], "deps wins over devDeps")
	assert.Equal(t, "29.0.0", merged["jest"])
	assert.Equal(t, "2.3.0", merged["fsevents"])
	assert.Equal(t, "18.0.0", merged["react"])
}

// Import cycle prevents referencing PackageStatus/Policy directly, so their JSON tags are pinned by value here.
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

	rowType := reflect.TypeOf(BlockedDepJSONRow{})
	assert.Len(t, expectedRowTags, rowType.NumField(),
		"BlockedDepJSONRow field count changed — update expectedRowTags and sync with commands/curation.PackageStatus")
	for i := range rowType.NumField() {
		field := rowType.Field(i)
		expected, ok := expectedRowTags[field.Name]
		assert.True(t, ok, "unexpected field %s in BlockedDepJSONRow — update expectedRowTags and sync with PackageStatus", field.Name)
		if ok {
			assert.Equal(t, expected, field.Tag.Get("json"),
				"BlockedDepJSONRow.%s json tag mismatch — keep in sync with commands/curation.PackageStatus", field.Name)
		}
	}

	policyType := reflect.TypeOf(BlockedDepPolicyJSON{})
	assert.Len(t, expectedPolicyTags, policyType.NumField(),
		"BlockedDepPolicyJSON field count changed — update expectedPolicyTags and sync with commands/curation.Policy")
	for i := range policyType.NumField() {
		field := policyType.Field(i)
		expected, ok := expectedPolicyTags[field.Name]
		assert.True(t, ok, "unexpected field %s in BlockedDepPolicyJSON — update expectedPolicyTags and sync with Policy", field.Name)
		if ok {
			assert.Equal(t, expected, field.Tag.Get("json"),
				"BlockedDepPolicyJSON.%s json tag mismatch — keep in sync with commands/curation.Policy", field.Name)
		}
	}
}
