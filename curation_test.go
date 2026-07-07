package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/commands/curation"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"

	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	commonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
)

func TestCurationAudit(t *testing.T) {
	integration.InitCurationTest(t)
	tempDirPath, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "npm"))
	defer cleanUp()

	expectedRequest := map[string]bool{
		"/api/npm/npms/json/-/json-9.0.6.tgz": false,
		"/api/npm/npms/xml/-/xml-1.0.1.tgz":   false,
	}
	requestToFail := map[string]bool{
		"/api/npm/npms/xml/-/xml-1.0.1.tgz": false,
	}
	serverMock, config := curationServer(t, expectedRequest, requestToFail)

	cleanUpJfrogHome, err := coreTests.SetJfrogHome()
	assert.NoError(t, err)
	defer cleanUpJfrogHome()

	config.User = "admin"
	config.Password = "password"
	config.ServerId = "test"
	configCmd := commonCommands.NewConfigCommand(commonCommands.AddOrEdit, config.ServerId).SetDetails(config).SetUseBasicAuthOnly(true).SetInteractive(false)
	assert.NoError(t, configCmd.Run())

	defer serverMock.Close()
	// Create build config
	assert.NoError(t, commonCommands.CreateBuildConfigWithOptions(false, project.Npm,
		commonCommands.WithResolverServerId(config.ServerId),
		commonCommands.WithResolverRepo("npms"),
		commonCommands.WithDeployerServerId(config.ServerId),
		commonCommands.WithDeployerRepo("npm-local"),
	))

	localXrayCli := securityTests.PlatformCli.WithoutCredentials()
	workingDirsFlag := fmt.Sprintf("--working-dirs=%s", filepath.Join(tempDirPath, "npm"))
	output := localXrayCli.RunCliCmdWithOutput(t, "curation-audit", "--format="+string(format.Json), workingDirsFlag)
	expectedResp := getCurationExpectedResponse(config)
	var got []curation.PackageStatus
	bracketIndex := strings.Index(output, "[")
	require.Less(t, 0, bracketIndex, "Unexpected Curation output with missing '['")
	err = json.Unmarshal([]byte(output[bracketIndex:]), &got)
	assert.NoError(t, err)
	assert.Equal(t, expectedResp, got)
	for k, v := range expectedRequest {
		assert.Truef(t, v, "didn't receive expected GET request for package url %s", k)
	}
}

// TestYarnCurationAudit exercises 'jf curation-audit' end-to-end for Yarn Berry projects
// (V3 and V4), driving the real resolution-only plugin path: with no lockfile present,
// 'jf ca' runs 'yarn jfrog-yarn-resolve-lockfile' to build a complete yarn.lock from the
// mock registry's npm packuments WITHOUT downloading tarballs, then the curation
// HEAD-walker probes the same /api/npm/<repo>/<pkg>/-/<pkg>-<ver>.tgz URLs as npm and
// reports the blocked package with PkgType "yarn" (curation rejects Yarn V1).
//
// V3 and V4 differ ONLY in how the resolution registry is read; everything else (the
// resolve-only plugin and the HEAD-walker) is identical:
//   - V3: from yarn.yaml written by the build config ('jf yarn-config' style).
//   - V4: natively from .yarnrc.yml (npmRegistryServer), with no 'jf yarn-config'.
func TestYarnCurationAudit(t *testing.T) {
	integration.InitCurationTest(t)
	testCases := []struct {
		name    string
		project string
		// configureRegistry wires the resolution registry the way each yarn version reads it.
		configureRegistry func(t *testing.T, tempDirPath string, config *config.ServerDetails)
	}{
		{
			name:    "Yarn V3 (registry from yarn.yaml)",
			project: "yarn-v3",
			configureRegistry: func(t *testing.T, tempDirPath string, config *config.ServerDetails) {
				// npm and yarn share the Artifactory npm API; resolve via the build config.
				assert.NoError(t, commonCommands.CreateBuildConfigWithOptions(false, project.Yarn,
					commonCommands.WithResolverServerId(config.ServerId),
					commonCommands.WithResolverRepo("npms"),
					commonCommands.WithDeployerServerId(config.ServerId),
					commonCommands.WithDeployerRepo("npm-local"),
				))
				// jf ca injects this http mock registry into the temp .yarnrc.yml; Yarn Berry
				// only accepts a plain-http registry when its host is whitelisted.
				appendToFile(t, filepath.Join(tempDirPath, ".yarnrc.yml"), "\nunsafeHttpWhitelist:\n  - \"127.0.0.1\"\n  - \"localhost\"\n")
			},
		},
		{
			name:    "Yarn V4 (registry from .yarnrc.yml)",
			project: "yarn-v4",
			configureRegistry: func(t *testing.T, tempDirPath string, config *config.ServerDetails) {
				// V4 native mode: the registry lives in .yarnrc.yml (the http whitelist is
				// already committed in the yarn-v4 fixture).
				appendToFile(t, filepath.Join(tempDirPath, ".yarnrc.yml"), fmt.Sprintf("\nnpmRegistryServer: \"%sapi/npm/npms/\"\n", config.ArtifactoryUrl))
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDirPath, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "yarn", tc.project))
			defer cleanUp()
			// Drop any committed lockfile so 'jf ca' must run the resolution-only plugin
			// (building yarn.lock from the mock packuments rather than reading a fresh lock).
			if err := os.Remove(filepath.Join(tempDirPath, "yarn.lock")); err != nil && !os.IsNotExist(err) {
				require.NoError(t, err)
			}

			expectedRequest := map[string]bool{
				"/api/npm/npms/json/-/json-9.0.6.tgz": false,
				"/api/npm/npms/xml/-/xml-1.0.1.tgz":   false,
			}
			requestToFail := map[string]bool{
				"/api/npm/npms/xml/-/xml-1.0.1.tgz": false,
			}
			serverMock, config := yarnCurationServer(t, expectedRequest, requestToFail)
			defer serverMock.Close()

			cleanUpJfrogHome, err := coreTests.SetJfrogHome()
			assert.NoError(t, err)
			defer cleanUpJfrogHome()

			config.User = "admin"
			config.Password = "password"
			config.ServerId = "test"
			configCmd := commonCommands.NewConfigCommand(commonCommands.AddOrEdit, config.ServerId).SetDetails(config).SetUseBasicAuthOnly(true).SetInteractive(false)
			assert.NoError(t, configCmd.Run())

			tc.configureRegistry(t, tempDirPath, config)

			localXrayCli := securityTests.PlatformCli.WithoutCredentials()
			workingDirsFlag := fmt.Sprintf("--working-dirs=%s", tempDirPath)
			output := localXrayCli.RunCliCmdWithOutput(t, "curation-audit", "--format="+string(format.Json), workingDirsFlag)
			expectedResp := getYarnCurationExpectedResponse(config)
			var got []curation.PackageStatus
			bracketIndex := strings.Index(output, "[")
			require.Less(t, 0, bracketIndex, "Unexpected Curation output with missing '['")
			err = json.Unmarshal([]byte(output[bracketIndex:]), &got)
			assert.NoError(t, err)
			assert.Equal(t, expectedResp, got)
			for k, v := range expectedRequest {
				assert.Truef(t, v, "didn't receive expected probe for package url %s", k)
			}
		})
	}
}

// appendToFile appends content to the file at path, creating it if it does not exist.
func appendToFile(t *testing.T, path, content string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	_, err = f.WriteString(content)
	require.NoError(t, err)
}

func getYarnCurationExpectedResponse(config *config.ServerDetails) []curation.PackageStatus {
	return []curation.PackageStatus{
		{
			Action:            "blocked",
			PackageName:       "xml",
			PackageVersion:    "1.0.1",
			BlockedPackageUrl: config.ArtifactoryUrl + "api/npm/npms/xml/-/xml-1.0.1.tgz",
			BlockingReason:    curation.BlockingReasonPolicy,
			ParentName:        "xml",
			ParentVersion:     "1.0.1",
			DepRelation:       "direct",
			PkgType:           "yarn",
			Policy: []curation.Policy{
				{Policy: "pol1", Condition: "cond1", Explanation: "explanation", Recommendation: "recommendation"},
				{Policy: "pol2", Condition: "cond2", Explanation: "explanation2", Recommendation: "recommendation2"},
			},
		},
	}
}

// curationBlockedTarballResponse is the Artifactory curation 403 body returned for a
// blocked tarball GET; the policy/condition tuples are parsed into PackageStatus.Policy.
const curationBlockedTarballResponse = "{\n    \"errors\": [\n        {\n            \"status\": 403,\n            " +
	"\"message\": \"Package download was blocked by JFrog Packages " +
	"Curation service due to the following policies violated {pol1, cond1, explanation, recommendation}, {pol2, cond2, explanation2, recommendation2}\"\n        }\n    ]\n}"

// yarnCurationServer mocks an Artifactory npm registry for the yarn curation tests. It
// serves npm packuments so 'yarn jfrog-yarn-resolve-lockfile' can resolve the graph from
// metadata without downloading tarballs, the version endpoints jf ca queries, and the
// curation HEAD/GET tarball probes (returning a policy-violation 403 for blocked tarballs).
func yarnCurationServer(t *testing.T, expectedRequest, requestToFail map[string]bool) (*httptest.Server, *config.ServerDetails) {
	mapLock := sync.Mutex{}
	// registryBase is the mock's own npm registry URL; it is set right after the
	// server is created (before any request is served) and used to build the
	// packument tarball URLs. Deriving it from the server URL rather than the
	// request's Host header avoids reflecting untrusted input into the response.
	var registryBase string
	serverMock, serverConfig, _ := commonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			mapLock.Lock()
			if _, exist := expectedRequest[r.RequestURI]; exist {
				expectedRequest[r.RequestURI] = true
			}
			mapLock.Unlock()
			if _, exist := requestToFail[r.RequestURI]; exist {
				w.WriteHeader(http.StatusForbidden)
			}
		case http.MethodGet:
			switch r.RequestURI {
			case "/api/system/version":
				_, err := w.Write([]byte(`{"version": "7.82.0"}`))
				require.NoError(t, err)
				return
			case "/api/v1/system/version":
				_, err := w.Write([]byte(`{"xray_version": "3.92.0"}`))
				require.NoError(t, err)
				return
			// Yarn V2/V3 resolve the registry via GetYarnAuthDetails, which queries
			// these two Artifactory endpoints before the resolve-only plugin runs.
			// (Yarn V4 reads the registry natively from .yarnrc.yml and skips them.)
			case "/api/npm/auth":
				_, err := w.Write([]byte("_auth = YWRtaW46cGFzc3dvcmQ=\nalways-auth = true\n"))
				require.NoError(t, err)
				return
			case "/api/repositories/npms":
				_, err := w.Write([]byte(`{"key":"npms","rclass":"remote","packageType":"npm"}`))
				require.NoError(t, err)
				return
			}
			// Blocked tarball GET (issued by the HEAD-walker after the 403 HEAD): return
			// the curation policy message so the package is reported as blocked-by-policy.
			if _, exist := requestToFail[r.RequestURI]; exist {
				w.WriteHeader(http.StatusForbidden)
				_, err := w.Write([]byte(curationBlockedTarballResponse))
				require.NoError(t, err)
				return
			}
			// npm packument lookup (resolve-only plugin); tarball GETs contain "/-/".
			if body := yarnPackument(r.URL.Path, registryBase); body != "" {
				_, err := w.Write([]byte(body))
				require.NoError(t, err)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}
	})
	registryBase = serverConfig.ArtifactoryUrl + "api/npm/npms/"
	return serverMock, serverConfig
}

// yarnPackument returns the npm packument JSON for the xml/json fixtures, or "" when the
// path is not a known packument lookup. The tarball URL uses base (the mock server's own
// registry URL) so it points at the running mock without reflecting request input.
func yarnPackument(reqPath, base string) string {
	if strings.Contains(reqPath, "/-/") {
		return ""
	}
	switch {
	case strings.HasSuffix(reqPath, "/api/npm/npms/xml"):
		return fmt.Sprintf(`{"name":"xml","dist-tags":{"latest":"1.0.1"},"versions":{"1.0.1":{"name":"xml","version":"1.0.1","dist":{"shasum":"97e0d0e9603c6ffd00fbf5419b3f48a6f4e0c7d9","tarball":"%sxml/-/xml-1.0.1.tgz"}}}}`, base)
	case strings.HasSuffix(reqPath, "/api/npm/npms/json"):
		return fmt.Sprintf(`{"name":"json","dist-tags":{"latest":"9.0.6"},"versions":{"9.0.6":{"name":"json","version":"9.0.6","bin":{"json":"./lib/json.js"},"dist":{"shasum":"0f53b0b2f48d1c7e54f3c00c4f5b3c8f0e6d4d0a","tarball":"%sjson/-/json-9.0.6.tgz"}}}}`, base)
	}
	return ""
}

func getCurationExpectedResponse(config *config.ServerDetails) []curation.PackageStatus {
	expectedResp := []curation.PackageStatus{
		{
			Action:            "blocked",
			PackageName:       "xml",
			PackageVersion:    "1.0.1",
			BlockedPackageUrl: config.ArtifactoryUrl + "api/npm/npms/xml/-/xml-1.0.1.tgz",
			BlockingReason:    curation.BlockingReasonPolicy,
			ParentName:        "xml",
			ParentVersion:     "1.0.1",
			DepRelation:       "direct",
			PkgType:           "npm",
			Policy: []curation.Policy{
				{
					Policy:         "pol1",
					Condition:      "cond1",
					Explanation:    "explanation",
					Recommendation: "recommendation",
				},
				{
					Policy:         "pol2",
					Condition:      "cond2",
					Explanation:    "explanation2",
					Recommendation: "recommendation2",
				},
			},
		},
	}
	return expectedResp
}

func TestDockerCurationAudit(t *testing.T) {
	integration.InitCurationTest(t)
	if securityTests.ContainerRegistry == nil || *securityTests.ContainerRegistry == "" || runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		t.Skip("Skipping Docker curation test - container registry not configured")
	}
	cleanUp := integration.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUp()

	testImage := fmt.Sprintf("%s/%s/%s", *securityTests.ContainerRegistry, "docker-curation", "bitnami/kubectl")

	output := securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, "curation-audit",
		"--image="+testImage,
		"--format="+string(format.Json))
	bracketIndex := strings.Index(output, "[")
	require.GreaterOrEqual(t, bracketIndex, 0, "Expected JSON array in output, got: %s", output)

	var results []curation.PackageStatus
	err := json.Unmarshal([]byte(output[bracketIndex:]), &results)
	require.NoError(t, err)

	require.NotEmpty(t, results, "Expected at least one blocked package")
	assert.Equal(t, "blocked", results[0].Action)
	assert.Equal(t, "bitnami/kubectl", results[0].PackageName)
	assert.Equal(t, curation.BlockingReasonPolicy, results[0].BlockingReason)
	require.NotEmpty(t, results[0].Policy, "Expected at least one policy violation")
	assert.Equal(t, "Image is not Docker Hub official", results[0].Policy[0].Condition)
}

func TestPoetryCurationAudit(t *testing.T) {
	integration.InitCurationTest(t)
	const repo = "pypi-curation"
	tempDirPath, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "poetry", "poetry-curation-project"))
	defer cleanUp()

	blockedURL := "/api/pypi/" + repo + "/packages/aa/urllib3-1.26.20-py2.py3-none-any.whl"
	expectedRequest := map[string]bool{blockedURL: false}
	requestToFail := map[string]bool{blockedURL: false}
	serverMock, config := curationServer(t, expectedRequest, requestToFail, map[string]string{
		"urllib3": `<a href="../../packages/aa/urllib3-1.26.20-py2.py3-none-any.whl">urllib3-1.26.20-py2.py3-none-any.whl</a>`,
	})
	defer serverMock.Close()

	cleanUpHome := integration.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()

	config.User = "admin"
	config.Password = "password"
	config.ServerId = "test"
	configCmd := commonCommands.NewConfigCommand(commonCommands.AddOrEdit, config.ServerId).SetDetails(config).SetUseBasicAuthOnly(true).SetInteractive(false)
	assert.NoError(t, configCmd.Run())

	localXrayCli := securityTests.PlatformCli.WithoutCredentials()
	workingDirsFlag := fmt.Sprintf("--working-dirs=%s", tempDirPath)
	output := localXrayCli.RunCliCmdWithOutput(t, "curation-audit", "--format="+string(format.Json), workingDirsFlag)

	expectedResp := getPoetryCurationExpectedResponse(config, repo)
	var got []curation.PackageStatus
	bracketIndex := strings.Index(output, "[")
	require.Less(t, 0, bracketIndex, "Unexpected Curation output with missing '['")
	err := json.Unmarshal([]byte(output[bracketIndex:]), &got)
	assert.NoError(t, err)
	assert.Equal(t, expectedResp, got)
	for k, v := range expectedRequest {
		assert.Truef(t, v, "didn't receive expected HEAD request for package url %s", k)
	}
}

func getPoetryCurationExpectedResponse(config *config.ServerDetails, repo string) []curation.PackageStatus {
	return []curation.PackageStatus{
		{
			Action:            "blocked",
			PackageName:       "urllib3",
			PackageVersion:    "1.26.20",
			BlockedPackageUrl: config.ArtifactoryUrl + "api/pypi/" + repo + "/packages/aa/urllib3-1.26.20-py2.py3-none-any.whl",
			BlockingReason:    curation.BlockingReasonPolicy,
			ParentName:        "urllib3",
			ParentVersion:     "1.26.20",
			DepRelation:       "direct",
			PkgType:           "poetry",
			Policy: []curation.Policy{
				{Policy: "pol1", Condition: "cond1", Explanation: "explanation", Recommendation: "recommendation"},
				{Policy: "pol2", Condition: "cond2", Explanation: "explanation2", Recommendation: "recommendation2"},
			},
		},
	}
}

// TestUvCurationAudit exercises 'jf curation-audit' end-to-end for uv. With no uv.lock
// present, 'jf ca' runs 'uv lock' against the mock's curation pass-through endpoint,
// resolving pexpect + ptyprocess from synthetic PEP 503/658 responses (see
// uvCurationServer). The curation HEAD-walker then probes the plain download URL
// recorded in the generated uv.lock and reports the blocked package as PkgType "uv".
func TestUvCurationAudit(t *testing.T) {
	integration.InitCurationTest(t)
	const repo = "pypi-curation"
	tempDirPath, cleanUp := securityTestUtils.CreateTestProjectEnvAndChdir(t, filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", "python", "uv", "uv-curation-project"))
	defer cleanUp()

	blockedURL := "/api/pypi/" + repo + "/packages/pexpect-4.8.0-py2.py3-none-any.whl"
	expectedRequest := map[string]bool{blockedURL: false}
	requestToFail := map[string]bool{blockedURL: false}
	serverMock, config := uvCurationServer(t, expectedRequest, requestToFail)
	defer serverMock.Close()

	cleanUpHome := integration.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUpHome()

	config.User = "admin"
	config.Password = "password"
	config.ServerId = "test"
	configCmd := commonCommands.NewConfigCommand(commonCommands.AddOrEdit, config.ServerId).SetDetails(config).SetUseBasicAuthOnly(true).SetInteractive(false)
	assert.NoError(t, configCmd.Run())

	appendToFile(t, filepath.Join(tempDirPath, "pyproject.toml"),
		fmt.Sprintf("\n[[tool.uv.index]]\nurl = \"%sapi/pypi/%s/simple\"\n", config.ArtifactoryUrl, repo))

	localXrayCli := securityTests.PlatformCli.WithoutCredentials()
	workingDirsFlag := fmt.Sprintf("--working-dirs=%s", tempDirPath)
	output := localXrayCli.RunCliCmdWithOutput(t, "curation-audit", "--format="+string(format.Json), workingDirsFlag)

	expectedResp := getUvCurationExpectedResponse(config, repo)
	var got []curation.PackageStatus
	bracketIndex := strings.Index(output, "[")
	require.Less(t, 0, bracketIndex, "Unexpected Curation output with missing '['")
	err := json.Unmarshal([]byte(output[bracketIndex:]), &got)
	assert.NoError(t, err)
	assert.Equal(t, expectedResp, got)
	for k, v := range expectedRequest {
		assert.Truef(t, v, "didn't receive expected HEAD request for package url %s", k)
	}
}

func getUvCurationExpectedResponse(config *config.ServerDetails, repo string) []curation.PackageStatus {
	return []curation.PackageStatus{
		{
			Action:            "blocked",
			PackageName:       "pexpect",
			PackageVersion:    "4.8.0",
			BlockedPackageUrl: config.ArtifactoryUrl + "api/pypi/" + repo + "/packages/pexpect-4.8.0-py2.py3-none-any.whl",
			BlockingReason:    curation.BlockingReasonPolicy,
			ParentName:        "pexpect",
			ParentVersion:     "4.8.0",
			DepRelation:       "direct",
			PkgType:           "uv",
			Policy: []curation.Policy{
				{Policy: "pol1", Condition: "cond1", Explanation: "explanation", Recommendation: "recommendation"},
				{Policy: "pol2", Condition: "cond2", Explanation: "explanation2", Recommendation: "recommendation2"},
			},
		},
	}
}

// uvSimplePackage holds the fixed pexpect/ptyprocess synthetic PyPI package data that
// the uv curation test resolves against.
type uvSimplePackage struct {
	name, version, sha256, requiresDist string
}

var uvSimplePackages = map[string]uvSimplePackage{
	"pexpect":    {name: "pexpect", version: "4.8.0", sha256: "0b48a55dcb3c05f3329815901ea4fc1537514d6ba867a152b581d69ae3710937", requiresDist: "Requires-Dist: ptyprocess (>=0.5)\n"},
	"ptyprocess": {name: "ptyprocess", version: "0.7.0", sha256: "4b41f3967fce3af57cc7e94b888626c18bf37a083e3651ca8feeb66d492fef35"},
}

func (p uvSimplePackage) wheelName() string {
	return fmt.Sprintf("%s-%s-py2.py3-none-any.whl", p.name, p.version)
}

// simpleIndexHtml is a minimal PEP 503 simple-index page for p, advertising PEP 658
// so 'uv lock' fetches the metadata sidecar below instead of the wheel itself.
func (p uvSimplePackage) simpleIndexHtml() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Simple index</title><meta name="api-version" value="2" /></head>
<body><a href="../../packages/%s#sha256=%s" data-core-metadata="true">%s</a></body></html>`,
		p.wheelName(), p.sha256, p.wheelName())
}

// coreMetadata is p's PEP 658 sidecar: just enough METADATA (Name/Version/Requires-Dist)
// for uv to resolve the dependency graph.
func (p uvSimplePackage) coreMetadata() string {
	return fmt.Sprintf("Metadata-Version: 2.1\nName: %s\nVersion: %s\n%s", p.name, p.version, p.requiresDist)
}

// uvCurationServer mocks Artifactory's PyPI curation pass-through for a real 'uv lock'
// subprocess to resolve against, serving synthetic PEP 503/658 responses.
func uvCurationServer(t *testing.T, expectedRequest, requestToFail map[string]bool) (*httptest.Server, *config.ServerDetails) {
	mapLock := sync.Mutex{}
	serverMock, serverConfig, _ := commonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			mapLock.Lock()
			if _, exist := expectedRequest[r.RequestURI]; exist {
				expectedRequest[r.RequestURI] = true
			}
			mapLock.Unlock()
			if _, exist := requestToFail[r.RequestURI]; exist {
				w.WriteHeader(http.StatusForbidden)
			}
		case http.MethodGet:
			switch r.RequestURI {
			case "/api/system/version":
				_, err := w.Write([]byte(`{"version": "7.82.0"}`))
				require.NoError(t, err)
				return
			case "/api/v1/system/version":
				_, err := w.Write([]byte(`{"xray_version": "3.92.0"}`))
				require.NoError(t, err)
				return
			}
			if strings.Contains(r.RequestURI, "api/curation/audit") {
				for _, pkg := range uvSimplePackages {
					if strings.HasSuffix(r.RequestURI, "/simple/"+pkg.name+"/") {
						_, err := w.Write([]byte(pkg.simpleIndexHtml()))
						require.NoError(t, err)
						return
					}
					if strings.HasSuffix(r.RequestURI, "/"+pkg.wheelName()+".metadata") {
						_, err := w.Write([]byte(pkg.coreMetadata()))
						require.NoError(t, err)
						return
					}
				}
			}
			if _, exist := requestToFail[r.RequestURI]; exist {
				w.WriteHeader(http.StatusForbidden)
				_, err := w.Write([]byte(curationBlockedTarballResponse))
				require.NoError(t, err)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return serverMock, serverConfig
}

func curationServer(t *testing.T, expectedRequest map[string]bool, requestToFail map[string]bool, simpleIndex ...map[string]string) (*httptest.Server, *config.ServerDetails) {
	mapLockReadWrite := sync.Mutex{}
	var index map[string]string
	if len(simpleIndex) > 0 {
		index = simpleIndex[0]
	}
	serverMock, config, _ := commonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			mapLockReadWrite.Lock()
			if _, exist := expectedRequest[r.RequestURI]; exist {
				expectedRequest[r.RequestURI] = true
			}
			mapLockReadWrite.Unlock()
			if _, exist := requestToFail[r.RequestURI]; exist {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		if r.Method == http.MethodGet {
			if r.RequestURI == "/api/system/version" {
				_, err := w.Write([]byte(`{"version": "7.82.0"}`))
				require.NoError(t, err)
				return
			}
			if r.RequestURI == "/api/v1/system/version" {
				_, err := w.Write([]byte(`{"xray_version": "3.92.0"}`))
				require.NoError(t, err)
				return
			}
			for name, href := range index {
				if strings.HasSuffix(r.URL.Path, "/simple/"+name+"/") {
					_, err := w.Write([]byte("<html><body>" + href + "</body></html>"))
					require.NoError(t, err)
					return
				}
			}
			if _, exist := requestToFail[r.RequestURI]; exist {
				w.WriteHeader(http.StatusForbidden)
				_, err := w.Write([]byte("{\n    \"errors\": [\n        {\n            \"status\": 403,\n            " +
					"\"message\": \"Package download was blocked by JFrog Packages " +
					"Curation service due to the following policies violated {pol1, cond1, explanation, recommendation}, {pol2, cond2, explanation2, recommendation2}\"\n        }\n    ]\n}"))
				require.NoError(t, err)
			}
		}
	})
	return serverMock, config
}
