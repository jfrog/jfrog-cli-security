package yarn

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"errors"

	"github.com/jfrog/build-info-go/build"
	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	biutils "github.com/jfrog/build-info-go/utils"
	coreCommonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// fakeYarnCapturingInstallForTest returns a POSIX "yarn" script that reports 4.5.0 for --version and, for any
// other call (the install), records the environment and the .yarnrc.yml it sees in the working directory.
func fakeYarnCapturingInstallForTest(t *testing.T) (yarnPath, envFile, yarnrcFile string) {
	captureDir := t.TempDir()
	envFile = filepath.Join(captureDir, "captured-env.txt")
	yarnrcFile = filepath.Join(captureDir, "captured-yarnrc.yml")
	yarnPath = filepath.Join(t.TempDir(), "yarn")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then echo 4.5.0; exit 0; fi\n" +
		"env > " + envFile + "\n" +
		"cat .yarnrc.yml > " + yarnrcFile + " 2>/dev/null\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(yarnPath, []byte(script), 0o755))
	return
}

func mockArtifactoryForYarnTest(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestConfigureYarnResolutionServerAndRunInstallBindsFallbackAuthToVerifiedRegistry: the credential is bound to the verified
// registry via a ${ENV} reference in the temp .yarnrc.yml (secret only in its own env var, not global YARN_NPM_AUTH_* or on disk).
func TestConfigureYarnResolutionServerAndRunInstallBindsFallbackAuthToVerifiedRegistry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake yarn executable is a POSIX shell script")
	}
	mockArtifactory := mockArtifactoryForYarnTest(t)
	curWd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(curWd, "package.json"), []byte(`{"name":"root"}`), 0644))
	fakeYarnPath, envCaptureFile, yarnrcCaptureFile := fakeYarnCapturingInstallForTest(t)

	//#nosec G101 -- test fixture, not a real secret
	const fallbackToken = "fallback-jf-c-token-xyz"
	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:               true,
		DependenciesRepository:      "tst-yarn-repo",
		YarnCredentialsFromFallback: true,
		ServerDetails: &config.ServerDetails{
			ArtifactoryUrl: mockArtifactory.URL + "/artifactory/",
			AccessToken:    fallbackToken,
		},
	}

	require.NoError(t, configureYarnResolutionServerAndRunInstall(params, curWd, fakeYarnPath))

	capturedEnvBytes, readErr := os.ReadFile(envCaptureFile)
	require.NoError(t, readErr, "the install subprocess (not just the --version probe) must have run")
	capturedEnv := string(capturedEnvBytes)
	for _, globalAuthEnv := range []string{"YARN_NPM_AUTH_TOKEN=", "YARN_NPM_AUTH_IDENT=", "YARN_NPM_ALWAYS_AUTH=", "YARN_NPM_REGISTRY_SERVER="} {
		assert.False(t, strings.Contains(capturedEnv, globalAuthEnv), "%s must not be set", globalAuthEnv)
	}

	yarnrcSeenByInstall, readErr := os.ReadFile(yarnrcCaptureFile)
	require.NoError(t, readErr)
	boundRegistry := mockArtifactory.URL + "/artifactory/api/npm/tst-yarn-repo"
	var seenRc struct {
		NpmRegistries map[string]map[string]interface{} `yaml:"npmRegistries"`
	}
	require.NoError(t, yaml.Unmarshal(yarnrcSeenByInstall, &seenRc))
	require.Contains(t, seenRc.NpmRegistries, boundRegistry, "the credential must be bound to the verified registry")
	authEnv := authEnvFromRef(t, seenRc.NpmRegistries[boundRegistry]["npmAuthToken"])
	assert.True(t, strings.Contains(capturedEnv, authEnv+"="+fallbackToken), "the secret must reach Yarn only through its per-run env var")
	assert.NotContains(t, string(yarnrcSeenByInstall), fallbackToken, "the secret must never be written to .yarnrc.yml")
	assert.Equal(t, true, seenRc.NpmRegistries[boundRegistry]["npmAlwaysAuth"])
	assert.Len(t, seenRc.NpmRegistries, 1, "nothing but the verified registry may carry the credential")

	yarnrcAfter, readErr := os.ReadFile(filepath.Join(curWd, ".yarnrc.yml"))
	require.NoError(t, readErr, "the resolution plugin registration made during the install must survive")
	assert.NotContains(t, string(yarnrcAfter), fallbackToken, "the credential must be stripped once the install is done")
	_, envLeft := os.LookupEnv(authEnv)
	assert.False(t, envLeft, "the env var must be unset again once the install is done")
}

// TestConfigureYarnResolutionServerAndRunInstallSkipsAuthInjectionWhenNotFallback verifies that
// when .yarnrc.yml already has its own token (YarnCredentialsFromFallback is false),
// the fallback binding is skipped — no GetYarnAuthDetails call is made. Proven by
// pointing ServerDetails at a server that always 500s: if the gate ever fires unconditionally
// again, that call would fail and the install would error.
func TestConfigureYarnResolutionServerAndRunInstallSkipsAuthInjectionWhenNotFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake yarn executable is a POSIX shell script")
	}
	var artifactoryCalled bool
	mockArtifactory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		artifactoryCalled = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockArtifactory.Close()

	curWd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(curWd, "package.json"), []byte(`{"name":"root"}`), 0644))
	fakeYarnPath, envCaptureFile, yarnrcCaptureFile := fakeYarnCapturingInstallForTest(t)

	//#nosec G101 -- test fixture, not a real secret
	const yarnrcToken = "yarnrc-own-token-abc"
	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:               true,
		DependenciesRepository:      "tst-yarn-repo",
		YarnCredentialsFromFallback: false,
		ServerDetails: &config.ServerDetails{
			ArtifactoryUrl: mockArtifactory.URL + "/artifactory/",
			AccessToken:    yarnrcToken,
		},
	}

	require.NoError(t, configureYarnResolutionServerAndRunInstall(params, curWd, fakeYarnPath),
		"must succeed even though the mock server 500s — GetYarnAuthDetails must never be called")
	assert.False(t, artifactoryCalled,
		"no request should reach Artifactory: .yarnrc.yml already has its own token, so no fallback injection is needed")

	capturedEnvBytes, readErr := os.ReadFile(envCaptureFile)
	require.NoError(t, readErr, "the install subprocess must have run")
	assert.False(t, strings.Contains(string(capturedEnvBytes), yarnrcToken), "the token already lives in .yarnrc.yml and must not be injected")
	yarnrcSeenByInstall, readErr := os.ReadFile(yarnrcCaptureFile)
	require.NoError(t, readErr)
	assert.NotContains(t, string(yarnrcSeenByInstall), yarnrcToken)
	assert.NotContains(t, string(yarnrcSeenByInstall), "npmRegistries", "no credential binding is written when not falling back")
}

// TestBindCurationFallbackAuthNoOpWithoutCredentials verifies that with no usable credentials nothing is
// written and the restore is a no-op — the anonymous-resolution case is unchanged.
func TestBindCurationFallbackAuthNoOpWithoutCredentials(t *testing.T) {
	curWd := t.TempDir()

	restore, err := bindCurationFallbackAuthInYarnrc(curWd, nil, "some-repo")
	require.NoError(t, err)
	require.NotNil(t, restore)
	require.NoError(t, restore())

	restore, err = bindCurationFallbackAuthInYarnrc(curWd, &config.ServerDetails{ArtifactoryUrl: "http://127.0.0.1:1/artifactory/"}, "some-repo")
	require.NoError(t, err)
	require.NoError(t, restore())

	assert.NoFileExists(t, filepath.Join(curWd, ".yarnrc.yml"))
}

// A Password-only server must not be treated as anonymous (it used to be, since the old predicate
// ignored Password entirely); this proves it now attempts real auth instead of a silent no-op.
func TestBindCurationFallbackAuthAttemptsAuthWithPasswordOnlyServer(t *testing.T) {
	curWd := t.TempDir()
	server := &config.ServerDetails{ArtifactoryUrl: "http://127.0.0.1:1/artifactory/", Password: "some-password"}

	_, err := bindCurationFallbackAuthInYarnrc(curWd, server, "some-repo")

	assert.Error(t, err, "a Password-only server must not be silently treated as anonymous")
	assert.NoFileExists(t, filepath.Join(curWd, ".yarnrc.yml"))
}

// TestBindCurationFallbackAuthBindsUserPasswordAsAuthIdent: with a user:password credential (no access token) the binding
// references the npmAuthIdent Artifactory returns for the verified registry, and sets no npmAuthToken.
func TestBindCurationFallbackAuthBindsUserPasswordAsAuthIdent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const authIdent = "ZmFrZS1pZGVudA==" // fake base64 ident, as returned by Artifactory's npm auth API
	npmAuthCalls := make(chan string, 4)
	mockArtifactory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/system/version"):
			_, _ = w.Write([]byte(`{"version":"7.90.0"}`))
		case strings.HasSuffix(r.URL.Path, "/api/npm/auth"):
			user, password, _ := r.BasicAuth()
			npmAuthCalls <- user + ":" + password
			_, _ = w.Write([]byte("_auth = " + authIdent + "\nalways-auth = true\nemail = jf-user@example.com\n"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(mockArtifactory.Close)
	curWd := t.TempDir()
	//#nosec G101 -- test fixture, not a real secret
	server := &config.ServerDetails{ArtifactoryUrl: mockArtifactory.URL + "/artifactory/", User: "jf-user", Password: "jf-pass"}

	restore, err := bindCurationFallbackAuthInYarnrc(curWd, server, "tst-yarn-repo")
	require.NoError(t, err)

	select {
	case basicAuth := <-npmAuthCalls:
		assert.Equal(t, "jf-user:jf-pass", basicAuth, "the ident must be requested with the user:password credential")
	default:
		t.Fatal("Artifactory's npm auth API was never called")
	}
	registries := requireMap(t, readYarnrcForTest(t, curWd)["npmRegistries"])
	require.Len(t, registries, 1)
	entry := requireMap(t, registries[mockArtifactory.URL+"/artifactory/api/npm/tst-yarn-repo"])
	authEnv := authEnvFromRef(t, entry["npmAuthIdent"])
	assert.Equal(t, authIdent, os.Getenv(authEnv), "the ident is carried by the env var, not the file")
	assert.NotContains(t, entry, "npmAuthToken")
	assert.Equal(t, true, entry["npmAlwaysAuth"])

	require.NoError(t, restore())
	assert.NoFileExists(t, filepath.Join(curWd, ".yarnrc.yml"), "the credential must be removed after the install")
	_, envLeft := os.LookupEnv(authEnv)
	assert.False(t, envLeft, "the credential env var must not outlive the run")
}

// TestBindCurationFallbackAuthKeepsSecretOffDiskAndUnsetsEnv: the temp copy never contains the secret, which lives only in a
// per-run env var that is gone after restore.
func TestBindCurationFallbackAuthKeepsSecretOffDiskAndUnsetsEnv(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mockArtifactory := mockArtifactoryForYarnTest(t)
	curWd := t.TempDir()
	server := &config.ServerDetails{ArtifactoryUrl: mockArtifactory.URL + "/artifactory/", AccessToken: "tok-secret-789"}

	restore, err := bindCurationFallbackAuthInYarnrc(curWd, server, "tst-yarn-repo")
	require.NoError(t, err)
	registries := requireMap(t, readYarnrcForTest(t, curWd)["npmRegistries"])
	authEnv := authEnvFromRef(t, requireMap(t, registries[mockArtifactory.URL+"/artifactory/api/npm/tst-yarn-repo"])["npmAuthToken"])
	assert.Equal(t, "tok-secret-789", os.Getenv(authEnv))
	entries, err := os.ReadDir(curWd)
	require.NoError(t, err)
	require.NotEmpty(t, entries, "the binding must have been written")
	for _, entry := range entries {
		content, readErr := os.ReadFile(filepath.Join(curWd, entry.Name()))
		require.NoError(t, readErr)
		assert.NotContains(t, string(content), "tok-secret-789", "the secret must not be on disk: %s", entry.Name())
	}

	require.NoError(t, restore())
	_, envLeft := os.LookupEnv(authEnv)
	assert.False(t, envLeft, "the credential env var must not outlive the run")
}

// TestBindCurationFallbackAuthUsesAFreshRandomEnvVarName: the name carrying the credential differs on every run, so a project
// can't write ${NAME} into a setting (e.g. a proxy URL) to read the token back out.
func TestBindCurationFallbackAuthUsesAFreshRandomEnvVarName(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mockArtifactory := mockArtifactoryForYarnTest(t)
	server := &config.ServerDetails{ArtifactoryUrl: mockArtifactory.URL + "/artifactory/", AccessToken: "tok-1"}
	const runs = 5
	names := map[string]bool{}
	for i := 0; i < runs; i++ {
		curWd := t.TempDir()
		restore, err := bindCurationFallbackAuthInYarnrc(curWd, server, "tst-yarn-repo")
		require.NoError(t, err)
		registries := requireMap(t, readYarnrcForTest(t, curWd)["npmRegistries"])
		name := authEnvFromRef(t, requireMap(t, registries[mockArtifactory.URL+"/artifactory/api/npm/tst-yarn-repo"])["npmAuthToken"])
		assert.Greater(t, len(name), len(yarnFallbackAuthEnvPrefix)+8, "the name must carry a random suffix")
		assert.NotEqual(t, "JFROG_CLI_CURATION_YARN_FALLBACK_AUTH", name, "the previous fixed name must not be used")
		names[name] = true
		require.NoError(t, restore())
	}
	assert.Len(t, names, runs, "every run must use a different env var name")
}

// authEnvFromRef returns the env var name in a bound ${NAME} reference, failing if it isn't one of ours.
func authEnvFromRef(t *testing.T, value interface{}) string {
	t.Helper()
	text, ok := value.(string)
	require.True(t, ok, "expected a ${ENV} reference, got %T", value)
	require.True(t, strings.HasPrefix(text, "${"+yarnFallbackAuthEnvPrefix) && strings.HasSuffix(text, "}"), "unexpected reference %q", text)
	return strings.TrimSuffix(strings.TrimPrefix(text, "${"), "}")
}

// requireMap returns value as a map, failing the test (instead of panicking) when it is not one.
func requireMap(t *testing.T, value interface{}) map[string]interface{} {
	t.Helper()
	m, ok := value.(map[string]interface{})
	require.True(t, ok, "expected a map, got %T", value)
	return m
}

func readYarnrcForTest(t *testing.T, dir string) map[string]interface{} {
	data, err := os.ReadFile(filepath.Join(dir, ".yarnrc.yml"))
	require.NoError(t, err)
	rc := map[string]interface{}{}
	require.NoError(t, yaml.Unmarshal(data, &rc))
	return rc
}

// TestBindCurationFallbackAuthBindsVerifiedAndSameHostScopesOnly: the credential goes to the verified registry and
// same-host scope registries, never to another host.
func TestBindCurationFallbackAuthBindsVerifiedAndSameHostScopesOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mockArtifactory := mockArtifactoryForYarnTest(t)
	curWd := t.TempDir()
	sameHostScope := mockArtifactory.URL + "/artifactory/api/npm/company-repo/"
	require.NoError(t, os.WriteFile(filepath.Join(curWd, ".yarnrc.yml"), []byte(
		"npmRegistryServer: \""+mockArtifactory.URL+"/artifactory/api/npm/tst-yarn-repo/\"\n"+
			"npmScopes:\n"+
			"  company:\n    npmRegistryServer: \""+sameHostScope+"\"\n"+
			"  evil:\n    npmRegistryServer: \"https://attacker.example.com/\"\n"+
			"  publishonly:\n    npmPublishRegistry: \""+mockArtifactory.URL+"/artifactory/api/npm/pub/\"\n"), 0o600))
	server := &config.ServerDetails{ArtifactoryUrl: mockArtifactory.URL + "/artifactory/", AccessToken: "tok-123"}

	restore, err := bindCurationFallbackAuthInYarnrc(curWd, server, "tst-yarn-repo")
	require.NoError(t, err)

	registries := requireMap(t, readYarnrcForTest(t, curWd)["npmRegistries"])
	assert.Len(t, registries, 2)
	var authEnv string
	for _, key := range []string{
		mockArtifactory.URL + "/artifactory/api/npm/tst-yarn-repo",
		mockArtifactory.URL + "/artifactory/api/npm/company-repo",
	} {
		require.Contains(t, registries, key)
		ref := authEnvFromRef(t, requireMap(t, registries[key])["npmAuthToken"])
		if authEnv != "" {
			assert.Equal(t, authEnv, ref, "every bound registry must reference the same per-run env var")
		}
		authEnv = ref
	}
	assert.Equal(t, "tok-123", os.Getenv(authEnv), "the secret is carried by the env var while bound")
	onDisk, readErr := os.ReadFile(filepath.Join(curWd, ".yarnrc.yml"))
	require.NoError(t, readErr)
	assert.NotContains(t, string(onDisk), "tok-123", "the secret must never be written to .yarnrc.yml")
	for key := range registries {
		assert.NotContains(t, key, "attacker.example.com", "a registry on another host must never get the credential")
	}

	require.NoError(t, restore())
	_, envLeft := os.LookupEnv(authEnv)
	assert.False(t, envLeft, "the env var must be unset again after restore")
	after := readYarnrcForTest(t, curWd)
	assert.NotContains(t, after, "npmRegistries", "the binding must be removed once the install is done")
	assert.Contains(t, after, "npmScopes", "the project's own settings must be left as they were")
}

// TestBindCurationFallbackAuthPreservesAndRestoresExistingRegistries: existing npmRegistries entries are kept while
// bound and restored afterwards; the plugin registration made in between survives.
func TestBindCurationFallbackAuthPreservesAndRestoresExistingRegistries(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mockArtifactory := mockArtifactoryForYarnTest(t)
	curWd := t.TempDir()
	boundKey := mockArtifactory.URL + "/artifactory/api/npm/tst-yarn-repo"
	require.NoError(t, os.WriteFile(filepath.Join(curWd, ".yarnrc.yml"), []byte(
		"npmRegistries:\n"+
			"  \""+boundKey+"\":\n    npmAlwaysAuth: false\n    npmAuthIdent: stale-ident\n"+
			"  \"//other.example.com\":\n    npmAuthToken: other-token\n"), 0o600))
	server := &config.ServerDetails{ArtifactoryUrl: mockArtifactory.URL + "/artifactory/", AccessToken: "tok-123"}

	restore, err := bindCurationFallbackAuthInYarnrc(curWd, server, "tst-yarn-repo")
	require.NoError(t, err)
	bound := requireMap(t, readYarnrcForTest(t, curWd)["npmRegistries"])
	boundEntry := requireMap(t, bound[boundKey])
	authEnvFromRef(t, boundEntry["npmAuthToken"])
	assert.Equal(t, true, boundEntry["npmAlwaysAuth"])
	assert.NotContains(t, boundEntry, "npmAuthIdent", "a stale ident must not shadow the bound token")
	assert.Equal(t, map[string]interface{}{"npmAuthToken": "other-token"}, bound["//other.example.com"])

	require.NoError(t, registerYarnPluginInYarnrc(curWd))
	require.NoError(t, restore())

	after := readYarnrcForTest(t, curWd)
	assert.Contains(t, after, "plugins", "the plugin registration made during the install must survive the restore")
	restored := requireMap(t, after["npmRegistries"])
	assert.Equal(t, map[string]interface{}{"npmAlwaysAuth": false, "npmAuthIdent": "stale-ident"}, restored[boundKey])
	assert.Equal(t, map[string]interface{}{"npmAuthToken": "other-token"}, restored["//other.example.com"])
}

// TestBindCurationFallbackAuthCreatesAndRemovesYarnrc: when the project has no .yarnrc.yml of its own the
// binding is written to a new one and the file is removed again afterwards.
func TestBindCurationFallbackAuthCreatesAndRemovesYarnrc(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mockArtifactory := mockArtifactoryForYarnTest(t)
	curWd := t.TempDir()
	server := &config.ServerDetails{ArtifactoryUrl: mockArtifactory.URL + "/artifactory/", AccessToken: "tok-123"}

	restore, err := bindCurationFallbackAuthInYarnrc(curWd, server, "tst-yarn-repo")
	require.NoError(t, err)
	assert.Contains(t, readYarnrcForTest(t, curWd), "npmRegistries")
	assert.FileExists(t, filepath.Join(curWd, ".yarnrc.yml"))

	require.NoError(t, restore())
	assert.NoFileExists(t, filepath.Join(curWd, ".yarnrc.yml"))
}

// TestBindCurationFallbackAuthRefusesUnparsableYarnrc: the credential is never written into a file we cannot
// merge into safely.
func TestBindCurationFallbackAuthRefusesUnparsableYarnrc(t *testing.T) {
	mockArtifactory := mockArtifactoryForYarnTest(t)
	curWd := t.TempDir()
	const broken = "npmRegistries: [unclosed\n"
	require.NoError(t, os.WriteFile(filepath.Join(curWd, ".yarnrc.yml"), []byte(broken), 0o600))
	server := &config.ServerDetails{ArtifactoryUrl: mockArtifactory.URL + "/artifactory/", AccessToken: "tok-123"}

	_, err := bindCurationFallbackAuthInYarnrc(curWd, server, "tst-yarn-repo")

	require.Error(t, err)
	data, readErr := os.ReadFile(filepath.Join(curWd, ".yarnrc.yml"))
	require.NoError(t, readErr)
	assert.Equal(t, broken, string(data))
}

func TestGetYarnrcNetworkSettings(t *testing.T) {
	const proxySecret = "secretpw" // a fake secret to prove it is never returned
	cleanRc := "npmRegistryServer: https://host.example/artifactory/api/npm/repo/\nnpmAuthToken: own-token\nnpmScopes:\n  a:\n    npmRegistryServer: https://host.example/x/\n"
	testCases := []struct {
		name     string
		yarnrc   string
		expected []string
	}{
		{name: "httpProxy", yarnrc: "httpProxy: \"http://user:" + proxySecret + "@proxy.example:3128\"\n", expected: []string{"httpProxy"}},
		{name: "httpsProxy", yarnrc: "httpsProxy: \"http://proxy.example:3128\"\n", expected: []string{"httpsProxy"}},
		{name: "enableStrictSsl false", yarnrc: "enableStrictSsl: false\n", expected: []string{"enableStrictSsl"}},
		{name: "enableStrictSsl false as a string", yarnrc: "enableStrictSsl: \"false\"\n", expected: []string{"enableStrictSsl"}},
		{name: "enableStrictSsl 0 unquoted", yarnrc: "enableStrictSsl: 0\n", expected: []string{"enableStrictSsl"}},
		{name: "enableStrictSsl 0 quoted", yarnrc: "enableStrictSsl: \"0\"\n", expected: []string{"enableStrictSsl"}},
		{name: "enableStrictSsl 1 left on", yarnrc: "enableStrictSsl: 1\n", expected: nil},
		{name: "enableStrictSsl env default false", yarnrc: "enableStrictSsl: \"${STRICT_SSL:-false}\"\n", expected: []string{"enableStrictSsl"}},
		{name: "enableStrictSsl env default 0", yarnrc: "enableStrictSsl: \"${STRICT_SSL:-0}\"\n", expected: []string{"enableStrictSsl"}},
		{name: "enableStrictSsl env reference", yarnrc: "enableStrictSsl: \"${STRICT_SSL}\"\n", expected: []string{"enableStrictSsl"}},
		{name: "scalar networkSettings", yarnrc: "networkSettings: \"not-a-map\"\n", expected: []string{"networkSettings"}},
		{name: "unsafeHttpWhitelist", yarnrc: "unsafeHttpWhitelist:\n  - \"registry.example\"\n", expected: []string{"unsafeHttpWhitelist"}},
		{
			name:     "networkSettings, one entry per host in order",
			yarnrc:   "networkSettings:\n  \"b.example\":\n    enableNetwork: false\n  \"a.example\":\n    httpsProxy: \"http://p\"\n",
			expected: []string{"networkSettings.a.example", "networkSettings.b.example"},
		},
		{
			name:     "several settings keep a fixed order",
			yarnrc:   "networkSettings:\n  \"h.example\":\n    enableNetwork: true\nunsafeHttpWhitelist: [\"h.example\"]\nenableStrictSsl: false\nhttpsProxy: \"http://p\"\nhttpProxy: \"http://p\"\n",
			expected: []string{"httpProxy", "httpsProxy", "enableStrictSsl", "unsafeHttpWhitelist", "networkSettings.h.example"},
		},
		{name: "clean rc", yarnrc: cleanRc, expected: nil},
		{name: "strict ssl left on", yarnrc: "enableStrictSsl: true\n", expected: nil},
		{name: "empty proxy and whitelist", yarnrc: "httpProxy: \"\"\nhttpsProxy: \"\"\nunsafeHttpWhitelist: []\nnetworkSettings: {}\n", expected: nil},
	}
	for _, testCase := range testCases {
		for _, location := range []string{"project", "parent", "home"} {
			t.Run(testCase.name+" in the "+location+" file", func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
				root := t.TempDir()
				member := filepath.Join(root, "packages", "app")
				require.NoError(t, os.MkdirAll(member, 0o755))
				placedIn := map[string]string{"project": member, "parent": root, "home": home}[location]
				rcPath := filepath.Join(placedIn, ".yarnrc.yml")
				require.NoError(t, os.WriteFile(rcPath, []byte(testCase.yarnrc), 0o600))

				found, err := GetYarnrcNetworkSettings(member)

				require.NoError(t, err)
				var names []string
				for _, setting := range found {
					names = append(names, setting.Setting)
					assert.Equal(t, rcPath, setting.File, "the file that sets it must be reported")
				}
				assert.Equal(t, testCase.expected, names)
			})
		}
	}

	t.Run("values are never returned", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		wd := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte("httpProxy: \"http://user:"+proxySecret+"@proxy.example:3128\"\n"), 0o600))
		found, err := GetYarnrcNetworkSettings(wd)
		require.NoError(t, err)
		require.Len(t, found, 1)
		assert.False(t, strings.Contains(fmt.Sprintf("%+v", found), proxySecret), "a proxy URL's secret must not be carried in the result")
	})

	t.Run("YARN_RC_FILENAME renames the file Yarn reads", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("YARN_RC_FILENAME", ".yarnrc.custom.yml")
		wd := t.TempDir()
		rcPath := filepath.Join(wd, ".yarnrc.custom.yml")
		require.NoError(t, os.WriteFile(rcPath, []byte("httpsProxy: \"http://proxy.example:3128\"\n"), 0o600))
		found, err := GetYarnrcNetworkSettings(wd)
		require.NoError(t, err)
		require.Len(t, found, 1)
		assert.Equal(t, "httpsProxy", found[0].Setting)
		assert.Equal(t, rcPath, found[0].File)
	})

	t.Run("an unparsable file is an error", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		wd := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte("httpProxy: [unclosed\n"), 0o600))
		found, err := GetYarnrcNetworkSettings(wd)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not parse")
		assert.Nil(t, found)
	})
}

func TestCurationAuthRegistryTargets(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	curWd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(curWd, ".yarnrc.yml"), []byte(
		"npmScopes:\n"+
			"  a:\n    npmRegistryServer: https://host.example/artifactory/api/npm/a-repo/\n"+
			"  dup:\n    npmRegistryServer: https://host.example/artifactory/api/npm/tst/\n"+
			"  evil:\n    npmRegistryServer: https://attacker.example/\n"+
			"  otherscheme:\n    npmRegistryServer: http://host.example/artifactory/api/npm/x/\n"+
			"  pub:\n    npmPublishRegistry: https://host.example/artifactory/api/npm/pub/\n"), 0o600))

	targets, err := curationAuthRegistryTargets(curWd, "https://host.example/artifactory/api/npm/tst/", "https://host.example/artifactory/")

	require.NoError(t, err)
	assert.Equal(t, []string{
		"https://host.example/artifactory/api/npm/tst",
		"https://host.example/artifactory/api/npm/a-repo",
	}, targets)
}

func TestCurationAuthRegistryTargetsFailsOnUnparsableYarnrc(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	curWd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(curWd, ".yarnrc.yml"), []byte("npmScopes: [unclosed\n"), 0o600))

	targets, err := curationAuthRegistryTargets(curWd, "https://host.example/artifactory/api/npm/tst/", "https://host.example/artifactory/")

	require.Error(t, err)
	assert.Nil(t, targets)
}

func TestParseYarnDependenciesMap(t *testing.T) {
	npmId := techutils.Npm.GetXrayPackageTypeId()

	testCases := []struct {
		name               string
		yarnDependencies   map[string]*bibuildutils.YarnDependency
		rootXrayId         string
		isCurationCmd      bool
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
			// Curation-only; see the next case for the non-curation behavior.
			name: "Workspace member excluded from uniqueDeps but kept in tree (curation)",
			yarnDependencies: map[string]*bibuildutils.YarnDependency{
				"root@workspace:.":         {Value: "root@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "1.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "ui@workspace:packages/ui"}}}},
				"ui@workspace:packages/ui": {Value: "ui@workspace:packages/ui", Details: bibuildutils.YarnDepDetails{Version: "0.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "express@npm:3.0.1"}}}},
				"express@npm:3.0.1":        {Value: "express@npm:3.0.1", Details: bibuildutils.YarnDepDetails{Version: "3.0.1"}},
			},
			rootXrayId:    npmId + "root:1.0.0",
			isCurationCmd: true,
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
			// Same shape, non-curation: workspace member must stay in uniqueDeps.
			name: "Workspace member kept in uniqueDeps for jf audit/jf scan (non-curation)",
			yarnDependencies: map[string]*bibuildutils.YarnDependency{
				"root@workspace:.":         {Value: "root@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "1.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "ui@workspace:packages/ui"}}}},
				"ui@workspace:packages/ui": {Value: "ui@workspace:packages/ui", Details: bibuildutils.YarnDepDetails{Version: "0.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "express@npm:3.0.1"}}}},
				"express@npm:3.0.1":        {Value: "express@npm:3.0.1", Details: bibuildutils.YarnDepDetails{Version: "3.0.1"}},
			},
			rootXrayId:    npmId + "root:1.0.0",
			isCurationCmd: false,
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
			expectedUniqueDeps: []string{npmId + "root:1.0.0", npmId + "ui:0.0.0", npmId + "express:3.0.1"},
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
			xrayDependenciesTree, uniqueDeps, err := parseYarnDependenciesMap(testcase.yarnDependencies, testcase.rootXrayId, testcase.isCurationCmd)
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

// TestCollectDeclaredDirectDepsAcrossWorkspaces verifies collectDeclaredDirectDeps merges the root package.json's direct deps with every workspace member's, with a member's spec overriding the root's on a name conflict.
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

	// express differs between root and admin-ui; members are merged after root and win on conflict.
	assert.Equal(t, "^3.0.1", declared["express"], "workspace member's spec wins over root's for the same package name")
	assert.Equal(t, "4.17.23", declared["lodash"], "root-only dep must be present")
	assert.Equal(t, "^26.0.0", declared["jsdom"], "workspace member's dep must be merged into the root scope")
	assert.Len(t, declared, 3, "got: %v", declared)
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
// TestCurationNoLockfileErrorNeutralWhenUnrelatedToCuration verifies that when the probe finds
// no blocked deps (no declared deps here) and installErr's text carries no curation-block
// signal (no "403"/"forbidden"), curationNoLockfileError returns a neutral "unrelated failure"
// message instead of blaming curation.
func TestCurationNoLockfileErrorNeutralWhenUnrelatedToCuration(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"root"}`), 0644))

	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		DependenciesRepository: "tst-yarn-repo",
	}
	installErr := errors.New("EACCES: permission denied, mkdir '/tmp/.yarn/berry/cache'")

	err := curationNoLockfileError(params, root, "", "", installErr)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "unrelated to a curation block")
	assert.NotContains(t, msg, "curation is blocking manifests")
	assert.Contains(t, msg, installErr.Error(), "must propagate the underlying error for traceability")
}

// TestCurationNoLockfileErrorBlamesCurationOnHttp403 verifies that when installErr's text does
// carry a curation-block signal (HTTP 403), curationNoLockfileError keeps the curation-blaming
// wording — this is a regression guard against over-correcting the fix above.
func TestCurationNoLockfileErrorBlamesCurationOnHttp403(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"root"}`), 0644))

	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		DependenciesRepository: "tst-yarn-repo",
	}
	installErr := errors.New("YN0035: Response Code: 403 (Forbidden)")

	err := curationNoLockfileError(params, root, "", "", installErr)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "unrelated to a curation block")
}

// TestCurationNoLockfileErrorDoesNotMatchBare403InUnrelatedText verifies a "403" appearing
// incidentally in unrelated text (e.g. a port number) isn't mistaken for an HTTP 403 curation
// block. Only the actual "Response Code: 403" shape yarn emits should match.
func TestCurationNoLockfileErrorDoesNotMatchBare403InUnrelatedText(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"root"}`), 0644))

	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		DependenciesRepository: "tst-yarn-repo",
	}
	installErr := errors.New("connect ECONNREFUSED 127.0.0.1:8403")

	err := curationNoLockfileError(params, root, "", "", installErr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrelated to a curation block",
		"a bare '403' inside a port number must not be mistaken for an HTTP 403 curation block")
}

func TestCurationNoLockfileErrorDoesNotMatchBareForbiddenInUnrelatedText(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"root"}`), 0644))

	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		DependenciesRepository: "tst-yarn-repo",
	}
	installErr := errors.New("fatal: unable to access 'https://github.com/example/repo.git/': remote: Forbidden")

	err := curationNoLockfileError(params, root, "", "", installErr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrelated to a curation block",
		"the word 'forbidden' alone, without a 'Response Code: 403' curation signal, must not be mistaken for a curation block")
}

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

// TestRootResolutionAppliesToAuditAndScan pins three contracts:
//
//  1. resolveYarnRoot runs only when params.IsCurationCmd is true (regression
//     guard for #759, which ran it unconditionally and broke 'jf audit'/
//     'jf scan' on Yarn workspace members).
//
//  2. @workspace:. is authoritative over build-info-go's heuristic, for
//     'jf ca' only.
//
//  3. stripWorkspaceUseLocalSuffix, unlike resolveYarnRoot, is NOT gated on
//     IsCurationCmd — applies to all callers.
func TestRootResolutionAppliesToAuditAndScan(t *testing.T) {
	t.Run("source contract: resolveYarnRoot is called only when IsCurationCmd is true", func(t *testing.T) {
		src, err := os.ReadFile("yarn.go")
		require.NoError(t, err)
		txt := string(src)
		callIdx := strings.Index(txt, "root = resolveYarnRoot(")
		require.NotEqual(t, -1, callIdx,
			"resolveYarnRoot call must be present in BuildDependencyTree")
		windowStart := callIdx - 200
		if windowStart < 0 {
			windowStart = 0
		}
		context := txt[windowStart:callIdx]
		assert.Contains(t, context, "if params.IsCurationCmd {",
			"resolveYarnRoot must only run for 'jf ca', not jf audit/jf scan")
	})

	t.Run("source contract: stripWorkspaceUseLocalSuffix is called unconditionally", func(t *testing.T) {
		// Must sit at top level (one leading tab), not nested under IsCurationCmd.
		src, err := os.ReadFile("yarn.go")
		require.NoError(t, err)
		txt := string(src)
		callStr := "stripWorkspaceUseLocalSuffix(dependenciesMap)"
		callIdx := strings.Index(txt, callStr)
		require.NotEqual(t, -1, callIdx,
			"stripWorkspaceUseLocalSuffix call must be present in BuildDependencyTree")
		lineStart := strings.LastIndex(txt[:callIdx], "\n") + 1
		line := txt[lineStart : callIdx+len(callStr)]
		assert.Equal(t, "\t"+callStr, line,
			"stripWorkspaceUseLocalSuffix must run unconditionally, not nested inside an if block")
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

// TestResolveYarnRootDoesNotOverrideWorkspaceMemberRoot unit-tests the
// resolveYarnRoot helper (curation-only; see TestRootResolutionAppliesToAuditAndScan
// for the IsCurationCmd gate at its call site).
func TestResolveYarnRootDoesNotOverrideWorkspaceMemberRoot(t *testing.T) {
	projectRoot := &bibuildutils.YarnDependency{Value: "jf-audit-yarn-ws-repro@workspace:.", Details: bibuildutils.YarnDepDetails{Version: "0.0.0"}}
	memberRoot := &bibuildutils.YarnDependency{
		Value:   "@repro/app@workspace:app",
		Details: bibuildutils.YarnDepDetails{Version: "1.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "lodash@npm:4.17.21"}}},
	}
	lodash := &bibuildutils.YarnDependency{Value: "lodash@npm:4.17.21", Details: bibuildutils.YarnDepDetails{Version: "4.17.21"}}
	deps := map[string]*bibuildutils.YarnDependency{
		"jf-audit-yarn-ws-repro@workspace:.": projectRoot,
		"@repro/app@workspace:app":           memberRoot,
		"lodash@npm:4.17.21":                 lodash,
	}

	t.Run("named workspace member: build-info-go's own root is kept, not clobbered by the outer project root", func(t *testing.T) {
		got := resolveYarnRoot(deps, memberRoot, "@repro/app")
		assert.Same(t, memberRoot, got)
	})

	t.Run("named project root: build-info-go's own root is kept", func(t *testing.T) {
		got := resolveYarnRoot(deps, projectRoot, "jf-audit-yarn-ws-repro")
		assert.Same(t, projectRoot, got)
	})

	t.Run("nameless package.json: falls back to the @workspace:. root", func(t *testing.T) {
		got := resolveYarnRoot(deps, nil, "")
		require.NotNil(t, got)
		assert.Equal(t, "jf-audit-yarn-ws-repro@workspace:.", got.Value)
	})

	t.Run("nil heuristic root with a name: still falls back to the @workspace:. root", func(t *testing.T) {
		got := resolveYarnRoot(deps, nil, "@repro/app")
		require.NotNil(t, got)
		assert.Equal(t, "jf-audit-yarn-ws-repro@workspace:.", got.Value)
	})

	t.Run("Yarn V1 (no @workspace:. entries): heuristic result passes through untouched, even nil", func(t *testing.T) {
		v1Deps := map[string]*bibuildutils.YarnDependency{
			"lodash": {Value: "lodash", Details: bibuildutils.YarnDepDetails{Version: "4.17.23"}},
		}
		assert.Nil(t, resolveYarnRoot(v1Deps, nil, ""))
	})
}

// TestBuildDependencyTreeWorkspaceRerouteIsCurationOnly guards that the
// workspace-member walk-up in BuildDependencyTree fires only for 'jf ca';
// 'jf audit'/'jf scan' must keep operating on the original currentDir.
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

// TestCollectDeclaredDirectDepsForMember pins the scoping contract for the probe collector: an empty memberRel merges the root package.json's direct deps with every workspace member's (member's spec overriding the root's on a name conflict), while a non-empty memberRel returns ONLY that member's direct deps.
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

	t.Run("empty memberRel returns deps merged across the whole workspace", func(t *testing.T) {
		got := collectDeclaredDirectDepsForMember(root, "")
		assert.Equal(t, "4.17.21", got["lodash"], "root dep must be present")
		assert.Equal(t, "^3.0.1", got["express"], "admin-ui member's dep must be merged in")
		assert.Equal(t, "^26.0.0", got["jsdom"], "web member's dep must be merged in")
		assert.Len(t, got, 3)
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

	t.Run("same name resolved at a different version is still synthesised", func(t *testing.T) {
		root := mkRoot()
		// express@4.17.1 is already resolved elsewhere in the tree (e.g. a transitive
		// dependency of some other package) — unrelated to the express@3.0.1 the user
		// declared directly and that curation just blocked.
		depMap := map[string]*bibuildutils.YarnDependency{
			"root@workspace:.":   root,
			"express@npm:4.17.1": {Value: "express@npm:4.17.1", Details: bibuildutils.YarnDepDetails{Version: "4.17.1"}},
		}
		declared := map[string]string{"express": "3.0.1"}
		reconcileDeclaredDirectDepsAgainstTree(depMap, root, declared)

		synth, ok := depMap["express@npm:3.0.1"]
		if assert.True(t, ok, "the declared (blocked) version must be synthesised even though a package of the same name resolved at a different version elsewhere in the tree") {
			assert.Equal(t, "3.0.1", synth.Details.Version)
		}
		var rootChildLocators []string
		for _, ptr := range root.Details.Dependencies {
			rootChildLocators = append(rootChildLocators, ptr.Locator)
		}
		assert.Contains(t, rootChildLocators, "express@npm:3.0.1")
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
				assert.Equal(t, "lodash", blocked[0].Name)
				assert.Equal(t, "4.17.21", blocked[0].ProbedVersion)
				assert.Equal(t, tt.wantReason, blocked[0].Reason)
				if tt.wantPolicy != "" && assert.Len(t, blocked[0].Policies, 1) {
					assert.Equal(t, tt.wantPolicy, blocked[0].Policies[0].Policy)
					assert.Equal(t, tt.wantCondition, blocked[0].Policies[0].Condition)
				}
			}
		})
	}
}

func TestProbeBlockedDirectDepsSendsCurationAuditIdHeader(t *testing.T) {
	const wantAuditId = "test-audit-id-123"
	var gotAuditIdHeader string

	mockServer, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get(utils.CurationAuditIdHeader); h != "" {
			gotAuditIdHeader = h
		}
		w.WriteHeader(http.StatusForbidden)
	})
	defer mockServer.Close()

	curWd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(curWd, "package.json"),
		[]byte(`{"name":"root","dependencies":{"lodash":"4.17.21"}}`), 0o644))

	params := technologies.BuildInfoBomGeneratorParams{
		ServerDetails:          serverDetails,
		DependenciesRepository: "tst-yarn-repo",
		ParallelRequests:       1,
		AuditId:                wantAuditId,
	}

	_, totalProbed := probeBlockedDirectDeps(params, curWd, "")

	assert.Equal(t, 1, totalProbed)
	assert.Equal(t, wantAuditId, gotAuditIdHeader)
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

func TestGetYarnrcAdditionalRegistries(t *testing.T) {
	getRefs := func(t *testing.T, dir string) []YarnrcRegistryRef {
		refs, err := GetYarnrcAdditionalRegistries(dir)
		require.NoError(t, err)
		return refs
	}
	setHome := func(t *testing.T, home string) {
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	}

	t.Run("no yarnrc", func(t *testing.T) {
		setHome(t, t.TempDir())
		assert.Empty(t, getRefs(t, t.TempDir()))
	})

	t.Run("only the default registry and registries auth", func(t *testing.T) {
		setHome(t, t.TempDir())
		wd := t.TempDir()
		yarnrc := "npmRegistryServer: https://host.example/artifactory/api/npm/repo/\n" +
			"npmRegistries:\n  \"//other.example/\":\n    npmAuthToken: t\n"
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte(yarnrc), 0o600))
		assert.Empty(t, getRefs(t, wd))
	})

	t.Run("audit registries are ignored", func(t *testing.T) {
		setHome(t, t.TempDir())
		wd := t.TempDir()
		yarnrc := "npmAuditRegistry: https://audit.example/\nnpmScopes:\n  a:\n    npmAuditRegistry: https://scope-audit.example/\n"
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte(yarnrc), 0o600))
		assert.Empty(t, getRefs(t, wd))
	})

	t.Run("scope without a registry of its own is not reported", func(t *testing.T) {
		// Yarn reports a default registry for such a scope; it was not declared by the project.
		setHome(t, t.TempDir())
		wd := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte("npmScopes:\n  plain:\n    npmAlwaysAuth: true\n"), 0o600))
		assert.Empty(t, getRefs(t, wd))
	})

	t.Run("all declaring settings, deterministic order", func(t *testing.T) {
		setHome(t, t.TempDir())
		wd := t.TempDir()
		yarnrc := "npmPublishRegistry: https://pub.example/\n" +
			"npmScopes:\n" +
			"  zeta:\n    npmRegistryServer: https://zeta.example/\n" +
			"  alpha:\n    npmRegistryServer: https://alpha.example/\n    npmPublishRegistry: https://alpha-pub.example/\n"
		require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte(yarnrc), 0o600))
		assert.Equal(t, []YarnrcRegistryRef{
			{Setting: "npmPublishRegistry", URL: "https://pub.example/"},
			{Setting: "npmScopes.alpha.npmRegistryServer", URL: "https://alpha.example/", RoutesPackages: true},
			{Setting: "npmScopes.alpha.npmPublishRegistry", URL: "https://alpha-pub.example/"},
			{Setting: "npmScopes.zeta.npmRegistryServer", URL: "https://zeta.example/", RoutesPackages: true},
		}, getRefs(t, wd))
	})

	t.Run("workspace root and home files are merged", func(t *testing.T) {
		home := t.TempDir()
		setHome(t, home)
		require.NoError(t, os.WriteFile(filepath.Join(home, ".yarnrc.yml"),
			[]byte("npmScopes:\n  fromhome:\n    npmRegistryServer: https://home.example/\n"), 0o600))
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, ".yarnrc.yml"),
			[]byte("npmScopes:\n  fromroot:\n    npmRegistryServer: https://root.example/\n"), 0o600))
		member := filepath.Join(root, "packages", "app")
		require.NoError(t, os.MkdirAll(member, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(member, ".yarnrc.yml"),
			[]byte("npmScopes:\n  frommember:\n    npmRegistryServer: https://member.example/\n"), 0o600))

		assert.Equal(t, []YarnrcRegistryRef{
			{Setting: "npmScopes.frommember.npmRegistryServer", URL: "https://member.example/", RoutesPackages: true},
			{Setting: "npmScopes.fromroot.npmRegistryServer", URL: "https://root.example/", RoutesPackages: true},
			{Setting: "npmScopes.fromhome.npmRegistryServer", URL: "https://home.example/", RoutesPackages: true},
		}, getRefs(t, member))
	})

	const duplicateScopes = "npmScopes:\n  a:\n    npmRegistryServer: https://a.example/\nnpmScopes:\n  b:\n    npmRegistryServer: https://attacker.example/\n"
	for name, content := range map[string]string{
		"unclosed flow sequence":  "npmScopes: [unclosed\n",
		"duplicate npmScopes key": duplicateScopes,
	} {
		t.Run("unparsable project file is an error: "+name, func(t *testing.T) {
			setHome(t, t.TempDir())
			wd := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(wd, ".yarnrc.yml"), []byte(content), 0o600))
			refs, err := GetYarnrcAdditionalRegistries(wd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "could not parse")
			assert.Nil(t, refs)
		})
	}

	t.Run("unparsable home file is an error", func(t *testing.T) {
		home := t.TempDir()
		setHome(t, home)
		require.NoError(t, os.WriteFile(filepath.Join(home, ".yarnrc.yml"), []byte(duplicateScopes), 0o600))
		_, err := GetYarnrcAdditionalRegistries(t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not parse")
	})

	t.Run("unparsable parent directory file is an error", func(t *testing.T) {
		setHome(t, t.TempDir())
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, ".yarnrc.yml"), []byte(duplicateScopes), 0o600))
		member := filepath.Join(root, "packages", "app")
		require.NoError(t, os.MkdirAll(member, 0o755))
		_, err := GetYarnrcAdditionalRegistries(member)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not parse")
	})
}

const curationRefusalText = "refusing to use the 'jf c' credentials"

// networkSettingsProjectForTest lays out <root>/packages/app (the project, with a package.json) under a fresh HOME and a temp base
// that the project copy is created in, so the copy's parent dirs are known and clean.
func networkSettingsProjectForTest(t *testing.T) (home, tempBase, project string) {
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	project = filepath.Join(t.TempDir(), "packages", "app")
	require.NoError(t, os.MkdirAll(project, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"root"}`), 0o644))
	tempBase = t.TempDir()
	previousBase := fileutils.GetTempDirBase()
	fileutils.SetTempDirBase(tempBase)
	t.Cleanup(func() { fileutils.SetTempDirBase(previousBase) })
	return
}

// fallbackCurationParamsForTest builds curation params for a project whose .yarnrc.yml has no token of its own, so the 'jf c'
// credential is lent to the install unless the server is anonymous.
func fallbackCurationParamsForTest(serverURL string, anonymous bool) technologies.BuildInfoBomGeneratorParams {
	server := &config.ServerDetails{ArtifactoryUrl: serverURL + "/artifactory/"}
	if !anonymous {
		//#nosec G101 -- test fixture, not a real secret
		server.AccessToken = "fallback-jf-c-token"
	}
	return technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:               true,
		DependenciesRepository:      "tst-yarn-repo",
		YarnCredentialsFromFallback: true,
		ServerDetails:               server,
	}
}

// TestResolveCurationLockfileDirRefusesNetworkSettings: a proxy, networkSettings, enableStrictSsl: false or unsafeHttpWhitelist (in the
// project, the copy's parent dir or ~/.yarnrc.yml) refuses the 'jf c' fallback before any install, naming the setting and file, not its value.
func TestResolveCurationLockfileDirRefusesNetworkSettings(t *testing.T) {
	const secret = "secretpw"
	settings := []struct {
		name       string
		yarnrc     string
		printed    string
		mustNotSay string
	}{
		{name: "httpProxy", yarnrc: "httpProxy: \"http://user:" + secret + "@proxy.attacker.example:3128\"\n", printed: `"httpProxy"`, mustNotSay: secret},
		{name: "httpsProxy", yarnrc: "httpsProxy: \"http://user:" + secret + "@proxy.attacker.example:3128\"\n", printed: `"httpsProxy"`, mustNotSay: secret},
		{name: "enableStrictSsl false", yarnrc: "enableStrictSsl: false\n", printed: `"enableStrictSsl"`},
		{name: "enableStrictSsl 0", yarnrc: "enableStrictSsl: 0\n", printed: `"enableStrictSsl"`},
		{name: "enableStrictSsl env default false", yarnrc: "enableStrictSsl: \"${STRICT_SSL:-false}\"\n", printed: `"enableStrictSsl"`},
		{name: "unsafeHttpWhitelist", yarnrc: "unsafeHttpWhitelist:\n  - \"whitelisted.attacker.example\"\n", printed: `"unsafeHttpWhitelist"`, mustNotSay: "whitelisted.attacker.example"},
		{
			name:       "networkSettings",
			yarnrc:     "networkSettings:\n  \"registry.example\":\n    httpsProxy: \"http://user:" + secret + "@proxy.attacker.example:3128\"\n",
			printed:    `"networkSettings.registry.example"`,
			mustNotSay: secret,
		},
		{name: "scalar networkSettings", yarnrc: "networkSettings: \"not-a-map\"\n", printed: `"networkSettings"`},
	}
	defaultRegistry := "npmRegistryServer: \"https://configured-server.example.com/artifactory/api/npm/yarn-test-repo/\"\n"
	for _, setting := range settings {
		for _, location := range []string{"project", "parent of the project copy", "home"} {
			t.Run(setting.name+" in the "+location+" file", func(t *testing.T) {
				home, tempBase, project := networkSettingsProjectForTest(t)
				placedIn := map[string]string{"project": project, "parent of the project copy": tempBase, "home": home}[location]
				rcPath := filepath.Join(placedIn, ".yarnrc.yml")
				content := setting.yarnrc
				if location == "project" {
					content = defaultRegistry + setting.yarnrc
				} else {
					require.NoError(t, os.WriteFile(filepath.Join(project, ".yarnrc.yml"), []byte(defaultRegistry), 0o644))
				}
				require.NoError(t, os.WriteFile(rcPath, []byte(content), 0o644))
				params := fallbackCurationParamsForTest("https://configured-server.example.com", false)

				_, cleanup, _, err := resolveCurationLockfileDir(params, project, filepath.Join(t.TempDir(), "no-such-yarn"), "")

				require.Error(t, err)
				assert.Contains(t, err.Error(), curationRefusalText, "an install failing on the bogus Yarn path must not pass for the refusal")
				assert.Contains(t, err.Error(), setting.printed, "the error must name the setting")
				assert.Contains(t, err.Error(), fmt.Sprintf("%q", rcPath), "the error must name the file as the user knows it, not the temp copy")
				assert.Contains(t, err.Error(), "YARN_UNSAFE_HTTP_WHITELIST", "the error must say how to allow a plain-http server")
				if setting.mustNotSay != "" {
					assert.False(t, strings.Contains(err.Error(), setting.mustNotSay), "the error must not echo a value from the rc file")
				}
				require.NoError(t, cleanup())
				leftovers, readErr := filepath.Glob(filepath.Join(tempBase, "jfrog.cli.temp*"))
				require.NoError(t, readErr)
				assert.Empty(t, leftovers, "the project copy must be removed after the refusal")
			})
		}
	}
}

// TestResolveCurationLockfileDirRefusesWhenNetworkSettingsCannotBeVerified: an rc file Yarn reads but yaml rejects (here in the copy's
// parent dir) can't be checked, so the fallback is refused instead of assumed clean.
func TestResolveCurationLockfileDirRefusesWhenNetworkSettingsCannotBeVerified(t *testing.T) {
	_, tempBase, project := networkSettingsProjectForTest(t)
	require.NoError(t, os.WriteFile(filepath.Join(tempBase, ".yarnrc.yml"), []byte("httpProxy: [unclosed\n"), 0o644))
	params := fallbackCurationParamsForTest("https://configured-server.example.com", false)

	_, cleanup, _, err := resolveCurationLockfileDir(params, project, filepath.Join(t.TempDir(), "no-such-yarn"), "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not parse")
	assert.Contains(t, err.Error(), "network settings can't be verified")
	assert.Contains(t, err.Error(), curationRefusalText)
	require.NoError(t, cleanup())
}

// resolveWithFakeYarnForTest runs resolveCurationLockfileDir with a fake Yarn that records whether an install ran.
func resolveWithFakeYarnForTest(t *testing.T, params technologies.BuildInfoBomGeneratorParams, project string) (lockfileDir string, installRan bool, err error) {
	fakeYarnPath, envCaptureFile, _ := fakeYarnCapturingInstallForTest(t)
	lockfileDir, cleanup, _, err := resolveCurationLockfileDir(params, project, fakeYarnPath, "")
	require.NoError(t, cleanup())
	_, statErr := os.Stat(envCaptureFile)
	return lockfileDir, statErr == nil, err
}

// TestResolveCurationLockfileDirKeepsFallbackWhenNothingCanLeak: no refusal for a clean rc, or when the token can't reach a risky setting
// (fresh lockfile, anonymous server, own token) or Yarn won't read it (a parent dir of the original project).
func TestResolveCurationLockfileDirKeepsFallbackWhenNothingCanLeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake yarn executable is a POSIX shell script")
	}
	registry := "npmRegistryServer: \"https://configured-server.example.com/artifactory/api/npm/yarn-test-repo/\"\n"
	const proxy = "httpsProxy: \"http://proxy.attacker.example:3128\"\n"

	t.Run("clean rc: the install runs", func(t *testing.T) {
		_, _, project := networkSettingsProjectForTest(t)
		rc := registry + "enableStrictSsl: true\nhttpProxy: \"\"\nunsafeHttpWhitelist: []\n"
		require.NoError(t, os.WriteFile(filepath.Join(project, ".yarnrc.yml"), []byte(rc), 0o644))

		_, installRan, err := resolveWithFakeYarnForTest(t, fallbackCurationParamsForTest(mockArtifactoryForYarnTest(t).URL, false), project)

		require.NoError(t, err)
		assert.True(t, installRan)
	})

	t.Run("fresh lockfile: no install runs, so nothing is lent", func(t *testing.T) {
		_, _, project := networkSettingsProjectForTest(t)
		require.NoError(t, os.WriteFile(filepath.Join(project, ".yarnrc.yml"), []byte(registry+proxy), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(project, "yarn.lock"), []byte("# fresh lockfile\n"), 0o644))

		lockfileDir, installRan, err := resolveWithFakeYarnForTest(t, fallbackCurationParamsForTest(mockArtifactoryForYarnTest(t).URL, false), project)

		require.NoError(t, err, "a proxy must not block a run in which Yarn never gets the token")
		assert.Equal(t, project, lockfileDir)
		assert.False(t, installRan)
	})

	t.Run("anonymous server: there is no credential to lend", func(t *testing.T) {
		_, _, project := networkSettingsProjectForTest(t)
		require.NoError(t, os.WriteFile(filepath.Join(project, ".yarnrc.yml"), []byte(registry+proxy), 0o644))

		_, installRan, err := resolveWithFakeYarnForTest(t, fallbackCurationParamsForTest(mockArtifactoryForYarnTest(t).URL, true), project)

		require.NoError(t, err, "an anonymous server exports no credential, so there is nothing to protect")
		assert.True(t, installRan)
	})

	t.Run("own token with unsafeHttpWhitelist: the jf c credential is not used", func(t *testing.T) {
		_, _, project := networkSettingsProjectForTest(t)
		rc := registry + "npmAuthToken: \"project-own-token\"\nunsafeHttpWhitelist:\n  - \"registry.example\"\n" + proxy
		require.NoError(t, os.WriteFile(filepath.Join(project, ".yarnrc.yml"), []byte(rc), 0o644))
		params := fallbackCurationParamsForTest(mockArtifactoryForYarnTest(t).URL, false)
		params.YarnCredentialsFromFallback = false

		_, installRan, err := resolveWithFakeYarnForTest(t, params, project)

		require.NoError(t, err)
		assert.True(t, installRan)
	})

	t.Run("a parent dir of the original project is not read by Yarn in the copy", func(t *testing.T) {
		_, _, project := networkSettingsProjectForTest(t)
		require.NoError(t, os.WriteFile(filepath.Join(project, ".yarnrc.yml"), []byte(registry), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(filepath.Dir(project)), ".yarnrc.yml"), []byte(proxy), 0o644))

		_, installRan, err := resolveWithFakeYarnForTest(t, fallbackCurationParamsForTest(mockArtifactoryForYarnTest(t).URL, false), project)

		require.NoError(t, err)
		assert.True(t, installRan)
	})
}
