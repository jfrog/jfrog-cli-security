package curation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	coreCommonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clienttestutils "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// curationBlockedHFResponse is the Artifactory 403 body for a blocked HF model.
const curationBlockedHFResponse = `{"errors":[{"status":403,"message":"Package download was blocked by JFrog Packages Curation service due to the following policies violated {blocks-unknown-license, Package has no identified license, Package license is unidentified, Please replace it with an alternate package}"}]}`

// TestHuggingFaceCurationAuditAutoDiscovery verifies HF model auto-discovery from source.
func TestHuggingFaceCurationAuditAutoDiscovery(t *testing.T) {
	cleanUpFlags := setCurationFlagsForTest(t)
	defer cleanUpFlags()

	projectDir := t.TempDir()
	pyContent := "from transformers import AutoModel\n" +
		"model = AutoModel.from_pretrained(\"org/blocked-model\", revision=\"v1.0\")\n"
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "app.py"), []byte(pyContent), 0o644))

	const (
		hfRepo        = "hf-local-repo"
		modelProbeURL = "/api/huggingfaceml/" + hfRepo + "/api/models/org/blocked-model/revision/v1.0"
	)
	expectedRequest := map[string]bool{modelProbeURL: false}
	requestToFail := map[string]bool{modelProbeURL: false}

	mockServer, serverConfig := hfMockServer(t, expectedRequest, requestToFail, hfRepo)
	defer mockServer.Close()

	tempHomeDir, cleanUpHome := createHFTestHome(t, serverConfig)
	defer cleanUpHome()
	callbackHomeDir := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempHomeDir)
	defer callbackHomeDir()

	t.Setenv("HF_ENDPOINT", serverConfig.ArtifactoryUrl+"api/huggingfaceml/"+hfRepo)

	curationCmd := NewCurationAuditCommand()
	curationCmd.SetServerDetails(serverConfig)
	curationCmd.SetIsCurationCmd(true)
	curationCmd.SetInsecureTls(true)
	curationCmd.SetWorkingDirs([]string{projectDir})
	curationCmd.OriginPath = projectDir // scan the temp project, not "."

	results := map[string]*CurationReport{}
	require.NoError(t, curationCmd.doCurateAudit(results))

	var blocked []*PackageStatus
	for _, report := range results {
		for _, pkg := range report.packagesStatus {
			if pkg.Action == "blocked" {
				blocked = append(blocked, pkg)
			}
		}
	}
	require.Len(t, blocked, 1, "expected exactly one blocked HF model")
	assert.Equal(t, "org/blocked-model", blocked[0].PackageName)
	assert.Equal(t, "v1.0", blocked[0].PackageVersion)
	assert.Equal(t, "huggingfaceml", blocked[0].PkgType)
	assert.Equal(t, BlockingReasonPolicy, blocked[0].BlockingReason)
	for k, v := range expectedRequest {
		assert.Truef(t, v, "expected HEAD probe for %s", k)
	}
}

// TestHuggingFaceCurationAuditAutoDiscovery_CleanModelWithWarning is a regression test for
// a bug where a real (non-blocked) audited model, combined with any warning (here: a
// skipped, unparsable notebook), got silently dropped from the results table. packagesStatus
// only ever holds blocked packages, so an all-clean audit also has it empty — identical in
// shape to the "nothing was audited" placeholder. isWarningsOnlyReport must tell the two
// apart using totalNumberOfPackages, which itself must count the real dependency (not
// undercount to 0 by assuming every tech's FlatTree.Nodes includes a root self-entry, which
// Hugging Face's BuildDependencyTree does not add).
func TestHuggingFaceCurationAuditAutoDiscovery_CleanModelWithWarning(t *testing.T) {
	cleanUpFlags := setCurationFlagsForTest(t)
	defer cleanUpFlags()

	projectDir := t.TempDir()
	pyContent := "from transformers import AutoModel\n" +
		"model = AutoModel.from_pretrained(\"org/clean-model\")\n"
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "app.py"), []byte(pyContent), 0o644))
	// Unparsable notebook triggers a skipped-file warning alongside the clean model audit.
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "broken.ipynb"), []byte("not json"), 0o644))

	const (
		hfRepo        = "hf-local-repo"
		modelProbeURL = "/api/huggingfaceml/" + hfRepo + "/api/models/org/clean-model/revision/main"
	)
	expectedRequest := map[string]bool{modelProbeURL: false}
	requestToFail := map[string]bool{} // no entry => probe returns 200 OK (not blocked)

	mockServer, serverConfig := hfMockServer(t, expectedRequest, requestToFail, hfRepo)
	defer mockServer.Close()

	tempHomeDir, cleanUpHome := createHFTestHome(t, serverConfig)
	defer cleanUpHome()
	callbackHomeDir := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempHomeDir)
	defer callbackHomeDir()

	t.Setenv("HF_ENDPOINT", serverConfig.ArtifactoryUrl+"api/huggingfaceml/"+hfRepo)

	curationCmd := NewCurationAuditCommand()
	curationCmd.SetServerDetails(serverConfig)
	curationCmd.SetIsCurationCmd(true)
	curationCmd.SetInsecureTls(true)
	curationCmd.SetWorkingDirs([]string{projectDir})
	curationCmd.OriginPath = projectDir

	results := map[string]*CurationReport{}
	require.NoError(t, curationCmd.doCurateAudit(results))

	require.Len(t, results, 1, "expected a single report for the audited project, not the warnings-only placeholder")
	var report *CurationReport
	for _, r := range results {
		report = r
	}
	assert.Empty(t, report.packagesStatus, "the clean model isn't blocked, so packagesStatus stays empty")
	assert.NotEmpty(t, report.warnings, "expected the skipped-file warning to be attached")
	assert.Equal(t, 1, report.totalNumberOfPackages, "the clean model must still be counted, not undercounted to 0")
	assert.False(t, isWarningsOnlyReport(report), "a report with a real audited package must not be treated as warnings-only")
	for k, v := range expectedRequest {
		assert.Truef(t, v, "expected HEAD probe for %s", k)
	}
}

// TestHuggingFaceCurationAuditExplicitModel verifies the --hugging-face-model spot-check.
func TestHuggingFaceCurationAuditExplicitModel(t *testing.T) {
	cleanUpFlags := setCurationFlagsForTest(t)
	defer cleanUpFlags()

	projectDir := t.TempDir()

	const (
		hfRepo        = "hf-local-repo"
		modelProbeURL = "/api/huggingfaceml/" + hfRepo + "/api/models/org/explicit-model/revision/main"
	)
	expectedRequest := map[string]bool{modelProbeURL: false}
	requestToFail := map[string]bool{modelProbeURL: false}

	mockServer, serverConfig := hfMockServer(t, expectedRequest, requestToFail, hfRepo)
	defer mockServer.Close()

	tempHomeDir, cleanUpHome := createHFTestHome(t, serverConfig)
	defer cleanUpHome()
	callbackHomeDir := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempHomeDir)
	defer callbackHomeDir()

	t.Setenv("HF_ENDPOINT", serverConfig.ArtifactoryUrl+"api/huggingfaceml/"+hfRepo)

	curationCmd := NewCurationAuditCommand()
	curationCmd.SetServerDetails(serverConfig)
	curationCmd.SetIsCurationCmd(true)
	curationCmd.SetInsecureTls(true)
	curationCmd.SetWorkingDirs([]string{projectDir})
	curationCmd.SetHuggingFaceModel("org/explicit-model")

	results := map[string]*CurationReport{}
	require.NoError(t, curationCmd.doCurateAudit(results))

	var blocked []*PackageStatus
	for _, report := range results {
		for _, pkg := range report.packagesStatus {
			if pkg.Action == "blocked" {
				blocked = append(blocked, pkg)
			}
		}
	}
	require.Len(t, blocked, 1, "expected exactly one blocked HF model")
	assert.Equal(t, "org/explicit-model", blocked[0].PackageName)
	assert.Equal(t, "main", blocked[0].PackageVersion)
	assert.Equal(t, "huggingfaceml", blocked[0].PkgType)
	assert.Equal(t, BlockingReasonPolicy, blocked[0].BlockingReason)
	for k, v := range expectedRequest {
		assert.Truef(t, v, "expected HEAD probe for %s", k)
	}
}

// TestHuggingFaceCurationAuditRun_MultipleRelativeWorkingDirs verifies that each
// entry in --working-dirs is resolved to an absolute path against the original
// root directory, not against the previous entry's cwd. Run() chdir's into each
// working dir in turn; resolving the next (relative) entry inside that loop,
// after the previous chdir, would incorrectly nest it under the prior directory
// (e.g. "b/model" resolving to ".../a/model/b/model") — a nonexistent path here,
// so it also silently drops HF root-node disambiguation for every entry past the
// first when directories share a basename.
func TestHuggingFaceCurationAuditRun_MultipleRelativeWorkingDirs(t *testing.T) {
	cleanUpFlags := setCurationFlagsForTest(t)
	defer cleanUpFlags()

	rootDir := t.TempDir()
	dirA := filepath.Join(rootDir, "a", "model")
	dirB := filepath.Join(rootDir, "b", "model")
	require.NoError(t, os.MkdirAll(dirA, 0o755))
	require.NoError(t, os.MkdirAll(dirB, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dirA, "app.py"),
		[]byte("from transformers import AutoModel\nmodel = AutoModel.from_pretrained(\"org/model-a\")\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dirB, "app.py"),
		[]byte("from transformers import AutoModel\nmodel = AutoModel.from_pretrained(\"org/model-b\")\n"), 0o644))

	const (
		hfRepo = "hf-local-repo"
		probeA = "/api/huggingfaceml/" + hfRepo + "/api/models/org/model-a/revision/main"
		probeB = "/api/huggingfaceml/" + hfRepo + "/api/models/org/model-b/revision/main"
	)
	expectedRequest := map[string]bool{probeA: false, probeB: false}
	requestToFail := map[string]bool{}

	mockServer, serverConfig := hfMockServer(t, expectedRequest, requestToFail, hfRepo)
	defer mockServer.Close()

	tempHomeDir, cleanUpHome := createHFTestHome(t, serverConfig)
	defer cleanUpHome()
	callbackHomeDir := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempHomeDir)
	defer callbackHomeDir()

	t.Setenv("HF_ENDPOINT", serverConfig.ArtifactoryUrl+"api/huggingfaceml/"+hfRepo)
	t.Chdir(rootDir)

	curationCmd := NewCurationAuditCommand()
	curationCmd.SetServerDetails(serverConfig)
	curationCmd.SetIsCurationCmd(true)
	curationCmd.SetInsecureTls(true)
	// Relative to rootDir (the cwd at Run() start) — this is exactly the shape that
	// triggers the bug: two relative dirs sharing a basename ("model").
	curationCmd.SetWorkingDirs([]string{filepath.Join("a", "model"), filepath.Join("b", "model")})

	require.NoError(t, curationCmd.Run())

	for k, v := range expectedRequest {
		assert.Truef(t, v, "expected HEAD probe for %s", k)
	}
}

// hfMockServer mocks Artifactory HEAD/GET probes and the repo-exists check for HF tests.
func hfMockServer(t *testing.T, expectedRequest, requestToFail map[string]bool, hfRepo string) (*httptest.Server, *config.ServerDetails) {
	mapLock := sync.Mutex{}
	serverMock, serverConfig, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			mapLock.Lock()
			if _, ok := expectedRequest[r.RequestURI]; ok {
				expectedRequest[r.RequestURI] = true
			}
			mapLock.Unlock()
			if _, ok := requestToFail[r.RequestURI]; ok {
				w.WriteHeader(http.StatusForbidden)
			}
		case http.MethodGet:
			switch r.RequestURI {
			case "/api/system/version":
				_, err := w.Write([]byte(`{"version": "7.82.0"}`))
				require.NoError(t, err)
			case "/api/v1/system/version":
				_, err := w.Write([]byte(`{"xray_version": "3.92.0"}`))
				require.NoError(t, err)
			case "/api/repositories/" + hfRepo:
				w.WriteHeader(http.StatusOK)
			default:
				if _, ok := requestToFail[r.RequestURI]; ok {
					w.WriteHeader(http.StatusForbidden)
					_, err := w.Write([]byte(curationBlockedHFResponse))
					require.NoError(t, err)
				}
			}
		}
	})
	return serverMock, serverConfig
}

// createHFTestHome writes a temp JFrog home with a default server config for the mock.
func createHFTestHome(t *testing.T, serverConfig *config.ServerDetails) (string, func()) {
	tempHomeDir, err := fileutils.CreateTempDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(tempHomeDir, ".jfrog"), 0o777))

	cfgVersion := coreutils.GetCliConfigVersion()
	conf := config.ConfigV5{
		Servers: []*config.ServerDetails{
			{
				ServerId:       "test",
				User:           "admin",
				Password:       "password",
				Url:            serverConfig.ArtifactoryUrl,
				ArtifactoryUrl: serverConfig.ArtifactoryUrl,
				IsDefault:      true,
			},
		},
		Version: "v" + strconv.Itoa(cfgVersion),
	}
	confBytes, err := json.Marshal(conf)
	require.NoError(t, err)
	confPath := filepath.Join(tempHomeDir, "jfrog-cli.conf.v"+strconv.Itoa(cfgVersion))
	require.NoError(t, os.WriteFile(confPath, confBytes, 0o644))

	return tempHomeDir, func() {
		_ = fileutils.RemoveTempDir(tempHomeDir)
	}
}
