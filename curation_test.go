package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/cli"
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
	if securityTests.ContainerRegistry == nil || *securityTests.ContainerRegistry == "" {
		t.Skip("Skipping Docker curation test - container registry not configured")
	}

	cleanUp := integration.UseTestHomeWithDefaultXrayConfig(t)
	defer cleanUp()
	integration.CreateJfrogHomeConfig(t, "", securityTests.XrDetails, true)
	loginCmd := exec.Command("docker", "login", *securityTests.ContainerRegistry, "-u", *securityTests.JfrogUser, "--password-stdin")
	loginCmd.Stdin = strings.NewReader(*securityTests.JfrogAccessToken)
	loginOutput, err := loginCmd.CombinedOutput()
	require.NoError(t, err, "Docker login failed: %s", string(loginOutput))

	testCli := integration.GetXrayTestCli(cli.GetJfrogCliSecurityApp(), false)

	testImage := fmt.Sprintf("%s/%s/%s", *securityTests.ContainerRegistry, "docker-curation", "ganodndentcom/drupal")

	output := testCli.WithoutCredentials().RunCliCmdWithOutput(t, "curation-audit",
		"--image="+testImage,
		"--format="+string(format.Json))

	bracketIndex := strings.Index(output, "[")
	require.GreaterOrEqual(t, bracketIndex, 0, "Expected JSON array in output, got: %s", output)

	var results []curation.PackageStatus
	err = json.Unmarshal([]byte(output[bracketIndex:]), &results)
	require.NoError(t, err)

	require.NotEmpty(t, results, "Expected at least one blocked package")
	assert.Equal(t, "blocked", results[0].Action)
	assert.Equal(t, "ganodndentcom/drupal", results[0].PackageName)
	assert.Equal(t, curation.BlockingReasonPolicy, results[0].BlockingReason)
	require.NotEmpty(t, results[0].Policy, "Expected at least one policy violation")
	assert.Equal(t, "Malicious package", results[0].Policy[0].Condition)
}

func curationServer(t *testing.T, expectedRequest map[string]bool, requestToFail map[string]bool) (*httptest.Server, *config.ServerDetails) {
	mapLockReadWrite := sync.Mutex{}
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
		}
		if r.Method == http.MethodGet {
			if r.RequestURI == "/api/system/version" {
				_, err := w.Write([]byte(`{"version": "7.0.0"}`))
				require.NoError(t, err)
				w.WriteHeader(http.StatusOK)
				return
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
