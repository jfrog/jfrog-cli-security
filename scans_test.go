package main

import (
	"encoding/json"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/formats"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/cli"
	"github.com/jfrog/jfrog-cli-security/cli/docs"
	"github.com/jfrog/jfrog-cli-security/commands/curation"
	"github.com/jfrog/jfrog-cli-security/commands/binaryscan"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/container"
	containerUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils/container"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"

	"github.com/jfrog/jfrog-cli-core/v2/common/build"
	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	commonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	"github.com/jfrog/jfrog-cli-security/softwarecomponents/scangraph"
	"github.com/jfrog/jfrog-cli-security/utils"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	clientTestUtils "github.com/jfrog/jfrog-client-go/utils/tests"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

// Binary scan tests

func TestXrayBinaryScanJson(t *testing.T) {
	output := testXrayBinaryScan(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}

func TestXrayBinaryScanSimpleJson(t *testing.T) {
	output := testXrayBinaryScan(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1)
}

func TestXrayBinaryScanJsonWithProgress(t *testing.T) {
	callback := commonTests.MockProgressInitialization()
	defer callback()
	output := testXrayBinaryScan(t, string(format.Json))
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}

func TestXrayBinaryScanSimpleJsonWithProgress(t *testing.T) {
	callback := commonTests.MockProgressInitialization()
	defer callback()
	output := testXrayBinaryScan(t, string(format.SimpleJson))
	securityTestUtils.VerifySimpleJsonScanResults(t, output, 1, 1)
}

func testXrayBinaryScan(t *testing.T, format string) string {
	securityTestUtils.InitSecurityTest(t, scangraph.GraphScanMinXrayVersion)
	binariesPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "binaries", "*")
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "scan", binariesPath, "--licenses", "--format="+format)
}

func TestXrayBinaryScanWithBypassArchiveLimits(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, binaryscan.BypassArchiveLimitsMinXrayVersion)
	unsetEnv := clientTestUtils.SetEnvWithCallbackAndAssert(t, "JF_INDEXER_COMPRESS_MAXENTITIES", "10")
	defer unsetEnv()
	binariesPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "binaries", "*")
	scanArgs := []string{"scan", binariesPath, "--format=json", "--licenses"}
	// Run without bypass flag and expect scan to fail
	err := securityTests.PlatformCli.Exec(scanArgs...)
	// Expect error
	assert.Error(t, err)

	// Run with bypass flag and expect it to find vulnerabilities
	scanArgs = append(scanArgs, "--bypass-archive-limits")
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, scanArgs...)
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}

// Docker scan tests

func TestDockerScanWithProgressBar(t *testing.T) {
	callback := commonTests.MockProgressInitialization()
	defer callback()
	TestDockerScan(t)
}

func TestDockerScan(t *testing.T) {
	cleanup := initNativeDockerWithXrayTest(t)
	defer cleanup()

	watchName, deleteWatch := createTestWatch(t)
	defer deleteWatch()

	imagesToScan := []string{
		// Simple image with vulnerabilities
		"bitnami/minio:2022",

		// Image with RPM with vulnerabilities
		"redhat/ubi8-micro:8.4",
	}
	for _, imageName := range imagesToScan {
		runDockerScan(t, imageName, watchName, 3, 3, 3)
	}

	// On Xray 3.40.3 there is a bug whereby xray fails to scan docker image with 0 vulnerabilities,
	// So we skip it for now till the next version will be released
	securityTestUtils.ValidateXrayVersion(t, "3.41.0")

	// Image with 0 vulnerabilities
	runDockerScan(t, "busybox:1.35", "", 0, 0, 0)
}

func initNativeDockerWithXrayTest(t *testing.T) func() {
	if !*securityTests.TestDockerScan || !*securityTests.TestSecurity {
		t.Skip("Skipping Docker scan test. To run Xray Docker test add the '-test.dockerScan=true' and '-test.security=true' options.")
	}
	oldHomeDir := os.Getenv(coreutils.HomeDir)
	securityTestUtils.ValidateXrayVersion(t, binaryscan.DockerScanMinXrayVersion)
	// Create server config to use with the command.
	securityTestUtils.CreateJfrogHomeConfig(t, true)
	// Add docker scan mock command
	securityTests.TestApplication.Commands = append(securityTests.TestApplication.Commands, dockerScanMockCommand(t))
	return func() {
		clientTestUtils.SetEnvAndAssert(t, coreutils.HomeDir, oldHomeDir)
		// remove docker scan mock command
		securityTests.TestApplication.Commands = securityTests.TestApplication.Commands[:len(securityTests.TestApplication.Commands)-1]
	}
}

func dockerScanMockCommand(t *testing.T) components.Command {
	return components.Command{
		Name:  "docker",
		Flags: docs.GetCommandFlags(docs.DockerScan),
		Action: func(c *components.Context) error {
			args := pluginsCommon.ExtractArguments(c)
			var cmd, image string
			// We may have prior flags before push/pull commands for the docker client.
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-") {
					if cmd == "" {
						cmd = arg
					} else {
						image = arg
						break
					}
				}
			}
			assert.Equal(t, "scan", cmd)
			return cli.DockerScan(c, image)
		},
	}
}

func runDockerScan(t *testing.T, imageName, watchName string, minViolations, minVulnerabilities, minLicenses int) {
	// Pull image from docker repo
	imageTag := path.Join(*securityTests.ContainerRegistry, securityTests.DockerVirtualRepo, imageName)
	dockerPullCommand := container.NewPullCommand(containerUtils.DockerClient)
	dockerPullCommand.SetCmdParams([]string{"pull", imageTag}).SetImageTag(imageTag).SetRepo(securityTests.DockerVirtualRepo).SetServerDetails(securityTests.XrDetails).SetBuildConfiguration(new(build.BuildConfiguration))
	if assert.NoError(t, dockerPullCommand.Run()) {
		defer commonTests.DeleteTestImage(t, imageTag, containerUtils.DockerClient)
		// Run docker scan on image
		cmdArgs := []string{"docker", "scan", imageTag, "--server-id=default", "--licenses", "--format=json", "--fail=false", "--min-severity=low", "--fixable-only"}
		output := securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, cmdArgs...)
		if assert.NotEmpty(t, output) {
			securityTestUtils.VerifyJsonScanResults(t, output, 0, minVulnerabilities, minLicenses)
		}
		// Run docker scan on image with watch
		if watchName == "" {
			return
		}
		cmdArgs = append(cmdArgs, "--watches="+watchName)
		output = securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, cmdArgs...)
		if assert.NotEmpty(t, output) {
			securityTestUtils.VerifyJsonScanResults(t, output, minViolations, 0, 0)
		}
	}
}

func createTestWatch(t *testing.T) (string, func()) {
	xrayManager, err := utils.CreateXrayServiceManager(securityTests.XrDetails)
	require.NoError(t, err)
	// Create new default policy.
	policyParams := xrayUtils.PolicyParams{
		Name: fmt.Sprintf("%s-%s", "docker-policy", strconv.FormatInt(time.Now().Unix(), 10)),
		Type: xrayUtils.Security,
		Rules: []xrayUtils.PolicyRule{{
			Name:     "sec_rule",
			Criteria: *xrayUtils.CreateSeverityPolicyCriteria(xrayUtils.Low),
			Priority: 1,
			Actions: &xrayUtils.PolicyAction{
				FailBuild: clientUtils.Pointer(true),
			},
		}},
	}
	if !assert.NoError(t, xrayManager.CreatePolicy(policyParams)) {
		return "", func() {}
	}
	// Create new default watch.
	watchParams := xrayUtils.NewWatchParams()
	watchParams.Name = fmt.Sprintf("%s-%s", "docker-watch", strconv.FormatInt(time.Now().Unix(), 10))
	watchParams.Active = true
	watchParams.Builds.Type = xrayUtils.WatchBuildAll
	watchParams.Policies = []xrayUtils.AssignedPolicy{
		{
			Name: policyParams.Name,
			Type: "security",
		},
	}
	assert.NoError(t, xrayManager.CreateWatch(watchParams))
	return watchParams.Name, func() {
		assert.NoError(t, xrayManager.DeleteWatch(watchParams.Name))
		assert.NoError(t, xrayManager.DeletePolicy(policyParams.Name))
	}
}

// JAS docker scan tests

func TestAdvancedSecurityDockerScan(t *testing.T) {
	cleanup := initNativeDockerWithXrayTest(t)
	defer cleanup()
	runAdvancedSecurityDockerScan(t, "jfrog/demo-security:latest")
}

func runAdvancedSecurityDockerScan(t *testing.T, imageName string) {
	// Pull image from docker repo
	imageTag := path.Join(*securityTests.ContainerRegistry, securityTests.DockerVirtualRepo, imageName)
	dockerPullCommand := container.NewPullCommand(containerUtils.DockerClient)
	dockerPullCommand.SetCmdParams([]string{"pull", imageTag}).SetImageTag(imageTag).SetRepo(securityTests.DockerVirtualRepo).SetServerDetails(securityTests.XrDetails).SetBuildConfiguration(new(build.BuildConfiguration))
	if assert.NoError(t, dockerPullCommand.Run()) {
		defer commonTests.DeleteTestImage(t, imageTag, containerUtils.DockerClient)
		args := []string{"docker", "scan", imageTag, "--server-id=default", "--format=simple-json", "--fail=false", "--min-severity=low", "--fixable-only"}

		// Run docker scan on image
		output := securityTests.PlatformCli.WithoutCredentials().RunCliCmdWithOutput(t, args...)
		if assert.NotEmpty(t, output) {
			verifyAdvancedSecurityScanResults(t, output)
		}
	}
}

func verifyAdvancedSecurityScanResults(t *testing.T, content string) {
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err)
	// Verify that the scan succeeded, and that at least one "Applicable" status was received.
	applicableStatusExists := false
	for _, vulnerability := range results.Vulnerabilities {
		if vulnerability.Applicable == string(utils.Applicable) {
			applicableStatusExists = true
			break
		}
	}
	assert.True(t, applicableStatusExists)

	// Verify that secretes detection succeeded.
	assert.NotEqual(t, 0, len(results.Secrets))

}

// Curation tests

func TestCurationAudit(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, "")
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	multiProject := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "projects", "package-managers", "npm")
	assert.NoError(t, biutils.CopyDir(multiProject, tempDirPath, true, nil))
	rootDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, os.Chdir(rootDir))
	}()
	require.NoError(t, os.Chdir(filepath.Join(tempDirPath, "npm")))
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
