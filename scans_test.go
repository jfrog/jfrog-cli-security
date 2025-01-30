package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/commands/curation"
	"github.com/jfrog/jfrog-cli-security/commands/scan"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/validations"

	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/container"
	containerUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils/container"

	"github.com/jfrog/jfrog-cli-core/v2/common/build"
	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	commonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	clientTestUtils "github.com/jfrog/jfrog-client-go/utils/tests"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

// Binary scan tests

func TestXrayBinaryScanJson(t *testing.T) {
	integration.InitScanTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayBinaryScan(t, string(format.Json), "", "")
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

func TestXrayBinaryScanSimpleJson(t *testing.T) {
	integration.InitScanTest(t, scangraph.GraphScanMinXrayVersion)
	output := testXrayBinaryScan(t, string(format.SimpleJson), "xray-scan-binary-policy", "scan-binary-watch")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1, Violations: 1},
	})
}

func TestXrayBinaryScanJsonWithProgress(t *testing.T) {
	integration.InitScanTest(t, scangraph.GraphScanMinXrayVersion)
	callback := commonTests.MockProgressInitialization()
	defer callback()
	output := testXrayBinaryScan(t, string(format.Json), "", "")
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

func TestXrayBinaryScanSimpleJsonWithProgress(t *testing.T) {
	integration.InitScanTest(t, scangraph.GraphScanMinXrayVersion)
	callback := commonTests.MockProgressInitialization()
	defer callback()
	output := testXrayBinaryScan(t, string(format.SimpleJson), "xray-scan-binary-progress-policy", "scan-binary-progress-watch")
	validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1, Violations: 1},
	})
}

func testXrayBinaryScan(t *testing.T, format, policyName, watchName string) string {
	binariesPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "binaries", "*")
	args := []string{"scan", binariesPath, "--licenses", "--format=" + format}
	if policyName != "" && watchName != "" {
		watchName, deleteWatch := securityTestUtils.CreateTestPolicyAndWatch(t, "xray-scan-binary-policy", "scan-binary-watch", xrayUtils.High)
		defer deleteWatch()
		// Include violations and vulnerabilities
		args = append(args, "--watches="+watchName, "--vuln")
	}
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, args...)
}

func TestXrayBinaryScanWithBypassArchiveLimits(t *testing.T) {
	integration.InitScanTest(t, scan.BypassArchiveLimitsMinXrayVersion)
	unsetEnv := clientTestUtils.SetEnvWithCallbackAndAssert(t, "JF_INDEXER_COMPRESS_MAXENTITIES", "10")
	defer unsetEnv()
	binariesPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "binaries", "*")
	scanArgs := []string{"scan", binariesPath, "--format=json", "--licenses"}
	// Run without bypass flag and expect scan to fail
	err := securityTests.PlatformCli.Exec(scanArgs...)
	// Expect error
	assert.Error(t, err)

	// Run with bypass flag and expect it to find vulnerabilities
	scanArgs = append(scanArgs, "--bypass-archive-limits")
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, scanArgs...)
	validations.VerifyJsonResults(t, output, validations.ValidationParams{
		Total: &validations.TotalCount{Licenses: 1, Vulnerabilities: 1},
	})
}

// Docker scan tests

func TestDockerScanWithProgressBar(t *testing.T) {
	callback := commonTests.MockProgressInitialization()
	defer callback()
	TestDockerScan(t)
}

func TestDockerScanWithTokenValidation(t *testing.T) {
	integration.InitScanTest(t, jasutils.DynamicTokenValidationMinXrayVersion)
	testCli, cleanup := integration.InitNativeDockerTest(t)
	defer cleanup()
	// #nosec G101 -- Image with dummy token for tests
	tokensImageToScan := "srmishj/inactive_tokens:latest"
	runDockerScan(t, testCli, tokensImageToScan, "", 0, 0, 0, 5, true)
}

func TestDockerScan(t *testing.T) {
	integration.InitScanTest(t, "")
	testCli, cleanup := integration.InitNativeDockerTest(t)
	defer cleanup()

	watchName, deleteWatch := securityTestUtils.CreateTestPolicyAndWatch(t, "docker-policy", "docker-watch", xrayUtils.Low)
	defer deleteWatch()

	imagesToScan := []string{
		// Simple image with vulnerabilities
		"bitnami/minio:2022",

		// Image with RPM with vulnerabilities
		"redhat/ubi8-micro:8.4",
	}
	for _, imageName := range imagesToScan {
		runDockerScan(t, testCli, imageName, watchName, 3, 3, 3, 0, false)
	}

	// Image with 0 vulnerabilities
	runDockerScan(t, testCli, "busybox:1.35", "", 0, 0, 0, 0, false)
}

func runDockerScan(t *testing.T, testCli *coreTests.JfrogCli, imageName, watchName string, minViolations, minVulnerabilities, minLicenses int, minInactives int, validateSecrets bool) {
	// Pull image from docker repo
	imageTag := path.Join(*securityTests.ContainerRegistry, securityTests.DockerVirtualRepo, imageName)
	dockerPullCommand := container.NewPullCommand(containerUtils.DockerClient)
	dockerPullCommand.SetCmdParams([]string{"pull", imageTag}).SetImageTag(imageTag).SetRepo(securityTests.DockerVirtualRepo).SetServerDetails(securityTests.XrDetails).SetBuildConfiguration(new(build.BuildConfiguration))
	if assert.NoError(t, dockerPullCommand.Run()) {
		defer commonTests.DeleteTestImage(t, imageTag, containerUtils.DockerClient)
		// Run docker scan on image
		cmdArgs := []string{"docker", "scan", imageTag, "--server-id=default", "--licenses", "--fail=false", "--min-severity=low", "--fixable-only"}
		if validateSecrets {
			cmdArgs = append(cmdArgs, "--validate-secrets", "--format=simple-json")
		} else {
			cmdArgs = append(cmdArgs, "--format=json")
		}
		output := testCli.WithoutCredentials().RunCliCmdWithOutput(t, cmdArgs...)
		if assert.NotEmpty(t, output) {
			if validateSecrets {
				validations.VerifySimpleJsonResults(t, output, validations.ValidationParams{
					Vulnerabilities: &validations.VulnerabilityCount{ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Inactive: minInactives}},
				})
			} else {
				validations.VerifyJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Vulnerabilities: minVulnerabilities, Licenses: minLicenses}})
			}
		}
		// Run docker scan on image with watch
		if watchName == "" {
			return
		}
		cmdArgs = append(cmdArgs, "--watches="+watchName)
		output = testCli.WithoutCredentials().RunCliCmdWithOutput(t, cmdArgs...)
		if assert.NotEmpty(t, output) {
			validations.VerifyJsonResults(t, output, validations.ValidationParams{Total: &validations.TotalCount{Violations: minViolations}})
		}
	}
}

// JAS docker scan tests

func TestAdvancedSecurityDockerScan(t *testing.T) {
	integration.InitScanTest(t, "")
	testCli, cleanup := integration.InitNativeDockerTest(t)
	defer cleanup()
	runAdvancedSecurityDockerScan(t, testCli, "jfrog/demo-security:latest")
}

func runAdvancedSecurityDockerScan(t *testing.T, testCli *coreTests.JfrogCli, imageName string) {
	// Pull image from docker repo
	imageTag := path.Join(*securityTests.ContainerRegistry, securityTests.DockerVirtualRepo, imageName)
	dockerPullCommand := container.NewPullCommand(containerUtils.DockerClient)
	dockerPullCommand.SetCmdParams([]string{"pull", imageTag}).SetImageTag(imageTag).SetRepo(securityTests.DockerVirtualRepo).SetServerDetails(securityTests.XrDetails).SetBuildConfiguration(new(build.BuildConfiguration))
	if assert.NoError(t, dockerPullCommand.Run()) {
		defer commonTests.DeleteTestImage(t, imageTag, containerUtils.DockerClient)
		args := []string{"docker", "scan", imageTag, "--server-id=default", "--format=simple-json", "--fail=false", "--min-severity=low", "--fixable-only"}

		// Run docker scan on image
		output := testCli.WithoutCredentials().RunCliCmdWithOutput(t, args...)
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
		if vulnerability.Applicable == string(jasutils.Applicable) {
			applicableStatusExists = true
			break
		}
	}
	assert.True(t, applicableStatusExists)

	// Verify that secretes detection succeeded.
	assert.NotEqual(t, 0, len(results.SecretsVulnerabilities))

}

// Curation tests

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
