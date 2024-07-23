package utils

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	configTests "github.com/jfrog/jfrog-cli-security/tests"
	"github.com/stretchr/testify/assert"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
)

func UnmarshalJson(t *testing.T, output string) formats.EnrichJson {
	var jsonMap formats.EnrichJson
	err := json.Unmarshal([]byte(output), &jsonMap)
	assert.NoError(t, err)
	return jsonMap
}

func UnmarshalXML(t *testing.T, output string) formats.Bom {
	var xmlMap formats.Bom
	err := xml.Unmarshal([]byte(output), &xmlMap)
	assert.NoError(t, err)
	return xmlMap
}

func InitSecurityTest(t *testing.T, xrayMinVersion string) {
	if !*configTests.TestSecurity {
		t.Skip("Skipping Security test. To run Security test add the '-test.security=true' option.")
	}
	ValidateXrayVersion(t, xrayMinVersion)
}

func ValidateXrayVersion(t *testing.T, minVersion string) {
	xrayVersion, err := getTestsXrayVersion()
	if err != nil {
		assert.NoError(t, err)
		return
	}
	err = clientUtils.ValidateMinimumVersion(clientUtils.Xray, xrayVersion.GetVersion(), minVersion)
	if err != nil {
		t.Skip(err)
	}
}

func ValidateXscVersion(t *testing.T, minVersion string) {
	xscVersion, err := getTestsXscVersion()
	if err != nil {
		t.Skip(err)
	}
	err = clientUtils.ValidateMinimumVersion(clientUtils.Xsc, xscVersion.GetVersion(), minVersion)
	if err != nil {
		t.Skip(err)
	}
}

func InitTestWithMockCommandOrParams(t *testing.T, mockCommands ...func(t *testing.T) components.Command) (mockCli *coreTests.JfrogCli, cleanUp func()) {
	oldHomeDir := os.Getenv(coreutils.HomeDir)
	// Create server config to use with the command.
	CreateJfrogHomeConfig(t, true)
	// Create mock cli with the mock commands.
	commands := []components.Command{}
	for _, mockCommand := range mockCommands {
		commands = append(commands, mockCommand(t))
	}
	return GetTestCli(components.CreateEmbeddedApp("security", commands)), func() {
		clientTests.SetEnvAndAssert(t, coreutils.HomeDir, oldHomeDir)
	}
}

func GetTestResourcesPath() string {
	dir, _ := os.Getwd()
	return filepath.ToSlash(dir + "/tests/testdata/")
}

func CleanTestsHomeEnv() {
	os.Unsetenv(coreutils.HomeDir)
	CleanFileSystem()
}

func CleanFileSystem() {
	removeDirs(configTests.Out, configTests.Temp)
}

func removeDirs(dirs ...string) {
	for _, dir := range dirs {
		isExist, err := fileutils.IsDirExists(dir, false)
		if err != nil {
			log.Error(err)
		}
		if isExist {
			err = fileutils.RemoveTempDir(dir)
			if err != nil {
				log.Error(errors.New("Cannot remove path: " + dir + " due to: " + err.Error()))
			}
		}
	}
}

func getTestsXrayVersion() (version.Version, error) {
	xrayVersion, err := configTests.XrAuth.GetVersion()
	return *version.NewVersion(xrayVersion), err
}

func getTestsXscVersion() (version.Version, error) {
	xscVersion, err := configTests.XscAuth.GetVersion()
	return *version.NewVersion(xscVersion), err
}

func ChangeWD(t *testing.T, newPath string) string {
	prevDir, err := os.Getwd()
	assert.NoError(t, err, "Failed to get current dir")
	clientTests.ChangeDirAndAssert(t, newPath)
	return prevDir
}

func ReadOutputFromFile(t *testing.T, path string) string {
	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	return filepath.FromSlash(strings.ReplaceAll(string(content), "\r\n", "\n"))
}

func CreateTestWatch(t *testing.T, policyName string, watchName, severity xrayUtils.Severity) (string, func()) {
	xrayManager, err := xray.CreateXrayServiceManager(configTests.XrDetails)
	require.NoError(t, err)
	// Create new default policy.
	policyParams := xrayUtils.PolicyParams{
		Name: fmt.Sprintf("%s-%s", policyName, strconv.FormatInt(time.Now().Unix(), 10)),
		Type: xrayUtils.Security,
		Rules: []xrayUtils.PolicyRule{{
			Name:     "sec_rule",
			Criteria: *xrayUtils.CreateSeverityPolicyCriteria(severity),
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
	watchParams.Name = fmt.Sprintf("%s-%s", watchName, strconv.FormatInt(time.Now().Unix(), 10))
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
