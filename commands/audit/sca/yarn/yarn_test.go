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
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
)

func TestParseYarnDependenciesList(t *testing.T) {
	npmId := techutils.Npm.GetPackageTypeId()
	yarnDependencies := map[string]*bibuildutils.YarnDependency{
		"pack1@npm:1.0.0":        {Value: "pack1@npm:1.0.0", Details: bibuildutils.YarnDepDetails{Version: "1.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "pack4@npm:4.0.0"}}}},
		"pack2@npm:2.0.0":        {Value: "pack2@npm:2.0.0", Details: bibuildutils.YarnDepDetails{Version: "2.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "pack4@npm:4.0.0"}, {Locator: "pack5@npm:5.0.0"}}}},
		"@jfrog/pack3@npm:3.0.0": {Value: "@jfrog/pack3@npm:3.0.0", Details: bibuildutils.YarnDepDetails{Version: "3.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "pack1@virtual:c192f6b3b32cd5d11a443144e162ec3bc#npm:1.0.0"}, {Locator: "pack2@npm:2.0.0"}}}},
		"pack4@npm:4.0.0":        {Value: "pack4@npm:4.0.0", Details: bibuildutils.YarnDepDetails{Version: "4.0.0"}},
		"pack5@npm:5.0.0":        {Value: "pack5@npm:5.0.0", Details: bibuildutils.YarnDepDetails{Version: "5.0.0", Dependencies: []bibuildutils.YarnDependencyPointer{{Locator: "pack2@npm:2.0.0"}}}},
	}

	rootXrayId := npmId + "@jfrog/pack3:3.0.0"
	expectedTree := &xrayUtils.GraphNode{
		Id: rootXrayId,
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
	}
	expectedUniqueDeps := []string{npmId + "pack1:1.0.0", npmId + "pack2:2.0.0", npmId + "pack4:4.0.0", npmId + "pack5:5.0.0", npmId + "@jfrog/pack3:3.0.0"}

	xrayDependenciesTree, uniqueDeps := parseYarnDependenciesMap(yarnDependencies, rootXrayId)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
	assert.True(t, tests.CompareTree(expectedTree, xrayDependenciesTree), "expected:", expectedTree.Nodes, "got:", xrayDependenciesTree.Nodes)
}

func TestIsInstallRequired(t *testing.T) {
	tempDirPath, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	yarnProjectPath := filepath.Join("..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "yarn", "yarn-project")
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
	yarnProjectPath := filepath.Join("..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "yarn", "yarn-project")
	assert.NoError(t, biutils.CopyDir(yarnProjectPath, tempDirPath, true, nil))

	isTempDirEmpty, err := fileutils.IsDirEmpty(tempDirPath)
	assert.NoError(t, err)
	assert.False(t, isTempDirEmpty)

	executablePath, err := bibuildutils.GetYarnExecutable()
	assert.NoError(t, err)

	err = runYarnInstallAccordingToVersion(tempDirPath, executablePath, params)
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
			dirPath, cleanUp := sca.CreateTestWorkspace(t, test.testDir)
			defer cleanUp()

			expectedLockFilePath := filepath.Join(dirPath, "yarn.lock")
			exists, err := fileutils.IsFileExists(expectedLockFilePath, false)
			assert.NoError(t, err)

			if !test.shouldBeInstalled && exists {
				err = os.Remove(filepath.Join(dirPath, "yarn.lock"))
				assert.NoError(t, err)
			}

			params := (&utils.AuditBasicParams{}).SetSkipAutoInstall(true)
			if test.installCommand != "" {
				splitInstallCommand := strings.Split(test.installCommand, " ")
				params = params.SetInstallCommandName(splitInstallCommand[0]).SetInstallCommandArgs(splitInstallCommand[1:])
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
