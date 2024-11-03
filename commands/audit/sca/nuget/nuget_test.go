package nuget

import (
	"encoding/json"
	"github.com/jfrog/build-info-go/build/utils/dotnet/solution"
	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	xrayUtils2 "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/build-info-go/entities"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/stretchr/testify/assert"
)

var testDataDir = filepath.Join("..", "..", "..", "..", "tests", "testdata", "projects", "package-managers")

func TestBuildNugetDependencyTree(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("other", "nuget"))
	defer cleanUp()
	dependenciesJson, err := os.ReadFile("dependencies.json")
	assert.NoError(t, err)

	var dependencies *entities.BuildInfo
	err = json.Unmarshal(dependenciesJson, &dependencies)
	assert.NoError(t, err)
	expectedUniqueDeps := []string{
		nugetPackageTypeIdentifier + "Microsoft.Net.Http:2.2.29",
		nugetPackageTypeIdentifier + "Microsoft.Bcl:1.1.10",
		nugetPackageTypeIdentifier + "Microsoft.Bcl.Build:1.0.14",
		nugetPackageTypeIdentifier + "Newtonsoft.Json:11.0.2",
		nugetPackageTypeIdentifier + "NUnit:3.10.1",
		nugetPackageTypeIdentifier + "bootstrap:4.1.1",
		nugetPackageTypeIdentifier + "popper.js:1.14.0",
		nugetPackageTypeIdentifier + "jQuery:3.0.0",
		nugetPackageTypeIdentifier + "MsbuildExample",
		nugetPackageTypeIdentifier + "MsbuildLibrary",
	}
	xrayDependenciesTree, uniqueDeps := parseNugetDependencyTree(dependencies)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
	expectedTreeJson, err := os.ReadFile("expectedTree.json")
	assert.NoError(t, err)

	var expectedTrees *[]xrayUtils.GraphNode
	err = json.Unmarshal(expectedTreeJson, &expectedTrees)
	assert.NoError(t, err)

	for i := range *expectedTrees {
		expectedTree := &(*expectedTrees)[i]
		assert.True(t, tests.CompareTree(expectedTree, xrayDependenciesTree[i]), "expected:", expectedTree.Nodes, "got:", xrayDependenciesTree[i].Nodes)
	}
}

func TestGetProjectToolName(t *testing.T) {
	testCases := []struct {
		testProjectName string
		expectedOutput  string
	}{
		{testProjectName: "dotnet-single", expectedOutput: "dotnet"},
		{testProjectName: "dotnet-single", expectedOutput: "nuget"},
		{testProjectName: "dotnet-multi", expectedOutput: "dotnet"},
	}

	for _, testcase := range testCases {
		tempDirPath, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
		defer createTempDirCallback()
		dotnetProjectPath := filepath.Join(testDataDir, "dotnet", testcase.testProjectName)
		assert.NoError(t, utils.CopyDir(dotnetProjectPath, tempDirPath, true, nil))

		// This phase designates the project as an 'old NuGet project' utilizing packages.config instead of <PackageReference> for dependency definition
		if testcase.expectedOutput == "nuget" {
			assert.NoError(t, os.Remove(filepath.Join(tempDirPath, testcase.testProjectName+".csproj")))
			tempFile, err := os.Create(filepath.Join(tempDirPath, "packages.config"))
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, tempFile.Close())
			}()
		}

		toolName, err := getProjectToolName(tempDirPath)
		assert.NoError(t, err)
		assert.Equal(t, testcase.expectedOutput, toolName)
	}

	// Verifies for errors if neither .csproj files nor packages.config files were detected
	emptyProject, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	toolName, err := getProjectToolName(emptyProject)
	assert.Empty(t, toolName)
	assert.Error(t, err)
}

func TestGetProjectConfigurationFilesPaths(t *testing.T) {
	dotnetProjectPath, err := filepath.Abs(filepath.Join(testDataDir, "dotnet"))
	assert.NoError(t, err)

	testCases := []struct {
		testProjectPath string
		expectedOutput  []string
	}{
		{
			testProjectPath: filepath.Join(dotnetProjectPath, "dotnet-single"),
			expectedOutput: []string{
				filepath.Join(dotnetProjectPath, "dotnet-single", "dotnet-single.csproj"),
			},
		},
		{
			testProjectPath: filepath.Join(dotnetProjectPath, "dotnet-multi"),
			expectedOutput: []string{
				filepath.Join(dotnetProjectPath, "dotnet-multi", "ClassLibrary1", "ClassLibrary1.csproj"),
				filepath.Join(dotnetProjectPath, "dotnet-multi", "TestApp1", "TestApp1.csproj"),
			},
		},
	}

	for _, testcase := range testCases {
		var projectFiles []string
		projectFiles, err = getProjectConfigurationFilesPaths(testcase.testProjectPath)
		assert.NoError(t, err)
		assert.Equal(t, testcase.expectedOutput, projectFiles)
	}
}

func TestRunDotnetRestoreAndLoadSolution(t *testing.T) {
	projectsToCheck := []string{"dotnet-single", "dotnet-multi"}
	for _, projectName := range projectsToCheck {
		tempDirPath, createTempDirCallback := tests.CreateTempDirWithCallbackAndAssert(t)
		defer createTempDirCallback()
		dotnetProjectPath := filepath.Join(testDataDir, "dotnet", projectName)
		assert.NoError(t, utils.CopyDir(dotnetProjectPath, tempDirPath, true, nil))

		sol, err := solution.Load(tempDirPath, "", "", log.Logger)
		assert.NoError(t, err)
		assert.Empty(t, sol.GetProjects())
		assert.Empty(t, sol.GetDependenciesSources())

		params := &xrayUtils2.AuditBasicParams{}
		sol, err = runDotnetRestoreAndLoadSolution(params, tempDirPath, "")
		assert.NoError(t, err)
		assert.NotEmpty(t, sol.GetProjects())
		assert.NotEmpty(t, sol.GetDependenciesSources())
	}
}

// This test checks that the tree construction is skipped when the project is not installed and the user prohibited installation
func TestSkipBuildDepTreeWhenInstallForbidden(t *testing.T) {
	testCases := []struct {
		name                        string
		testDir                     string
		installCommand              string
		successfulTreeBuiltExpected bool
	}{
		{
			name:                        "nuget single 4.0  - installed | install not required",
			testDir:                     filepath.Join("projects", "package-managers", "nuget", "single4.0"),
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "nuget single 5.0  - not installed | install required - install command",
			testDir:                     filepath.Join("projects", "package-managers", "nuget", "single5.0"),
			installCommand:              "nuget restore", // todo test in ci with nuget restore
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "nuget single 5.0  - not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "nuget", "single5.0"),
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "nuget multi  - not installed | install required - install command",
			testDir:                     filepath.Join("projects", "package-managers", "nuget", "multi"),
			installCommand:              "nuget restore", // todo test in ci with nuget restore
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "nuget multi  - not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "nuget", "multi"),
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "dotnet-single  - not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "dotnet", "dotnet-single"),
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "dotnet-multi  - not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "dotnet", "dotnet-multi"),
			successfulTreeBuiltExpected: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Create and change directory to test workspace
			_, cleanUp := sca.CreateTestWorkspace(t, test.testDir)
			defer cleanUp()

			params := (&xrayUtils2.AuditBasicParams{}).SetSkipAutoInstall(true)
			if test.installCommand != "" {
				splitInstallCommand := strings.Split(test.installCommand, " ")
				params = params.SetInstallCommandName(splitInstallCommand[0]).SetInstallCommandArgs(splitInstallCommand[1:])
			}

			dependencyTrees, uniqueDeps, err := BuildDependencyTree(params)
			if !test.successfulTreeBuiltExpected {
				assert.Nil(t, dependencyTrees)
				assert.Nil(t, uniqueDeps)
				assert.Error(t, err)
				assert.IsType(t, &utils.ErrProjectNotInstalled{}, err)
			} else {
				assert.NotNil(t, dependencyTrees)
				assert.NotNil(t, uniqueDeps)
				assert.NoError(t, err)
			}
		})
	}
}
