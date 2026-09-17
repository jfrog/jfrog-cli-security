package nuget

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	bidotnet "github.com/jfrog/build-info-go/build/utils/dotnet"
	"github.com/jfrog/build-info-go/build/utils/dotnet/solution"
	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/build-info-go/entities"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
)

var testDataDir = filepath.Join("..", "..", "..", "..", "..", "tests", "testdata", "projects", "package-managers")

func TestBuildNugetDependencyTree(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("other", "nuget"))
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

		sol, err = runDotnetRestoreAndLoadSolution(technologies.BuildInfoBomGeneratorParams{}, tempDirPath, "", true)
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
		skipMsg                     string
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
			skipMsg:                     "CI fails on 'dotnet restore' - MSBuild auto-detection: using msbuild version '' from '/opt/homebrew/bin'. xbuild tool is deprecated use msbuild instead, pending fix XRAY-128186",
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
			skipMsg:                     "CI fails on 'dotnet restore' - MSBuild auto-detection: using msbuild version '' from '/opt/homebrew/bin'. xbuild tool is deprecated use msbuild instead, pending fix XRAY-128186",
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
			if test.skipMsg != "" {
				securityTestUtils.SkipTestIfDurationNotPassed(t, "01-08-2026", 60, test.skipMsg)
			}
			// Create and change directory to test workspace
			_, cleanUp := technologies.CreateTestWorkspace(t, test.testDir)
			defer cleanUp()

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
				assert.IsType(t, &utils.ErrProjectNotInstalled{}, err)
			} else {
				assert.NotNil(t, dependencyTrees)
				assert.NotNil(t, uniqueDeps)
				assert.NoError(t, err)
			}
		})
	}
}

func TestSolutionFilePathParameter(t *testing.T) {
	testCases := []struct {
		name             string
		solutionFilePath string
		expectedFileName string
	}{
		{
			name:             "solution file path from params",
			solutionFilePath: "/path/to/my-solution.sln",
			expectedFileName: "my-solution.sln",
		},
		{
			name:             "slnx solution file path from params",
			solutionFilePath: "/path/to/my-solution.slnx",
			expectedFileName: "my-solution.slnx",
		},
		{
			name:             "no solution file path",
			solutionFilePath: "",
			expectedFileName: "",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedFileName, solutionFileName(test.solutionFilePath))
		})
	}
}

func TestRunDotnetRestoreWithRealSolutionFile(t *testing.T) {
	testDataDir := filepath.Join("..", "..", "..", "..", "..", "tests", "testdata", "projects", "package-managers")
	multiProjectPath := filepath.Join(testDataDir, "nuget", "multi")
	solutionFilePath := filepath.Join(multiProjectPath, "TestSolution.sln")
	_, err := os.Stat(solutionFilePath)
	assert.NoError(t, err, "Test solution file should exist")

	params := technologies.BuildInfoBomGeneratorParams{
		SolutionFilePath: solutionFilePath,
	}
	toolType := bidotnet.ConvertNameToToolType("dotnet")
	err = runDotnetRestore(multiProjectPath, params, toolType, []string{})
	if err != nil {
		assert.NotContains(t, err.Error(), "this folder contains more than one project or solution file")
	}
}

// TestBuildDependencyTreeWithSlnxSolution proves a '.slnx'-only project (no '.sln' fallback)
// resolves real dependencies via BuildDependencyTree, the same entry point 'jf ca' uses.
func TestBuildDependencyTreeWithSlnxSolution(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "nuget", "slnx-single"))
	defer cleanUp()

	params := technologies.BuildInfoBomGeneratorParams{}
	dependencyTrees, uniqueDeps, err := BuildDependencyTree(params)
	require.NoError(t, err)
	assert.NotEmpty(t, dependencyTrees, "expected at least one dependency tree to be built from the '.slnx' solution")
	assert.NotEmpty(t, uniqueDeps, "expected at least one dependency to be resolved from the '.slnx' solution's ClassLibrary1 project")
}

// TestBuildDependencyTreeWithExplicitSlnxSolutionPath proves passing a '.slnx' file explicitly
// via '--solution-path' resolves real dependencies via BuildDependencyTree, not just auto-discovery.
func TestBuildDependencyTreeWithExplicitSlnxSolutionPath(t *testing.T) {
	workDir, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "nuget", "slnx-single"))
	defer cleanUp()

	params := technologies.BuildInfoBomGeneratorParams{
		SolutionFilePath: filepath.Join(workDir, "TestSolution.slnx"),
	}
	dependencyTrees, uniqueDeps, err := BuildDependencyTree(params)
	require.NoError(t, err)
	assert.NotEmpty(t, dependencyTrees, "expected at least one dependency tree to be built from the '.slnx' solution via --solution-path")
	assert.NotEmpty(t, uniqueDeps, "expected at least one dependency to be resolved from the '.slnx' solution's ClassLibrary1 project via --solution-path")
}

// TestSolutionFilePathDisambiguatesMultipleSlnFiles verifies --solution-path correctly picks
// one '.sln' out of several in the same directory, instead of hitting dotnet's "more than one
// project or solution file" ambiguity error.
//
// Uses its own "multi-solutions" fixture (not "multi") because TestSkipBuildDepTreeWhenInstallForbidden
// relies on "multi" having exactly one '.sln' for its auto-discovery/no-solution-path case.
func TestSolutionFilePathDisambiguatesMultipleSlnFiles(t *testing.T) {
	workDir, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "nuget", "multi-solutions"))
	defer cleanUp()

	// Sanity check: the workspace must actually contain more than one '.sln' file, otherwise
	// this test wouldn't be exercising disambiguation at all.
	slnFiles, err := filepath.Glob(filepath.Join(workDir, "*.sln"))
	require.NoError(t, err)
	require.Len(t, slnFiles, 2, "expected exactly 2 '.sln' files in the fixture to test disambiguation")

	toolType := bidotnet.ConvertNameToToolType("dotnet")
	for _, slnName := range []string{"TestSolution.sln", "TestAppOnly.sln"} {
		t.Run(slnName, func(t *testing.T) {
			params := technologies.BuildInfoBomGeneratorParams{
				SolutionFilePath: filepath.Join(workDir, slnName),
			}
			err := runDotnetRestore(workDir, params, toolType, []string{})
			assert.NoError(t, err)
		})
	}
}

// TestSolutionFilePathValidation covers the '--solution-path' pre-flight check in
// BuildDependencyTree. The check runs before any solution load or 'restore', so these
// cases never invoke the dotnet CLI.
func TestSolutionFilePathValidation(t *testing.T) {
	testCases := []struct {
		name             string
		solutionFilePath string
		setup            func(t *testing.T, dir string)
	}{
		{
			name:             "base name not present in scanned directory",
			solutionFilePath: filepath.Join("sub", "Missing.sln"),
		},
		{
			name:             "path resolves to a directory, not a solution file",
			solutionFilePath: filepath.Join("sub", "NotASolution"),
			setup: func(t *testing.T, dir string) {
				require.NoError(t, os.Mkdir(filepath.Join(dir, "NotASolution"), 0o750))
			},
		},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.setup != nil {
				test.setup(t, dir)
			}
			t.Chdir(dir)
			dependencyTrees, uniqueDeps, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{
				SolutionFilePath: test.solutionFilePath,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--solution-path", "the error must name the flag the user passed")
			assert.Contains(t, err.Error(), filepath.Base(test.solutionFilePath))
			assert.Nil(t, dependencyTrees)
			assert.Nil(t, uniqueDeps)
		})
	}
}

func TestParseNuGetSourcesOutput(t *testing.T) {
	testCases := []struct {
		name     string
		output   string
		expected []nugetSource
	}{
		{
			name: "dotnet-style detailed output, single enabled source",
			output: "Registered Sources:\n" +
				"  1.  nuget.org [Enabled]\n" +
				"      https://api.nuget.org/v3/index.json\n",
			expected: []nugetSource{
				{name: "nuget.org", url: "https://api.nuget.org/v3/index.json"},
			},
		},
		{
			name: "multiple sources, disabled source is skipped",
			output: "Registered Sources:\n" +
				"  1.  nuget.org [Enabled]\n" +
				"      https://api.nuget.org/v3/index.json\n" +
				"  2.  MyArtifactory [Enabled]\n" +
				"      https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json\n" +
				"  3.  OldFeed [Disabled]\n" +
				"      https://old.example.com/index.json\n",
			expected: []nugetSource{
				{name: "nuget.org", url: "https://api.nuget.org/v3/index.json"},
				{name: "MyArtifactory", url: "https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json"},
			},
		},
		{
			name: "legacy nuget.exe 'sources List' output — same detailed format",
			output: "Registered Sources:\n" +
				"  1.  nuget.org [Enabled]\n" +
				"      https://api.nuget.org/v3/index.json\n",
			expected: []nugetSource{
				{name: "nuget.org", url: "https://api.nuget.org/v3/index.json"},
			},
		},
		{
			name:     "no sources configured",
			output:   "Registered Sources:\n  There are no sources.\n",
			expected: nil,
		},
		{
			name:     "empty output",
			output:   "",
			expected: nil,
		},
		{
			name: "header with no URL line following (malformed/truncated) is skipped",
			output: "Registered Sources:\n" +
				"  1.  nuget.org [Enabled]\n" +
				"  2.  MyArtifactory [Enabled]\n" +
				"      https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json\n",
			expected: []nugetSource{
				{name: "MyArtifactory", url: "https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json"},
			},
		},
		{
			name: "source name containing brackets/spaces is captured correctly",
			output: "Registered Sources:\n" +
				"  1.  My [Company] Feed [Enabled]\n" +
				"      https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json\n",
			expected: []nugetSource{
				{name: "My [Company] Feed", url: "https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseNuGetSourcesOutput(tc.output)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestParseArtifactoryNugetSourceUrl(t *testing.T) {
	testCases := []struct {
		name           string
		sourceUrl      string
		expectedBase   string
		expectedRepo   string
		expectErr      bool
		errMsgContains string
	}{
		{
			name:         "V3 standard URL with /artifactory context root",
			sourceUrl:    "https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json",
			expectedBase: "https://artifactory.example.com/artifactory/",
			expectedRepo: "nuget-remote",
		},
		{
			name:         "V2 standard URL with /artifactory context root",
			sourceUrl:    "https://artifactory.example.com/artifactory/api/nuget/nuget-remote",
			expectedBase: "https://artifactory.example.com/artifactory/",
			expectedRepo: "nuget-remote",
		},
		{
			name:         "V2 URL with trailing slash",
			sourceUrl:    "https://artifactory.example.com/artifactory/api/nuget/nuget-remote/",
			expectedBase: "https://artifactory.example.com/artifactory/",
			expectedRepo: "nuget-remote",
		},
		{
			name:         "V3 reverse-proxy URL without /artifactory context root",
			sourceUrl:    "https://nuget.company.com/api/nuget/v3/nuget-remote/index.json",
			expectedBase: "https://nuget.company.com/",
			expectedRepo: "nuget-remote",
		},
		{
			name:         "V2 reverse-proxy URL without /artifactory context root",
			sourceUrl:    "https://nuget.company.com/api/nuget/nuget-remote",
			expectedBase: "https://nuget.company.com/",
			expectedRepo: "nuget-remote",
		},
		{
			name:           "non-Artifactory URL",
			sourceUrl:      "https://api.nuget.org/v3/index.json",
			expectErr:      true,
			errMsgContains: "does not appear to be an Artifactory NuGet registry",
		},
		{
			name:           "Artifactory NuGet API path with no repo name",
			sourceUrl:      "https://artifactory.example.com/artifactory/api/nuget/v3/index.json",
			expectErr:      true,
			errMsgContains: "could not extract repository name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			base, repo, err := parseArtifactoryNugetSourceUrl(tc.sourceUrl)
			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsgContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedBase, base)
			assert.Equal(t, tc.expectedRepo, repo)
		})
	}
}

func TestSchemeAndHostOf(t *testing.T) {
	testCases := []struct {
		name         string
		rawUrl       string
		expectedHost string
		expectErr    bool
	}{
		{name: "standard https URL", rawUrl: "https://artifactory.example.com/artifactory/api/nuget/v3/repo/index.json", expectedHost: "https://artifactory.example.com"},
		{name: "URL with port", rawUrl: "https://artifactory.example.com:8081/artifactory/api/nuget/repo", expectedHost: "https://artifactory.example.com:8081"},
		{name: "http URL — scheme is part of the match key, not stripped", rawUrl: "http://artifactory.example.com/artifactory/api/nuget/v3/repo/index.json", expectedHost: "http://artifactory.example.com"},
		{name: "no host in URL", rawUrl: "/just/a/path", expectErr: true},
		{name: "empty URL", rawUrl: "", expectErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			host, err := schemeAndHostOf(tc.rawUrl)
			if tc.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedHost, host)
		})
	}
}

// TestSelectMatchingNuGetSource_SchemeMismatch_NotTreatedAsMatch verifies a same-host
// http:// native source is never matched against a https:// configured Artifactory server —
// otherwise https credentials from 'jf c' would be attached to a plaintext source.
func TestSelectMatchingNuGetSource_SchemeMismatch_NotTreatedAsMatch(t *testing.T) {
	sources := []nugetSource{
		{name: "Artifactory", url: "http://artifactory.example.com/artifactory/api/nuget/v3/repo/index.json"},
	}
	_, err := selectMatchingNuGetSource(sources, "https://artifactory.example.com/artifactory/", dotnetToolType)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not find a NuGet source configured")
}

func TestSelectMatchingNuGetSource(t *testing.T) {
	sources := []nugetSource{
		{name: "nuget.org", url: "https://api.nuget.org/v3/index.json"},
		{name: "MyArtifactory", url: "https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json"},
	}

	t.Run("matches the configured Artifactory host, case-insensitively", func(t *testing.T) {
		result, err := selectMatchingNuGetSource(sources, "https://Artifactory.Example.com/artifactory/", dotnetToolType)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "MyArtifactory", result.SourceName)
		assert.Equal(t, "https://artifactory.example.com/artifactory/", result.ArtifactoryUrl)
		assert.Equal(t, "nuget-remote", result.RepoName)
	})

	t.Run("no configured source matches the host", func(t *testing.T) {
		result, err := selectMatchingNuGetSource(sources, "https://other-artifactory.example.com/artifactory/", dotnetToolType)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "could not find a NuGet source configured")
		assert.Contains(t, err.Error(), "dotnet nuget list source")
	})

	t.Run("error message references legacy nuget CLI command for nugetToolType", func(t *testing.T) {
		_, err := selectMatchingNuGetSource(sources, "https://other-artifactory.example.com/artifactory/", nugetToolType)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nuget sources List")
	})

	t.Run("source matches host but is not a recognizable Artifactory NuGet URL", func(t *testing.T) {
		malformed := []nugetSource{
			{name: "BadArtifactory", url: "https://artifactory.example.com/some/other/path"},
		}
		_, err := selectMatchingNuGetSource(malformed, "https://artifactory.example.com/artifactory/", dotnetToolType)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a recognizable Artifactory NuGet repository URL")
	})

	t.Run("invalid configured Artifactory URL", func(t *testing.T) {
		_, err := selectMatchingNuGetSource(sources, "not-a-valid-url-%", dotnetToolType)
		require.Error(t, err)
	})
}

// TestSelectMatchingNuGetSource_MultipleMatches_WarnsAndUsesFirst verifies that when more than
// one configured source matches the Artifactory host (e.g. a leftover 'Set me up' source plus a
// newly added one), the first match is still used for backward compatibility, but a Warn is
// logged naming all the ambiguous sources so the user can clean them up.
func TestSelectMatchingNuGetSource_MultipleMatches_WarnsAndUsesFirst(t *testing.T) {
	sources := []nugetSource{
		{name: "OldArtifactory", url: "https://artifactory.example.com/artifactory/api/nuget/v3/old-repo/index.json"},
		{name: "NewArtifactory", url: "https://artifactory.example.com/artifactory/api/nuget/v3/new-repo/index.json"},
	}

	var buf bytes.Buffer
	origLogger := log.Logger
	log.SetLogger(log.NewLogger(log.INFO, &buf))
	defer log.SetLogger(origLogger)

	result, err := selectMatchingNuGetSource(sources, "https://artifactory.example.com/artifactory/", dotnetToolType)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "OldArtifactory", result.SourceName)
	assert.Equal(t, "old-repo", result.RepoName)

	logOutput := buf.String()
	assert.Contains(t, logOutput, "Multiple configured NuGet sources match")
	assert.Contains(t, logOutput, "OldArtifactory")
	assert.Contains(t, logOutput, "NewArtifactory")
}

// TestSelectMatchingNuGetSource_SingleMatch_NoWarning is a regression test: the common case of
// exactly one matching source must not trigger the ambiguity warning.
func TestSelectMatchingNuGetSource_SingleMatch_NoWarning(t *testing.T) {
	sources := []nugetSource{
		{name: "MyArtifactory", url: "https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json"},
	}

	var buf bytes.Buffer
	origLogger := log.Logger
	log.SetLogger(log.NewLogger(log.INFO, &buf))
	defer log.SetLogger(origLogger)

	_, err := selectMatchingNuGetSource(sources, "https://artifactory.example.com/artifactory/", dotnetToolType)
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "Multiple configured NuGet sources match")
}

// writeFakeToolExecutable writes an executable in dir named toolName that echoes the given
// stdout content regardless of arguments, for exercising listNativeNuGetSources /
// GetNativeNuGetRegistryConfig without depending on a real dotnet/nuget install.
func writeFakeToolExecutable(t *testing.T, dir, toolName, stdout string) {
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, toolName+".cmd")
		script := "@echo off\r\n" + "echo " + stdout + "\r\n"
		require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
		return
	}
	path := filepath.Join(dir, toolName)
	script := "#!/bin/sh\ncat <<'EOF'\n" + stdout + "\nEOF\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
}

func TestListNativeNuGetSources(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake tool executable is a POSIX shell script")
	}
	fakeOutput := "Registered Sources:\n" +
		"  1.  MyArtifactory [Enabled]\n" +
		"      https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json\n"

	toolDir := t.TempDir()
	writeFakeToolExecutable(t, toolDir, "dotnet", fakeOutput)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	sources, err := listNativeNuGetSources(dotnetToolType)
	require.NoError(t, err)
	require.Len(t, sources, 1)
	assert.Equal(t, "MyArtifactory", sources[0].name)
}

func TestListNativeNuGetSourcesUnsupportedTool(t *testing.T) {
	_, err := listNativeNuGetSources("some-other-tool")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported tool type")
}

func TestListNativeNuGetSourcesCommandFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake tool executable is a POSIX shell script")
	}
	toolDir := t.TempDir()
	failingScriptPath := filepath.Join(toolDir, "dotnet")
	require.NoError(t, os.WriteFile(failingScriptPath, []byte("#!/bin/sh\necho 'boom' >&2\nexit 1\n"), 0o755))
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := listNativeNuGetSources(dotnetToolType)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

// TestGetNativeNuGetRegistryConfig_DotnetProject runs GetNativeNuGetRegistryConfig end-to-end
// against a fake 'dotnet' executable and a project directory containing a PackageReference-style
// .csproj (so getProjectToolName resolves to the dotnet CLI), verifying the full resolution
// priority: detect tool -> list sources -> match by host -> parse Artifactory URL/repo.
func TestGetNativeNuGetRegistryConfig_DotnetProject(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake tool executable is a POSIX shell script")
	}
	fakeOutput := "Registered Sources:\n" +
		"  1.  nuget.org [Enabled]\n" +
		"      https://api.nuget.org/v3/index.json\n" +
		"  2.  MyArtifactory [Enabled]\n" +
		"      https://artifactory.example.com/artifactory/api/nuget/v3/nuget-remote/index.json\n"

	toolDir := t.TempDir()
	writeFakeToolExecutable(t, toolDir, "dotnet", fakeOutput)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "app.csproj"),
		[]byte("<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" /></ItemGroup></Project>"), 0o644))

	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer func() { require.NoError(t, os.Chdir(origWd)) }()

	serverDetails := &config.ServerDetails{ArtifactoryUrl: "https://artifactory.example.com/artifactory/"}
	result, err := GetNativeNuGetRegistryConfig(serverDetails)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "MyArtifactory", result.SourceName)
	assert.Equal(t, "https://artifactory.example.com/artifactory/", result.ArtifactoryUrl)
	assert.Equal(t, "nuget-remote", result.RepoName)
}

// TestGetNativeNuGetRegistryConfig_NoMatchingSource verifies the clear, actionable error when
// none of the configured NuGet sources match the configured Artifactory server's host.
func TestGetNativeNuGetRegistryConfig_NoMatchingSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake tool executable is a POSIX shell script")
	}
	fakeOutput := "Registered Sources:\n" +
		"  1.  nuget.org [Enabled]\n" +
		"      https://api.nuget.org/v3/index.json\n"

	toolDir := t.TempDir()
	writeFakeToolExecutable(t, toolDir, "dotnet", fakeOutput)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "app.csproj"),
		[]byte("<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" /></ItemGroup></Project>"), 0o644))

	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer func() { require.NoError(t, os.Chdir(origWd)) }()

	serverDetails := &config.ServerDetails{ArtifactoryUrl: "https://artifactory.example.com/artifactory/"}
	result, err := GetNativeNuGetRegistryConfig(serverDetails)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "could not find a NuGet source configured")
}
