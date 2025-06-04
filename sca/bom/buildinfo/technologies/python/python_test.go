package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/build-info-go/utils/pythonutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

func TestBuildPipDependencyListSetuppy(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pip", "pip", "setuppyproject"))
	defer cleanUp()
	// Run getModulesDependencyTrees
	rootNode, uniqueDeps, _, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{}, techutils.Pip)
	assert.NoError(t, err)
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"pexpect:4.8.0")
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"ptyprocess:0.7.0")
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"pip-example:1.2.3")
	assert.Len(t, rootNode, 1)
	if len(rootNode) > 0 {
		assert.NotEmpty(t, rootNode[0].Nodes)
		if rootNode[0].Nodes != nil {
			// Test direct dependency
			directDepNode := tests.GetAndAssertNode(t, rootNode[0].Nodes, "pip-example:1.2.3")
			// Test child module
			childNode := tests.GetAndAssertNode(t, directDepNode.Nodes, "pexpect:4.8.0")
			// Test sub child module
			tests.GetAndAssertNode(t, childNode.Nodes, "ptyprocess:0.7.0")
		}
	}
}

func TestPipDependencyListCustomInstallArgs(t *testing.T) {
	// Create and change directory to test workspace
	mainPath := filepath.Join("projects", "package-managers", "python", "pip", "pip")
	actualMainPath, cleanUp := technologies.CreateTestWorkspace(t, mainPath)
	defer cleanUp()
	assert.NoError(t, os.Chdir(filepath.Join(actualMainPath, "referenceproject")))
	// Run getModulesDependencyTrees
	params := technologies.BuildInfoBomGeneratorParams{InstallCommandArgs: []string{"--force-reinstall"}}
	rootNode, uniqueDeps, _, err := BuildDependencyTree(params, techutils.Pip)
	validatePipRequirementsProject(t, err, uniqueDeps, rootNode)
}

func TestBuildPipDependencyListSetuppyForCuration(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pip", "pip", "setuppyproject"))
	defer cleanUp()
	// Run getModulesDependencyTrees
	params := technologies.BuildInfoBomGeneratorParams{IsCurationCmd: true}
	rootNode, uniqueDeps, downloadUrls, err := BuildDependencyTree(params, techutils.Pip)
	assert.NoError(t, err)
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"pexpect:4.8.0")
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"ptyprocess:0.7.0")
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"pip-example:1.2.3")
	assert.Len(t, rootNode, 1)
	if assert.NotNil(t, rootNode[0].Nodes) && assert.NotEmpty(t, rootNode[0].Nodes) {
		// Test direct dependency
		directDepNode := tests.GetAndAssertNode(t, rootNode[0].Nodes, "pip-example:1.2.3")
		// Test child module
		childNode := tests.GetAndAssertNode(t, directDepNode.Nodes, "pexpect:4.8.0")
		// Test sub child module
		tests.GetAndAssertNode(t, childNode.Nodes, "ptyprocess:0.7.0")

		assert.NotEmpty(t, downloadUrls)
		url, exist := downloadUrls[PythonPackageTypeIdentifier+"ptyprocess:0.7.0"]
		assert.True(t, exist)
		assert.True(t, strings.HasSuffix(url, "packages/22/a6/858897256d0deac81a172289110f31629fc4cee19b6f01283303e18c8db3/ptyprocess-0.7.0-py2.py3-none-any.whl"))

		url, exist = downloadUrls[PythonPackageTypeIdentifier+"pexpect:4.8.0"]
		assert.True(t, exist)
		assert.True(t, strings.HasSuffix(url, "packages/39/7b/88dbb785881c28a102619d46423cb853b46dbccc70d3ac362d99773a78ce/pexpect-4.8.0-py2.py3-none-any.whl"))
	}
}

func TestPipDependencyListRequirementsFallback(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"))
	defer cleanUp()
	// No requirements file field specified, expect the command to use the fallback 'pip install -r requirements.txt' command
	rootNode, uniqueDeps, _, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{}, techutils.Pip)
	validatePipRequirementsProject(t, err, uniqueDeps, rootNode)
}

func validatePipRequirementsProject(t *testing.T, err error, uniqueDeps []string, rootNode []*utils.GraphNode) {
	assert.NoError(t, err)
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"pexpect:4.7.0")
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"ptyprocess:0.7.0")
	require.Len(t, rootNode, 1)
	if assert.GreaterOrEqual(t, len(rootNode[0].Nodes), 2) {
		childNode := tests.GetAndAssertNode(t, rootNode[0].Nodes, "pexpect:4.7.0")
		if childNode != nil {
			// Test child module
			tests.GetAndAssertNode(t, childNode.Nodes, "ptyprocess:0.7.0")
		}
	}
}

func TestBuildPipDependencyListRequirements(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"))
	defer cleanUp()
	// Run getModulesDependencyTrees
	rootNode, uniqueDeps, _, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{PipRequirementsFile: "requirements.txt"}, techutils.Pip)
	assert.NoError(t, err)
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"pexpect:4.7.0")
	assert.Contains(t, uniqueDeps, PythonPackageTypeIdentifier+"ptyprocess:0.7.0")
	assert.Len(t, rootNode, 1)
	if len(rootNode) > 0 {
		assert.NotEmpty(t, rootNode[0].Nodes)
		if rootNode[0].Nodes != nil {
			// Test root module
			directDepNode := tests.GetAndAssertNode(t, rootNode[0].Nodes, "pexpect:4.7.0")
			// Test child module
			tests.GetAndAssertNode(t, directDepNode.Nodes, "ptyprocess:0.7.0")
		}
	}
}

func TestBuildPipenvDependencyList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pipenv", "pipenv", "pipenvproject"))
	defer cleanUp()
	expectedPipenvUniqueDeps := []string{
		PythonPackageTypeIdentifier + "toml:0.10.2",
		PythonPackageTypeIdentifier + "pexpect:4.8.0",
		PythonPackageTypeIdentifier + "ptyprocess:0.7.0",
	}
	// Run getModulesDependencyTrees
	rootNode, uniqueDeps, _, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{}, techutils.Pipenv)
	if err != nil {
		t.Fatal(err)
	}
	assert.ElementsMatch(t, uniqueDeps, expectedPipenvUniqueDeps, "First is actual, Second is Expected")
	assert.Len(t, rootNode, 1)
	if len(rootNode) > 0 {
		assert.NotEmpty(t, rootNode[0].Nodes)
		// Test child module
		childNode := tests.GetAndAssertNode(t, rootNode[0].Nodes, "pexpect:4.8.0")
		// Test sub child module
		if assert.NotNil(t, childNode) {
			tests.GetAndAssertNode(t, childNode.Nodes, "ptyprocess:0.7.0")
		}
	}
}

func TestBuildPoetryDependencyList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "poetry", "my-poetry-project"))
	defer cleanUp()
	expectedPoetryUniqueDeps := []string{
		PythonPackageTypeIdentifier + "wcwidth:0.2.13",
		PythonPackageTypeIdentifier + "colorama:0.4.6",
		PythonPackageTypeIdentifier + "packaging:24.2",
		PythonPackageTypeIdentifier + "python:",
		PythonPackageTypeIdentifier + "pluggy:0.13.1",
		PythonPackageTypeIdentifier + "py:1.11.0",
		PythonPackageTypeIdentifier + "atomicwrites:1.4.1",
		PythonPackageTypeIdentifier + "attrs:25.1.0",
		PythonPackageTypeIdentifier + "more-itertools:10.6.0",
		PythonPackageTypeIdentifier + "numpy:1.26.4",
		PythonPackageTypeIdentifier + "pytest:5.4.3",
	}
	// Run getModulesDependencyTrees
	rootNode, uniqueDeps, _, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{}, techutils.Poetry)
	if err != nil {
		t.Fatal(err)
	}
	assert.ElementsMatch(t, uniqueDeps, expectedPoetryUniqueDeps, "First is actual, Second is Expected")
	assert.Len(t, rootNode, 1)
	if len(rootNode) > 0 {
		assert.NotEmpty(t, rootNode[0].Nodes)
		// Test child module
		childNode := tests.GetAndAssertNode(t, rootNode[0].Nodes, "pytest:5.4.3")
		// Test sub child module
		if assert.NotNil(t, childNode) {
			tests.GetAndAssertNode(t, childNode.Nodes, "packaging:24.2")
		}
	}
}

func TestBuildDependencyTreeWhenInstallForbidden(t *testing.T) {
	// This feature is currently supported and tested for Pip and Poetry only
	testcases := []struct {
		name                             string
		testDir                          string
		technology                       techutils.Technology
		installBeforeFetchingInitialDeps bool
	}{
		// pip
		{
			name:                             "pip: project not installed | install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"),
			technology:                       techutils.Pip,
			installBeforeFetchingInitialDeps: false,
		},
		{
			name:                             "pip: project installed before dep tree construction| install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"),
			technology:                       techutils.Pip,
			installBeforeFetchingInitialDeps: true,
		},
		{
			name:                             "poetry: project not installed | install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "poetry", "poetry"),
			technology:                       techutils.Poetry,
			installBeforeFetchingInitialDeps: false,
		},
		{
			name:                             "poetry: project installed before dep tree construction| install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "poetry", "poetry"),
			technology:                       techutils.Poetry,
			installBeforeFetchingInitialDeps: true,
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			testDir, cleanUp := technologies.CreateTestWorkspace(t, test.testDir)
			defer cleanUp()

			// Create virtual env according to package manager if needed
			if !test.installBeforeFetchingInitialDeps {
				// If we install before calling BuildDependencyTree a virtual environment is going to be created, and we don't have to do it manually
				if test.technology == techutils.Pip {
					restoreEnv, err := SetPipVirtualEnvPath()
					defer func() {
						assert.NoError(t, restoreEnv(), "restoring env after setting pip virtual env creation failed")
					}()
					require.NoError(t, err)
				}
			}

			// Setting scan params
			params := technologies.BuildInfoBomGeneratorParams{SkipAutoInstall: true}
			if test.technology == techutils.Pip {
				params.PipRequirementsFile = "requirements.txt"
			}

			if test.installBeforeFetchingInitialDeps {
				restoreEnv, err := runPythonInstall(params, pythonutils.PythonTool(test.technology))
				defer func() {
					assert.NoError(t, restoreEnv(), "restoring env after setting "+test.technology+" virtual env creation failed")
				}()
				require.NoError(t, err)
			}

			// Checking dependencies before BuildDependencyTree
			localDependenciesPath, err := config.GetJfrogDependenciesPath()
			assert.NoError(t, err)
			// We use the dependencies graph and not the list of dependencies since the list includes only direct dependencies
			dependenciesGraphBeforeBuildDepTree, _, err := pythonutils.GetPythonDependencies(pythonutils.PythonTool(test.technology), testDir, localDependenciesPath, log.GetLogger())
			assert.NoError(t, err)

			var dependenciesBeforeBuildDepTree []string
			switch test.technology {
			case techutils.Pip:
				dependenciesBeforeBuildDepTree = maps.Keys(dependenciesGraphBeforeBuildDepTree)
			case techutils.Poetry:
				if len(dependenciesGraphBeforeBuildDepTree) != 0 {
					mapKey := maps.Keys(dependenciesGraphBeforeBuildDepTree)[0]
					dependenciesBeforeBuildDepTree = dependenciesGraphBeforeBuildDepTree[mapKey]
				}
			}

			// Build dependency tree
			_, uniqueDeps, _, err := BuildDependencyTree(params, test.technology)
			require.NoError(t, err)
			var trimmedUniqueDeps []string
			for _, dep := range uniqueDeps {
				trimmedUniqueDeps = append(trimmedUniqueDeps, strings.TrimPrefix(dep, "pypi://"))
			}
			slices.Sort(dependenciesBeforeBuildDepTree)
			slices.Sort(trimmedUniqueDeps)
			assert.Equal(t, dependenciesBeforeBuildDepTree, trimmedUniqueDeps)
		})
	}
}

func TestGetPipInstallArgs(t *testing.T) {
	assert.Equal(t, []string{"-m", "pip", "install", "."}, getPipInstallArgs("", "", "", ""))
	assert.Equal(t, []string{"-m", "pip", "install", "-r", "requirements.txt"}, getPipInstallArgs("requirements.txt", "", "", ""))

	assert.Equal(t, []string{"-m", "pip", "install", ".", "-i", "https://user@pass:remote.url/repo"}, getPipInstallArgs("", "https://user@pass:remote.url/repo", "", ""))
	assert.Equal(t, []string{"-m", "pip", "install", "-r", "requirements.txt", "-i", "https://user@pass:remote.url/repo"}, getPipInstallArgs("requirements.txt", "https://user@pass:remote.url/repo", "", ""))
	assert.Equal(t, []string{"-m", "pip", "install", ".", "--cache-dir", filepath.Join("test", "path"), "--ignore-installed", "--report", "report.json"}, getPipInstallArgs("", "", filepath.Join("test", "path"), "report.json"))

}
