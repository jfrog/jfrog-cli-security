package python

import (
	biutils "github.com/jfrog/build-info-go/utils"
	cliSecUtils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

func TestBuildPipDependencyListSetuppy(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pip", "pip", "setuppyproject"))
	defer cleanUp()
	// Run getModulesDependencyTrees
	params := cliSecUtils.AuditBasicParams{}
	params.SetTechnologies([]string{string(techutils.Pip)})
	rootNode, uniqueDeps, _, err := BuildDependencyTree(&params)
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
	actualMainPath, cleanUp := sca.CreateTestWorkspace(t, mainPath)
	defer cleanUp()
	assert.NoError(t, os.Chdir(filepath.Join(actualMainPath, "referenceproject")))
	// Run getModulesDependencyTrees
	params := cliSecUtils.AuditBasicParams{}
	params.SetTechnologies([]string{string(techutils.Pip)})
	params.SetInstallCommandArgs([]string{"--break-system-packages"})
	rootNode, uniqueDeps, _, err := BuildDependencyTree(&params)
	validatePipRequirementsProject(t, err, uniqueDeps, rootNode)
}

func TestBuildPipDependencyListSetuppyForCuration(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pip", "pip", "setuppyproject"))
	defer cleanUp()
	// Run getModulesDependencyTrees
	params := cliSecUtils.AuditBasicParams{}
	params.SetTechnologies([]string{string(techutils.Pip)})
	params.SetIsCurationCmd(true)
	rootNode, uniqueDeps, downloadUrls, err := BuildDependencyTree(&params)
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
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"))
	defer cleanUp()
	// No requirements file field specified, expect the command to use the fallback 'pip install -r requirements.txt' command
	params := cliSecUtils.AuditBasicParams{}
	params.SetTechnologies([]string{string(techutils.Pip)})
	rootNode, uniqueDeps, _, err := BuildDependencyTree(&params)
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
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"))
	defer cleanUp()
	// Run getModulesDependencyTrees
	params := cliSecUtils.AuditBasicParams{}
	params.SetTechnologies([]string{string(techutils.Pip)})
	params.SetPipRequirementsFile("requirements.txt")
	rootNode, uniqueDeps, _, err := BuildDependencyTree(&params)
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
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "pipenv", "pipenv", "pipenvproject"))
	defer cleanUp()
	expectedPipenvUniqueDeps := []string{
		PythonPackageTypeIdentifier + "toml:0.10.2",
		PythonPackageTypeIdentifier + "pexpect:4.8.0",
		PythonPackageTypeIdentifier + "ptyprocess:0.7.0",
	}
	// Run getModulesDependencyTrees
	params := cliSecUtils.AuditBasicParams{}
	params.SetTechnologies([]string{string(techutils.Pipenv)})
	rootNode, uniqueDeps, _, err := BuildDependencyTree(&params)
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
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "python", "poetry", "my-poetry-project"))
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
	params := cliSecUtils.AuditBasicParams{}
	params.SetTechnologies([]string{string(techutils.Poetry)})
	rootNode, uniqueDeps, _, err := BuildDependencyTree(&params)
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

func TestSkipBuildDepTreeWhenInstallForbidden(t *testing.T) {
	t.Skip()
	//TODO: Tests not ready yet.
	//TODO: need a test case of more than one technology?
	testCases := []struct {
		name                        string
		testDir                     string
		descriptorFile              string
		installCommand              string
		shouldBeInstalled           bool
		successfulTreeBuiltExpected bool
	}{
		//pip
		{
			name:                        "not installed | install required - install command",
			testDir:                     filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"),
			descriptorFile:              "requirements.txt",
			installCommand:              "pip install",
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"),
			descriptorFile:              "requirements.txt",
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "installed | install not required",
			testDir:                     filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"),
			descriptorFile:              "requirements.txt",
			shouldBeInstalled:           true,
			successfulTreeBuiltExpected: true,
		},

		//pipenv
		{
			name:                        "not installed | install required - install command",
			testDir:                     filepath.Join("projects", "package-managers", "python", "pipenv", "pipenv", "pipenvproject"),
			descriptorFile:              "Pipfile",
			installCommand:              "pipenv install",
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "python", "pipenv", "pipenv", "pipenvproject"),
			descriptorFile:              "Pipfile",
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "installed | install not required",
			testDir:                     filepath.Join("projects", "package-managers", "python", "pipenv", "pipenv", "pipenvproject"),
			descriptorFile:              "Pipfile",
			shouldBeInstalled:           true,
			successfulTreeBuiltExpected: true,
		},

		//poetry
		{
			name:                        "not installed | install required - install command",
			testDir:                     filepath.Join("projects", "package-managers", "poetry", "poetry"),
			descriptorFile:              "pyproject.toml",
			installCommand:              "poetry install",
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: true,
		},
		{
			name:                        "not installed | install required - install forbidden",
			testDir:                     filepath.Join("projects", "package-managers", "poetry", "poetry"),
			descriptorFile:              "pyproject.toml",
			shouldBeInstalled:           false,
			successfulTreeBuiltExpected: false,
		},
		{
			name:                        "installed | install not required",
			testDir:                     filepath.Join("projects", "package-managers", "poetry", "poetry"),
			descriptorFile:              "pyproject.toml",
			shouldBeInstalled:           true,
			successfulTreeBuiltExpected: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			dirPath, cleanUp := sca.CreateTestWorkspace(t, test.testDir)
			defer cleanUp()

			exists, err := fileutils.IsFileExists(filepath.Join(dirPath, "requirements.txt"), false)
			assert.NoError(t, err)

			if !test.shouldBeInstalled && exists {
				err = os.Remove(filepath.Join(dirPath, "requirements.txt"))
				assert.NoError(t, err)
			}

			params := (&cliSecUtils.AuditBasicParams{}).SetSkipAutoInstall(true)
			if test.installCommand != "" {
				splitInstallCommand := strings.Split(test.installCommand, " ")
				params = params.SetInstallCommandName(splitInstallCommand[0]).SetInstallCommandArgs(splitInstallCommand[1:])
			}
			dependencyTrees, uniqueDeps, _, err := BuildDependencyTree(params)
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

func TestGetPipInstallArgs(t *testing.T) {
	assert.Equal(t, []string{"-m", "pip", "install", "."}, getPipInstallArgs("", "", "", ""))
	assert.Equal(t, []string{"-m", "pip", "install", "-r", "requirements.txt"}, getPipInstallArgs("requirements.txt", "", "", ""))

	assert.Equal(t, []string{"-m", "pip", "install", ".", "-i", "https://user@pass:remote.url/repo"}, getPipInstallArgs("", "https://user@pass:remote.url/repo", "", ""))
	assert.Equal(t, []string{"-m", "pip", "install", "-r", "requirements.txt", "-i", "https://user@pass:remote.url/repo"}, getPipInstallArgs("requirements.txt", "https://user@pass:remote.url/repo", "", ""))
	assert.Equal(t, []string{"-m", "pip", "install", ".", "--cache-dir", filepath.Join("test", "path"), "--ignore-installed", "--report", "report.json"}, getPipInstallArgs("", "", filepath.Join("test", "path"), "report.json"))

}
