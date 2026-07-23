package python

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jfrog/build-info-go/utils/pythonutils"
	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	coreCommonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
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
	// Test direct dependency
	tests.GetAndAssertNode(t, rootNode, "pip-example:1.2.3")
	if len(rootNode) > 0 {
		assert.NotEmpty(t, rootNode[0].Nodes)
		if rootNode[0].Nodes != nil {
			// Test child module
			childNode := tests.GetAndAssertNode(t, rootNode[0].Nodes, "pexpect:4.8.0")
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
	tests.GetAndAssertNode(t, rootNode, "pip-example:1.2.3")
	if assert.NotNil(t, rootNode[0].Nodes) && assert.NotEmpty(t, rootNode[0].Nodes) {
		// Test child module
		childNode := tests.GetAndAssertNode(t, rootNode[0].Nodes, "pexpect:4.8.0")
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

func TestShouldRunPythonInstallForPipenv(t *testing.T) {
	assert.False(t, shouldRunPythonInstall(technologies.BuildInfoBomGeneratorParams{SkipAutoInstall: true}, techutils.Pipenv))
	assert.True(t, shouldRunPythonInstall(technologies.BuildInfoBomGeneratorParams{
		SkipAutoInstall: true,
		IsCurationCmd:   true,
	}, techutils.Pipenv))
	assert.True(t, shouldRunPythonInstall(technologies.BuildInfoBomGeneratorParams{}, techutils.Pipenv))
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
	// Run getModulesDependencyTrees. SkipAutoInstall avoids running `poetry install`
	// (which would fail on CI if locked packages lack wheels for the current Python version),
	// relying instead on build-info-go's direct poetry.lock parsing.
	rootNode, uniqueDeps, _, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{SkipAutoInstall: true}, techutils.Poetry)
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
		rootDetected                     bool
	}{
		// pip
		{
			name:                             "pip: project not installed | install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"),
			technology:                       techutils.Pip,
			installBeforeFetchingInitialDeps: false,
			rootDetected:                     false,
		},
		{
			name:                             "pip: project installed before dep tree construction| install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "pip", "pip", "requirementsproject"),
			technology:                       techutils.Pip,
			installBeforeFetchingInitialDeps: true,
			rootDetected:                     false,
		},
		{
			name:                             "poetry: project not installed | install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "poetry", "poetry"),
			technology:                       techutils.Poetry,
			installBeforeFetchingInitialDeps: false,
			rootDetected:                     false,
		},
		{
			// Poetry's BuildDependencyTree reads poetry.lock directly, so a pre-existing
			// lock file is the equivalent of "already installed" without requiring `poetry
			// install` (which would need network access to resolve/download packages).
			name:                             "poetry: lock file pre-exists | install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "poetry", "poetry-preinstalled"),
			technology:                       techutils.Poetry,
			installBeforeFetchingInitialDeps: false,
			rootDetected:                     false,
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
				rootDetected, restoreEnv, err := runPythonInstall(params, pythonutils.PythonTool(test.technology))
				defer func() {
					assert.NoError(t, restoreEnv(), "restoring env after setting "+test.technology+" virtual env creation failed")
				}()
				require.NoError(t, err)
				assert.Equal(t, test.rootDetected, rootDetected, "Root detection mismatch for "+test.technology+" technology")
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
					// getPoetryDependencies only adds a package as a graph key when it has
					// at least one dependency; the root package (the project itself) is
					// always added.  For a simple single-dependency project (packaging, no
					// transitives) the graph has exactly one key, so maps.Keys(...)[0] is
					// deterministic and its VALUE is the list of direct dependencies – the
					// same set BuildDependencyTree traverses into uniqueDeps.
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

// =============================================================================
// Unit tests for Poetry curation helpers.
// These tests do not require poetry, pip, or a real Artifactory — they exercise
// the pure helpers and the filesystem-only branches added for `jf ca --poetry`.
// =============================================================================

func TestNormalizePypiName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Flask", "flask"},
		{"PyYAML", "pyyaml"},
		{"zope.interface", "zope-interface"},
		{"jaraco_classes", "jaraco-classes"},
		{"foo___bar.baz", "foo-bar-baz"},
		{"foo--bar", "foo-bar"},
		{"already-normalized", "already-normalized"},
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			assert.Equal(t, c.want, NormalizePypiName(c.in))
		})
	}
}

func TestParsePoetryScalar(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		key     string
		wantVal string
		wantOk  bool
	}{
		{"basic key value", `name = "flask"`, "name", "flask", true},
		{"extra whitespace around equals", `name   =    "flask"`, "name", "flask", true},
		{"empty quoted value is ok", `name = ""`, "name", "", true},
		{"wrong key returns false", `version = "1.0"`, "name", "", false},
		{"unquoted value returns false", `name = flask`, "name", "", false},
		{"single quotes not supported", `name = 'flask'`, "name", "", false},
		{"missing closing quote returns false", `name = "flask`, "name", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotVal, gotOk := parsePoetryScalar(c.line, c.key)
			assert.Equal(t, c.wantOk, gotOk, "ok mismatch")
			assert.Equal(t, c.wantVal, gotVal, "value mismatch")
		})
	}
}

func TestPickPoetryHrefByFilename(t *testing.T) {
	body := []byte(`<html><body>
<a href="packages/aa/bb/Flask-2.0.0.tar.gz#sha256=abc">Flask-2.0.0.tar.gz</a>
<a href="packages/cc/dd/Flask-2.0.0-py3-none-any.whl#sha256=def">Flask-2.0.0-py3-none-any.whl</a>
</body></html>`)

	t.Run("returns href without fragment when filename matches", func(t *testing.T) {
		got := pickPoetryHrefByFilename(body, []string{"Flask-2.0.0-py3-none-any.whl"})
		assert.Equal(t, "packages/cc/dd/Flask-2.0.0-py3-none-any.whl", got)
	})

	t.Run("returns empty when no filename matches", func(t *testing.T) {
		got := pickPoetryHrefByFilename(body, []string{"unrelated.whl"})
		assert.Equal(t, "", got)
	})

	t.Run("returns empty for empty body", func(t *testing.T) {
		got := pickPoetryHrefByFilename(nil, []string{"Flask-2.0.0.tar.gz"})
		assert.Equal(t, "", got)
	})

	t.Run("matches first href when multiple wanted files are present", func(t *testing.T) {
		got := pickPoetryHrefByFilename(body, []string{
			"Flask-2.0.0.tar.gz",
			"Flask-2.0.0-py3-none-any.whl",
		})
		// Both match; pickPoetryHrefByFilename returns the first hit in body order.
		assert.Equal(t, "packages/aa/bb/Flask-2.0.0.tar.gz", got)
	})
}

func TestParsePoetryLockPackages(t *testing.T) {
	t.Run("v2 inline files format", func(t *testing.T) {
		fixture := []byte(`# generated by poetry
[[package]]
name = "flask"
version = "2.0.0"
description = "Web framework"
files = [
    {file = "Flask-2.0.0.tar.gz", hash = "sha256:abc"},
    {file = "Flask-2.0.0-py3-none-any.whl", hash = "sha256:def"},
]

[[package]]
name = "click"
version = "8.0.1"
files = [
    {file = "click-8.0.1-py3-none-any.whl", hash = "sha256:ghi"},
]

[metadata]
lock-version = "2.0"
`)
		got := parsePoetryLockPackages(fixture)
		require.Len(t, got, 2)

		assert.Equal(t, "flask", got[0].Name)
		assert.Equal(t, "2.0.0", got[0].Version)
		assert.ElementsMatch(t, []string{
			"Flask-2.0.0.tar.gz",
			"Flask-2.0.0-py3-none-any.whl",
		}, got[0].Files)

		assert.Equal(t, "click", got[1].Name)
		assert.Equal(t, "8.0.1", got[1].Version)
		assert.ElementsMatch(t, []string{"click-8.0.1-py3-none-any.whl"}, got[1].Files)
	})

	t.Run("v1 metadata.files format", func(t *testing.T) {
		fixture := []byte(`[[package]]
name = "flask"
version = "2.0.0"

[[package]]
name = "click"
version = "8.0.1"

[metadata]
lock-version = "1.1"

[metadata.files]
flask = [
    {file = "Flask-2.0.0.tar.gz", hash = "sha256:abc"},
]
click = [
    {file = "click-8.0.1-py3-none-any.whl", hash = "sha256:ghi"},
]
`)
		got := parsePoetryLockPackages(fixture)
		require.Len(t, got, 2)
		assert.Equal(t, "flask", got[0].Name)
		assert.ElementsMatch(t, []string{"Flask-2.0.0.tar.gz"}, got[0].Files)
		assert.Equal(t, "click", got[1].Name)
		assert.ElementsMatch(t, []string{"click-8.0.1-py3-none-any.whl"}, got[1].Files)
	})

	t.Run("v1 quoted dotted key in metadata.files", func(t *testing.T) {
		fixture := []byte(`[[package]]
name = "zope.interface"
version = "5.0.0"

[metadata]
lock-version = "1.1"

[metadata.files]
"zope.interface" = [
    {file = "zope.interface-5.0.0.tar.gz", hash = "sha256:aaa"},
    {file = "zope.interface-5.0.0-cp39-cp39-linux_x86_64.whl", hash = "sha256:bbb"},
]
`)
		got := parsePoetryLockPackages(fixture)
		require.Len(t, got, 1)
		assert.Equal(t, "zope.interface", got[0].Name)
		assert.ElementsMatch(t, []string{
			"zope.interface-5.0.0.tar.gz",
			"zope.interface-5.0.0-cp39-cp39-linux_x86_64.whl",
		}, got[0].Files,
			"files for a dotted package with a quoted key in [metadata.files] must be collected")
	})

	t.Run("v1 file value containing '= [' is not mistaken for a package key", func(t *testing.T) {
		// A file entry whose name contains "= [" appears mid-array, before the
		// real wheel. A bare strings.Contains(line, "= [") guard would treat it as
		// a new package key, reset currentMetaPkg, and silently drop flask's files.
		fixture := []byte(`[[package]]
name = "flask"
version = "2.0.0"

[metadata]
lock-version = "1.1"

[metadata.files]
flask = [
    {file = "weird = [name].whl", hash = "sha256:abc"},
    {file = "Flask-2.0.0.tar.gz", hash = "sha256:def"},
]
`)
		got := parsePoetryLockPackages(fixture)
		require.Len(t, got, 1)
		assert.Equal(t, "flask", got[0].Name)
		assert.ElementsMatch(t, []string{
			"weird = [name].whl",
			"Flask-2.0.0.tar.gz",
		}, got[0].Files,
			"files must stay attributed to flask, not to a spurious metadata key")
	})

	t.Run("empty content returns empty slice", func(t *testing.T) {
		got := parsePoetryLockPackages(nil)
		assert.Empty(t, got)
	})

	t.Run("comments only returns empty slice", func(t *testing.T) {
		got := parsePoetryLockPackages([]byte("# only a comment\n# another\n"))
		assert.Empty(t, got)
	})
}

func TestBuildPoetryDownloadUrlsMapInputValidation(t *testing.T) {
	t.Run("nil server details returns error", func(t *testing.T) {
		_, err := buildPoetryDownloadUrlsMap(nil, "poetry-repo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server details")
	})

	t.Run("empty artifactory url returns error", func(t *testing.T) {
		_, err := buildPoetryDownloadUrlsMap(&config.ServerDetails{}, "poetry-repo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server details")
	})

	t.Run("empty repository returns error", func(t *testing.T) {
		sd := &config.ServerDetails{ArtifactoryUrl: "http://example.com/artifactory/"}
		_, err := buildPoetryDownloadUrlsMap(sd, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "repository must be configured")
	})
}

func TestReadPoetryLockIfExists(t *testing.T) {
	t.Run("returns error when poetry.lock is missing", func(t *testing.T) {
		t.Chdir(t.TempDir())
		_, err := readPoetryLockIfExists()
		require.Error(t, err)
		assert.Contains(t, err.Error(), poetryLockFile)
	})

	t.Run("parses lock content when present", func(t *testing.T) {
		dir := t.TempDir()
		lockContent := []byte(`[[package]]
name = "flask"
version = "2.0.0"
files = [
    {file = "Flask-2.0.0.tar.gz", hash = "sha256:abc"},
]

[metadata]
lock-version = "2.0"
`)
		require.NoError(t, os.WriteFile(filepath.Join(dir, poetryLockFile), lockContent, 0600))
		t.Chdir(dir)

		got, err := readPoetryLockIfExists()
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "flask", got[0].Name)
		assert.Equal(t, "2.0.0", got[0].Version)
		assert.ElementsMatch(t, []string{"Flask-2.0.0.tar.gz"}, got[0].Files)
	})
}

// TestSetCurationSourceInPyproject covers the three source-handling cases:
//
//  1. pyproject.toml has no [[tool.poetry.source]] → a single entry named
//     after the Artifactory repo (`repoName`) is added.
//  2. pyproject.toml has exactly one [[tool.poetry.source]] with a name
//     that differs from the Artifactory repo → the user's name is
//     preserved and only the URL is rewritten. This is the regression
//     guard for the bug where renaming the source forced Poetry to abort
//     the relock with "Repository '<old-name>' does not exist" and push
//     every `jf ca` run with a pre-existing lock into the no-lockfile
//     probe path.
//  3. pyproject.toml has multiple [[tool.poetry.source]] entries → every
//     name is preserved and every URL is rewritten to the curation
//     pass-through.
func TestSetCurationSourceInPyproject(t *testing.T) {
	const (
		repoName = "my-curation-repo"
		repoURL  = "https://example.com/artifactory/api/curation/audit/my-curation-repo"
	)

	t.Run("no existing source — falls back to repoName", func(t *testing.T) {
		dir := t.TempDir()
		initial := []byte(`[tool.poetry]
name = "test-project"
version = "0.1.0"
description = "fixture"
`)
		pyprojectPath := filepath.Join(dir, pyprojectToml)
		require.NoError(t, os.WriteFile(pyprojectPath, initial, 0600))
		t.Chdir(dir)

		require.NoError(t, setCurationSourceInPyproject(repoName, repoURL, 0))

		written, err := os.ReadFile(pyprojectPath)
		require.NoError(t, err)
		out := string(written)
		assert.Contains(t, out, repoName, "fallback name must be written when pyproject has no existing source")
		assert.Contains(t, out, repoURL)
		assert.True(t, strings.Contains(out, "tool.poetry.source") || strings.Contains(out, "[tool.poetry]"),
			"expected pyproject.toml to retain a tool.poetry section, got:\n%s", out)
	})

	t.Run("existing single source with different name — name preserved, url rewritten", func(t *testing.T) {
		dir := t.TempDir()
		initial := []byte(`[tool.poetry]
name = "test-project"
version = "0.1.0"

[[tool.poetry.source]]
name = "poetry-test"
url = "https://example.com/artifactory/api/pypi/my-curation-repo/simple"
`)
		pyprojectPath := filepath.Join(dir, pyprojectToml)
		require.NoError(t, os.WriteFile(pyprojectPath, initial, 0600))
		t.Chdir(dir)

		require.NoError(t, setCurationSourceInPyproject(repoName, repoURL, 0))

		written, err := os.ReadFile(pyprojectPath)
		require.NoError(t, err)
		out := string(written)

		assert.Contains(t, out, `name = "poetry-test"`,
			"user's source name must be preserved so poetry.lock stays in sync; got:\n%s", out)
		assert.Contains(t, out, repoURL, "URL must be rewritten to the curation pass-through")
		assert.NotContains(t, out, `name = "`+repoName+`"`,
			"the Artifactory repo name must NOT replace the user's source name when one already exists; got:\n%s", out)
	})

	t.Run("existing multi-source — all names preserved, all urls rewritten", func(t *testing.T) {
		dir := t.TempDir()
		initial := []byte(`[tool.poetry]
name = "test-project"
version = "0.1.0"

[[tool.poetry.source]]
name = "primary-mirror"
url = "https://example.com/artifactory/api/pypi/my-curation-repo/simple"

[[tool.poetry.source]]
name = "secondary-mirror"
url = "https://example.com/artifactory/api/pypi/other-repo/simple"
`)
		pyprojectPath := filepath.Join(dir, pyprojectToml)
		require.NoError(t, os.WriteFile(pyprojectPath, initial, 0600))
		t.Chdir(dir)

		require.NoError(t, setCurationSourceInPyproject(repoName, repoURL, 0))

		written, err := os.ReadFile(pyprojectPath)
		require.NoError(t, err)
		out := string(written)

		assert.Contains(t, out, `name = "primary-mirror"`, "first source name must be preserved; got:\n%s", out)
		assert.Contains(t, out, `name = "secondary-mirror"`, "second source name must be preserved; got:\n%s", out)
		assert.Contains(t, out, repoURL, "URLs must be rewritten to the curation pass-through")
		assert.NotContains(t, out, "/api/pypi/my-curation-repo/simple",
			"original non-curation URL on first source must be replaced")
		assert.NotContains(t, out, "/api/pypi/other-repo/simple",
			"original non-curation URL on second source must be replaced")
	})

	t.Run("dotted dependency name is not corrupted", func(t *testing.T) {
		dir := t.TempDir()
		initial := []byte(`[tool.poetry]
name = "test-project"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
"zope.interface" = "5.0.0"
`)
		pyprojectPath := filepath.Join(dir, pyprojectToml)
		require.NoError(t, os.WriteFile(pyprojectPath, initial, 0600))
		t.Chdir(dir)

		require.NoError(t, setCurationSourceInPyproject(repoName, repoURL, 1))

		written, err := os.ReadFile(pyprojectPath)
		require.NoError(t, err)
		out := string(written)

		assert.Contains(t, out, `"zope.interface" = "5.0.0"`,
			"quoted dotted dependency key must survive the pyproject.toml rewrite; got:\n%s", out)
		assert.Contains(t, out, repoURL)
	})
}

func TestExtractPoetrySourceNames(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, extractPoetrySourceNames(nil))
	})
	t.Run("wrong type returns nil", func(t *testing.T) {
		assert.Nil(t, extractPoetrySourceNames("not-an-array"))
		assert.Nil(t, extractPoetrySourceNames(map[string]any{"name": "x"}))
	})
	t.Run("entries without name are skipped", func(t *testing.T) {
		got := extractPoetrySourceNames([]any{
			map[string]any{"url": "https://x"},
			map[string]any{"name": "named", "url": "https://y"},
			map[string]any{"name": "   ", "url": "https://z"},
		})
		assert.Equal(t, []string{"named"}, got)
	})
	t.Run("duplicate names are deduped, order preserved", func(t *testing.T) {
		got := extractPoetrySourceNames([]any{
			map[string]any{"name": "a", "url": "https://1"},
			map[string]any{"name": "b", "url": "https://2"},
			map[string]any{"name": "a", "url": "https://3"},
		})
		assert.Equal(t, []string{"a", "b"}, got)
	})
}

func TestStripPoetrySourceBlocks(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{
			name: "no source blocks — content unchanged",
			in:   "[tool.poetry]\nname = \"x\"\n",
			want: "[tool.poetry]\nname = \"x\"\n",
		},
		{
			name: "single source block stripped, following section kept",
			in:   "[tool.poetry]\nname = \"x\"\n[[tool.poetry.source]]\nname = \"pypi\"\nurl = \"https://pypi.org\"\n[tool.poetry.dependencies]\npython = \"^3.9\"\n",
			want: "[tool.poetry]\nname = \"x\"\n[tool.poetry.dependencies]\npython = \"^3.9\"\n",
		},
		{
			name: "two consecutive source blocks stripped without consuming next section",
			in:   "[tool.poetry]\nname = \"x\"\n[[tool.poetry.source]]\nname = \"a\"\nurl = \"https://a\"\n[[tool.poetry.source]]\nname = \"b\"\nurl = \"https://b\"\n[tool.poetry.dependencies]\npython = \"^3.9\"\n",
			want: "[tool.poetry]\nname = \"x\"\n[tool.poetry.dependencies]\npython = \"^3.9\"\n",
		},
		{
			// The source block extends to EOF, so the trailing empty line
			// produced by the final newline is consumed along with it.
			name: "source block at EOF",
			in:   "[tool.poetry]\nname = \"x\"\n[[tool.poetry.source]]\nname = \"pypi\"\n",
			want: "[tool.poetry]\nname = \"x\"",
		},
		{
			name: "indented source header is still stripped",
			in:   "[tool.poetry]\n  [[tool.poetry.source]]\n  name = \"pypi\"\n[tool.poetry.dependencies]\n",
			want: "[tool.poetry]\n[tool.poetry.dependencies]\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, stripPoetrySourceBlocks(tc.in))
		})
	}
}

// TestBuildPoetryDownloadUrl_HTTP exercises the simple-index lookup that
// resolves a poetry.lock package to an absolute Artifactory download URL.
// The function:
//   - GETs /api/pypi/{repo}/simple/{normalized-name}/
//   - scans the body for an <a href> whose basename matches one of pkg.Files
//   - returns the href resolved against the simple-index URL
//
// The three cases below cover the happy path, the upstream-error path, and
// the listing-without-match path.
func TestBuildPoetryDownloadUrl_HTTP(t *testing.T) {
	const repo = "pypi-curation"
	pkg := poetryLockPackage{
		Name:    "telnyx",
		Version: "4.87.1",
		Files:   []string{"telnyx-4.87.1.tar.gz", "telnyx-4.87.1-py3-none-any.whl"},
	}

	t.Run("200 with matching filename returns absolute URL", func(t *testing.T) {
		server, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/simple/telnyx/") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body>
<a href="../../packages/aa/bb/telnyx-4.87.1.tar.gz#sha256=abc">telnyx-4.87.1.tar.gz</a>
</body></html>`))
				return
			}
			t.Fatalf("unexpected request to %s", r.URL.Path)
		})
		defer server.Close()
		httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

		got, err := buildPoetryDownloadUrl(rtManager, &httpDetails, server.URL, repo, pkg)
		require.NoError(t, err)
		assert.Contains(t, got, "/packages/aa/bb/telnyx-4.87.1.tar.gz", "resolved URL must include the matched file path")
		assert.True(t, strings.HasPrefix(got, server.URL), "resolved URL must be absolute against the simple-index base, got %q", got)
		assert.NotContains(t, got, "#", "fragment must be stripped from the returned URL")
	})

	t.Run("non-200 from simple-index surfaces status code", func(t *testing.T) {
		server, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		defer server.Close()
		httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

		_, err := buildPoetryDownloadUrl(rtManager, &httpDetails, server.URL, repo, pkg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "404")
		assert.Contains(t, err.Error(), "simple-index")
	})

	t.Run("200 with no matching filename returns error", func(t *testing.T) {
		server, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>
<a href="../../packages/aa/bb/telnyx-1.0.0.tar.gz">telnyx-1.0.0.tar.gz</a>
</body></html>`))
		})
		defer server.Close()
		httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

		_, err := buildPoetryDownloadUrl(rtManager, &httpDetails, server.URL, repo, pkg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no matching href")
	})

	t.Run("uses normalized name in simple-index URL", func(t *testing.T) {
		// PEP 503: the URL segment must be the normalized name. A package
		// declared as "Flask_Babel" in poetry.lock must hit /simple/flask-babel/.
		var seenPath string
		server, _, rtManager := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			seenPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<a href="../../packages/aa/Flask_Babel-1.0.tar.gz">Flask_Babel-1.0.tar.gz</a>`))
		})
		defer server.Close()
		httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

		quirky := poetryLockPackage{Name: "Flask_Babel", Version: "1.0", Files: []string{"Flask_Babel-1.0.tar.gz"}}
		_, err := buildPoetryDownloadUrl(rtManager, &httpDetails, server.URL, repo, quirky)
		require.NoError(t, err)
		assert.Contains(t, seenPath, "/simple/flask-babel/", "must use PEP 503 normalized name in the simple-index URL, got %q", seenPath)
	})
}

func TestParsePoetryVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Poetry (version 1.8.3)", "1.8.3"},
		{"Poetry version 1.5.0", "1.5.0"},
		{"Poetry (version 2.0.0)", "2.0.0"},
		{"Poetry version 1.2.0", "1.2.0"},
		{"", ""},
		{"some unrelated output", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, parsePoetryVersion(tt.in))
		})
	}
}

// writeFakeExecutable creates a platform-appropriate fake executable named
// executableName in dir and prepends dir to PATH so the fake shadows any real
// installation. On Unix it writes a shell script; on Windows a batch script.
func writeFakeExecutable(t *testing.T, dir, executableName, shContent, batContent string) {
	t.Helper()
	name := filepath.Join(dir, executableName)
	content := shContent
	if runtime.GOOS == "windows" {
		name += ".bat"
		content = batContent
	}
	require.NoError(t, os.WriteFile(name, []byte(content), 0755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestValidateMinimumPoetryVersionUnparsableMajorErrors(t *testing.T) {
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "poetry",
		"#!/bin/sh\necho 'Poetry (version 2x.0.0)'\n",
		"@echo off\necho Poetry (version 2x.0.0)\n",
	)

	major, err := validateMinimumPoetryVersion(CurationPoetryMinimumVersion)
	require.Error(t, err, "unparsable major version must return an error, not (0, nil)")
	assert.Equal(t, 0, major)
}

func TestInstallPoetryDepsLockCheckErrorSurfacedOnRelockFailure(t *testing.T) {
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "poetry",
		`#!/bin/sh
case "$*" in
  *"--version"*) echo "Poetry (version 1.8.0)"; exit 0 ;;
  *"check"*"--lock"*) echo "Error: SyntaxError in pyproject.toml at line 12" >&2; exit 1 ;;
  *"lock"*) echo "Error: cannot resolve dependencies" >&2; exit 1 ;;
  *) echo "unexpected call: $*" >&2; exit 2 ;;
esac
`,
		// Dispatches on %1 (the first argument) to avoid echo %* | findstr, which
		// breaks if any argument contains a cmd.exe metacharacter (|, >, &, <).
		`@echo off
if "%1"=="--version" goto :ver
if "%1"=="check" goto :chk
if "%1"=="lock" goto :lck
echo unexpected call: %* 1>&2
exit /b 2
:ver
echo Poetry (version 1.8.0)
exit /b 0
:chk
echo Error: SyntaxError in pyproject.toml at line 12 1>&2
exit /b 1
:lck
echo Error: cannot resolve dependencies 1>&2
exit /b 1
`,
	)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, poetryLockFile), []byte("# lock\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, pyprojectToml), []byte("[tool.poetry]\nname=\"x\"\n"), 0600))
	t.Chdir(dir)

	_, _, err := installPoetryDeps(technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SyntaxError",
		"original check error must appear in the returned error chain")
}

func TestInstallPoetryDepsNonCurationErrorPropagated(t *testing.T) {
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "poetry",
		"#!/bin/sh\necho 'install failed' >&2\nexit 1\n",
		"@echo off\necho install failed 1>&2\nexit /b 1\n",
	)

	_, _, err := installPoetryDeps(technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          false,
		DependenciesRepository: "",
	})

	require.Error(t, err, "non-curation poetry install failure must propagate to the caller")
}

func TestWrapPoetryCurationErrReturnsCvsBlockedError(t *testing.T) {
	// CVS-stripped version: poetry emits "X (version) which doesn't match any versions".
	lockErr := errors.New("Because sample-project depends on telnyx (4.87.1) which doesn't match any versions, version solving failed.")
	wrapped := wrapPoetryCurationErr(lockErr)

	var cvsErr *CvsBlockedError
	require.ErrorAs(t, wrapped, &cvsErr, "CVS-filtered poetry error must be wrapped as *CvsBlockedError")
	require.Len(t, cvsErr.Packages, 1)
	assert.Equal(t, "telnyx", cvsErr.Packages[0].Name)
	assert.Equal(t, "4.87.1", cvsErr.Packages[0].Version)
	assert.ErrorIs(t, cvsErr, lockErr, "CvsBlockedError must unwrap to the original lock error")
}

func TestWrapPoetryCurationErrNonCvsPassesThrough(t *testing.T) {
	// A plain poetry install error (not CVS) must not be wrapped as CvsBlockedError.
	lockErr := errors.New("SolverProblemError: incompatible package constraint")
	wrapped := wrapPoetryCurationErr(lockErr)

	var cvsErr *CvsBlockedError
	assert.False(t, errors.As(wrapped, &cvsErr), "non-CVS poetry error must not be wrapped as *CvsBlockedError")
	assert.ErrorIs(t, wrapped, lockErr)
}

func TestWrapPoetryCurationErrMsgToUserPath(t *testing.T) {
	// Poetry emits an HTTP 403 during poetry lock (real download block, not CVS
	// index stripping). IsForbiddenOutput recognises "http error 403" for poetry,
	// so GetMsgToUserForCurationBlock returns a non-empty user-facing message.
	// wrapPoetryCurationErr must join the original error with that message.
	lockErr := errors.New("http error 403 downloading https://artifactory.example.com/telnyx-4.87.1.tar.gz")
	wrapped := wrapPoetryCurationErr(lockErr)

	var cvsErr *CvsBlockedError
	assert.False(t, errors.As(wrapped, &cvsErr), "403-blocked poetry error must not be wrapped as *CvsBlockedError")
	assert.ErrorIs(t, wrapped, lockErr, "original lockErr must be in the error chain")
	assert.Contains(t, wrapped.Error(), "poetry", "user-facing message must mention the package manager")
}

func TestParsePipenvVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"pipenv, version 2023.7.4", "2023.7.4"},
		{"pipenv, version 2026.6.1", "2026.6.1"},
		{"pipenv, version 2022.1.8", "2022.1.8"},
		// Extra whitespace / prefix lines must still match
		{"some preamble\npipenv, version 2024.11.26\n", "2024.11.26"},
		// Non-matching strings
		{"", ""},
		{"some unrelated output", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, parsePipenvVersion(tt.in))
		})
	}
}

func TestValidateMinimumPipenvVersionOk(t *testing.T) {
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\necho 'pipenv, version 2025.0.0'\n",
		"@echo off\necho pipenv, version 2025.0.0\n",
	)
	require.NoError(t, validateMinimumPipenvVersion())
}

func TestValidateMinimumPipenvVersionTooOld(t *testing.T) {
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\necho 'pipenv, version 2022.1.1'\n",
		"@echo off\necho pipenv, version 2022.1.1\n",
	)
	err := validateMinimumPipenvVersion()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2023.7.4", "error must mention the minimum required version")
	assert.Contains(t, err.Error(), "2022.1.1", "error must mention the installed version")
}

func TestValidateMinimumPipenvVersionUnparsable(t *testing.T) {
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\necho 'unrecognized output'\n",
		"@echo off\necho unrecognized output\n",
	)
	err := validateMinimumPipenvVersion()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestInstallPipenvDepsCurationNoRepoNoNativeErrors(t *testing.T) {
	// When IsCurationCmd=true, no DependenciesRepository, and no Pipfile with an
	// Artifactory [[source]], installPipenvDeps must return an actionable error.
	dir := t.TempDir()
	t.Chdir(dir)
	pipConfigPath := filepath.Join(dir, "pip.conf")
	require.NoError(t, os.WriteFile(pipConfigPath, nil, 0600))
	t.Setenv("PIP_CONFIG_FILE", pipConfigPath)
	require.NoError(t, os.WriteFile(pipfileFile, []byte(`[[source]]
name = "pypi"
url = "https://pypi.org/simple"

[packages]
requests = "*"
`), 0600))
	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		DependenciesRepository: "",
	}
	_, restore, err := installPipenvDeps(params)
	require.NotNil(t, restore)
	t.Cleanup(func() { require.NoError(t, restore()) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pipenv-config")
	assert.Contains(t, err.Error(), "Pipfile")
}

func TestInstallPipenvDepsCurationNativeFromPipfile(t *testing.T) {
	// When IsCurationCmd=true and no DependenciesRepository but Pipfile has an
	// Artifactory [[source]], installPipenvDeps must detect the repo natively
	// and call runPipenvInstallFromRemoteRegistry (which will fail here because
	// pipenv isn't installed in the test env — but it must NOT error with the
	// "pipenv-config" message; it must get past native detection).
	fakeDir := t.TempDir()
	testURL := "https://myuser:mytoken@myartifactory.jfrog.io/artifactory/api/pypi/my-pip-repo/simple" // #nosec G101 -- test fixture, not a real credential
	pipfileContent := fmt.Sprintf(`[[source]]
url = "%s"
verify_ssl = true
name = "artifactory"

[packages]
requests = "==2.31.0"
`, testURL)
	require.NoError(t, os.WriteFile(filepath.Join(fakeDir, "Pipfile"), []byte(pipfileContent), 0644))
	t.Chdir(fakeDir)

	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		DependenciesRepository: "",
	}
	_, restore, err := installPipenvDeps(params)
	require.NotNil(t, restore)
	t.Cleanup(func() { require.NoError(t, restore()) })
	// The call will fail because pipenv/virtualenv is not available in the test
	// environment, but it must NOT fail with a "pipenv-config/Pipfile" config error.
	if err != nil {
		assert.NotContains(t, err.Error(), "pipenv-config", "native detection must succeed; error must come from pipenv CLI, not config")
		assert.NotContains(t, err.Error(), "Artifactory [[source]]", "native detection must succeed; error must come from pipenv CLI, not config")
	}
}

func TestParsePipfileArtifactorySource(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantRepo   string
		wantArtURL string
		wantUser   string
		wantPass   string
	}{
		{
			name:       "standard Artifactory pypi source with credentials",
			content:    "[[source]]\nurl = \"https://myuser:mytoken@myartifactory.jfrog.io/artifactory/api/pypi/my-pip-repo/simple\"\nverify_ssl = true\nname = \"artifactory\"", // #nosec G101 -- test fixture, not a real credential
			wantRepo:   "my-pip-repo",
			wantArtURL: "https://myartifactory.jfrog.io/artifactory/",
			wantUser:   "myuser",
			wantPass:   "mytoken",
		},
		{
			name:       "package index selects Artifactory source",
			content:    "[[source]]\nurl = \"https://acme.jfrog.io/artifactory/api/pypi/curation-repo/simple\"\nname = \"primary\"\n\n[[source]]\nurl = \"https://admin:s3cret@acme.jfrog.io/artifactory/api/pypi/curation-repo/simple\"\nname = \"jfrog\"\n\n[packages]\nrequests = {version = \"*\", index = \"jfrog\"}", // #nosec G101 -- test fixture, not a real credential
			wantRepo:   "curation-repo",
			wantArtURL: "https://acme.jfrog.io/artifactory/",
			wantUser:   "admin",
			wantPass:   "s3cret",
		},
		{
			name: "no Artifactory source — returns empty",
			content: `[[source]]
url = "https://pypi.org/simple"
name = "pypi"`,
			wantRepo: "",
		},
		{
			name:     "empty Pipfile",
			content:  "",
			wantRepo: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			pipfilePath := filepath.Join(dir, "Pipfile")
			require.NoError(t, os.WriteFile(pipfilePath, []byte(tt.content), 0644))

			sd, repo, err := ParsePipfileArtifactorySource(pipfilePath)
			require.NoError(t, err)
			assert.Equal(t, tt.wantRepo, repo)
			if tt.wantRepo == "" {
				assert.Nil(t, sd)
				return
			}
			require.NotNil(t, sd)
			assert.Equal(t, tt.wantArtURL, sd.ArtifactoryUrl)
			assert.Equal(t, tt.wantUser, sd.User)
			assert.Equal(t, tt.wantPass, sd.Password)
		})
	}
}

func TestEffectivePipfileSourceNames(t *testing.T) {
	t.Run("Sources[0] is effective for an index-less package", func(t *testing.T) {
		cfg := pipfileConfig{
			Sources: []pipfileSource{
				{Name: "jfrog", URL: "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"},
				{Name: "other", URL: "https://packages.example.com/simple"},
			},
			Packages: map[string]any{"requests": "*"},
		}
		names, err := effectivePipfileSourceNames(cfg)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"jfrog"}, names)
	})

	t.Run("Sources[0] is not effective when every package has an explicit index", func(t *testing.T) {
		cfg := pipfileConfig{
			Sources: []pipfileSource{
				{Name: "other", URL: "https://packages.example.com/simple"},
				{Name: "jfrog", URL: "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"},
			},
			Packages: map[string]any{
				"requests": map[string]any{"version": "*", "index": "jfrog"},
			},
		}
		names, err := effectivePipfileSourceNames(cfg)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"jfrog"}, names)
	})

	t.Run("no sources and no index assignment is valid", func(t *testing.T) {
		cfg := pipfileConfig{Packages: map[string]any{"requests": "*"}}
		names, err := effectivePipfileSourceNames(cfg)
		require.NoError(t, err)
		assert.Empty(t, names)
	})

	t.Run("no sources but an index assignment errors", func(t *testing.T) {
		cfg := pipfileConfig{
			Packages: map[string]any{"requests": map[string]any{"version": "*", "index": "jfrog"}},
		}
		_, err := effectivePipfileSourceNames(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no [[source]] entries")
	})

	t.Run("no packages falls back to Sources[0]", func(t *testing.T) {
		cfg := pipfileConfig{
			Sources: []pipfileSource{
				{Name: "jfrog", URL: "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"},
				{Name: "other", URL: "https://packages.example.com/simple"},
			},
		}
		names, err := effectivePipfileSourceNames(cfg)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"jfrog"}, names)
	})
}

func TestMergePipenvCredentials(t *testing.T) {
	target := &config.ServerDetails{ArtifactoryUrl: "https://acme.jfrog.io/artifactory/"}
	endpoint, err := endpointFromServer(target, "repo")
	require.NoError(t, err)

	t.Run("no credentials anywhere is not an error", func(t *testing.T) {
		merged, err := mergePipenvCredentials(target, endpoint, nil, nil)
		require.NoError(t, err)
		assert.Empty(t, merged.User)
		assert.Empty(t, merged.Password)
		assert.Empty(t, merged.AccessToken)
	})

	t.Run("complete source credentials are selected", func(t *testing.T) {
		source := &config.ServerDetails{User: "u", Password: "p"}
		merged, err := mergePipenvCredentials(target, endpoint, []*config.ServerDetails{source}, nil)
		require.NoError(t, err)
		assert.Equal(t, "u", merged.User)
		assert.Equal(t, "p", merged.Password)
	})

	t.Run("access token wins over password on the selected source", func(t *testing.T) {
		source := &config.ServerDetails{User: "u", Password: "p", AccessToken: "tok"}
		merged, err := mergePipenvCredentials(target, endpoint, []*config.ServerDetails{source}, nil)
		require.NoError(t, err)
		assert.Equal(t, "tok", merged.AccessToken)
		assert.Empty(t, merged.Password)
	})

	t.Run("partial source credentials error", func(t *testing.T) {
		source := &config.ServerDetails{User: "u"}
		_, err := mergePipenvCredentials(target, endpoint, []*config.ServerDetails{source}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "selected Pipfile source has incomplete credentials")
	})

	t.Run("conflicting complete source credentials error", func(t *testing.T) {
		sourceA := &config.ServerDetails{User: "a", Password: "p"}
		sourceB := &config.ServerDetails{User: "b", Password: "p"}
		_, err := mergePipenvCredentials(target, endpoint, []*config.ServerDetails{sourceA, sourceB}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflicting credentials")
	})

	t.Run("agreeing complete source credentials do not conflict", func(t *testing.T) {
		sourceA := &config.ServerDetails{User: "u", Password: "p"}
		sourceB := &config.ServerDetails{User: "u", Password: "p"}
		merged, err := mergePipenvCredentials(target, endpoint, []*config.ServerDetails{sourceA, sourceB}, nil)
		require.NoError(t, err)
		assert.Equal(t, "u", merged.User)
	})

	t.Run("configured resolver credentials are used when no source has any", func(t *testing.T) {
		withCreds := &config.ServerDetails{ArtifactoryUrl: target.ArtifactoryUrl, User: "u", Password: "p"}
		merged, err := mergePipenvCredentials(withCreds, endpoint, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "u", merged.User)
	})

	t.Run("configured resolver partial credentials error", func(t *testing.T) {
		withCreds := &config.ServerDetails{ArtifactoryUrl: target.ArtifactoryUrl, User: "u"}
		_, err := mergePipenvCredentials(withCreds, endpoint, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configured resolver has incomplete credentials")
	})

	t.Run("matching fallback credentials are used as a last resort", func(t *testing.T) {
		fallback := &config.ServerDetails{ArtifactoryUrl: target.ArtifactoryUrl, User: "u", Password: "p"}
		merged, err := mergePipenvCredentials(target, endpoint, nil, fallback)
		require.NoError(t, err)
		assert.Equal(t, "u", merged.User)
		assert.Equal(t, target.ArtifactoryUrl, merged.ArtifactoryUrl)
	})

	t.Run("matching fallback partial credentials error", func(t *testing.T) {
		fallback := &config.ServerDetails{ArtifactoryUrl: target.ArtifactoryUrl, User: "u"}
		_, err := mergePipenvCredentials(target, endpoint, nil, fallback)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "matching JFrog server has incomplete credentials")
	})

	t.Run("non-matching fallback is ignored even with credentials", func(t *testing.T) {
		fallback := &config.ServerDetails{ArtifactoryUrl: "https://other.jfrog.io/artifactory/", User: "u", Password: "p"}
		merged, err := mergePipenvCredentials(target, endpoint, nil, fallback)
		require.NoError(t, err)
		assert.Empty(t, merged.User)
	})
}

func TestParsePipfileArtifactorySourceNotFound(t *testing.T) {
	_, _, err := ParsePipfileArtifactorySource("/nonexistent/path/Pipfile")
	require.Error(t, err)
}

func TestResolvePipfileArtifactorySource(t *testing.T) {
	writePipfile := func(t *testing.T, content string) string {
		path := filepath.Join(t.TempDir(), "Pipfile")
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
		return path
	}
	target := &config.ServerDetails{
		ArtifactoryUrl: "https://acme.jfrog.io/artifactory/",
		XrayUrl:        "https://acme.jfrog.io/xray/",
		User:           "configured-user",
		Password:       "configured-token", // #nosec G101 -- test fixture
	}

	t.Run("source aliases for the same endpoint are allowed", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"

[[source]]
name = "alias"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"

[packages]
requests = "*"
`)
		server, repo, err := ResolvePipfileArtifactorySource(path, target, "repo", nil)
		require.NoError(t, err)
		assert.Equal(t, "repo", repo)
		assert.Equal(t, "configured-token", server.Password)
	})

	t.Run("unused secondary endpoint does not affect resolution", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"

[[source]]
name = "other"
url = "https://bad-user-only@packages.example.com/simple"

[packages]
requests = "*"
`)
		server, repo, err := ResolvePipfileArtifactorySource(path, target, "repo", nil)
		require.NoError(t, err)
		assert.Equal(t, "repo", repo)
		assert.Equal(t, "configured-token", server.Password)
	})

	t.Run("unused non-Artifactory Sources[0] does not affect resolution", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "other"
url = "https://bad-user-only@packages.example.com/simple"

[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"

[packages]
requests = {version = "*", index = "jfrog"}
`)
		server, repo, err := ResolvePipfileArtifactorySource(path, target, "repo", nil)
		require.NoError(t, err)
		assert.Equal(t, "repo", repo)
		assert.Equal(t, "configured-token", server.Password)
	})

	t.Run("unused Artifactory source is not selected natively", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "pypi"
url = "https://pypi.org/simple"

[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"

[packages]
requests = "*"
`)
		server, repo, err := ResolvePipfileArtifactorySource(path, nil, "", nil)
		require.NoError(t, err)
		assert.Nil(t, server)
		assert.Empty(t, repo)
	})

	t.Run("assigned secondary endpoint is rejected", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"

[[source]]
name = "other"
url = "https://packages.example.com/simple"

[packages]
requests = {version = "*", index = "other"}
`)
		_, _, err := ResolvePipfileArtifactorySource(path, target, "repo", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `source "other"`)
	})

	t.Run("search all sources rejects another endpoint", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"

[[source]]
name = "other"
url = "https://packages.example.com/simple"

[packages]
requests = "*"

[pipenv]
install_search_all_sources = true
`)
		_, _, err := ResolvePipfileArtifactorySource(path, target, "repo", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `source "other"`)
	})

	t.Run("duplicate source names are rejected", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"

[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/other/simple"
`)
		_, _, err := ResolvePipfileArtifactorySource(path, target, "repo", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate source name")
	})

	t.Run("complete source credentials win", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://source-user:source-token@acme.jfrog.io/artifactory/api/pypi/repo/simple"
`)
		server, _, err := ResolvePipfileArtifactorySource(path, target, "repo", nil)
		require.NoError(t, err)
		assert.Equal(t, "source-user", server.User)
		assert.Equal(t, "source-token", server.Password)
	})

	t.Run("matching fallback supplies credentials", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"
`)
		credentialless := &config.ServerDetails{ArtifactoryUrl: target.ArtifactoryUrl}
		server, _, err := ResolvePipfileArtifactorySource(path, credentialless, "repo", target)
		require.NoError(t, err)
		assert.Equal(t, "configured-user", server.User)
		assert.Equal(t, "configured-token", server.Password)
		assert.Equal(t, target.XrayUrl, server.XrayUrl)
	})

	t.Run("access token takes precedence over configured password", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"
`)
		withToken := *target
		withToken.AccessToken = "access-token" // #nosec G101 -- test fixture
		server, _, err := ResolvePipfileArtifactorySource(path, &withToken, "repo", nil)
		require.NoError(t, err)
		assert.Equal(t, "access-token", server.AccessToken)
		assert.Empty(t, server.Password)
	})

	t.Run("different endpoint fallback credentials are ignored", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://acme.jfrog.io/artifactory/api/pypi/repo/simple"
`)
		credentialless := &config.ServerDetails{ArtifactoryUrl: target.ArtifactoryUrl}
		other := &config.ServerDetails{
			ArtifactoryUrl: "https://other.jfrog.io/artifactory/",
			User:           "wrong",
			Password:       "wrong-token", // #nosec G101 -- test fixture
		}
		server, _, err := ResolvePipfileArtifactorySource(path, credentialless, "repo", other)
		require.NoError(t, err)
		assert.Empty(t, server.User)
		assert.Empty(t, server.Password)
	})

	t.Run("unsafe repository name is rejected", func(t *testing.T) {
		path := writePipfile(t, "[packages]\nrequests = \"*\"\n")
		_, _, err := ResolvePipfileArtifactorySource(path, target, "..", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid configured resolver")
	})

	t.Run("unset credential variable is an error", func(t *testing.T) {
		t.Setenv("PIPENV_TEST_USER", "user")
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://$PIPENV_TEST_USER:$PIPENV_MISSING_TOKEN@acme.jfrog.io/artifactory/api/pypi/repo/simple"
`)
		_, _, err := ResolvePipfileArtifactorySource(path, nil, "", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PIPENV_MISSING_TOKEN")
		assert.NotContains(t, err.Error(), "https://")
	})

	t.Run("encoded credentials remain decoded once", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://user:p%40ss%2Fword@acme.jfrog.io/artifactory/api/pypi/repo/simple"
`)
		server, _, err := ResolvePipfileArtifactorySource(path, nil, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "p@ss/word", server.Password)
	})

	t.Run("expanded credential may contain dollar sign", func(t *testing.T) {
		t.Setenv("PIPENV_DOLLAR_TOKEN", "tok$en")
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://user:$PIPENV_DOLLAR_TOKEN@acme.jfrog.io/artifactory/api/pypi/repo/simple"
`)
		server, _, err := ResolvePipfileArtifactorySource(path, nil, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "tok$en", server.Password)
	})

	t.Run("dotenv credentials are expanded", func(t *testing.T) {
		path := writePipfile(t, `[[source]]
name = "jfrog"
url = "https://$PIPENV_DOTENV_USER:${PIPENV_DOTENV_TOKEN}@acme.jfrog.io/artifactory/api/pypi/repo/simple"
`)
		require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(path), ".env"),
			[]byte("PIPENV_DOTENV_USER=dotenv-user\nPIPENV_DOTENV_TOKEN=dotenv-token\n"), 0600)) // #nosec G101 -- test fixture
		server, _, err := ResolvePipfileArtifactorySource(path, nil, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "dotenv-user", server.User)
		assert.Equal(t, "dotenv-token", server.Password)
	})

	t.Run("environment expansion follows platform syntax", func(t *testing.T) {
		environment := map[string]string{"PIPENV_WINDOWS_USER": "windows-user"}
		expanded, err := expandPipfileEnvVarsForOS(
			"https://%pipenv_windows_user%@acme.example.com/$PIPENV_WINDOWS_USER", "jfrog", environment, "windows")
		require.NoError(t, err)
		assert.Equal(t, "https://windows-user@acme.example.com/windows-user", expanded)

		expanded, err = expandPipfileEnvVarsForOS(
			"https://%PIPENV_WINDOWS_USER%@acme.example.com/$PIPENV_WINDOWS_USER", "jfrog", environment, "linux")
		require.NoError(t, err)
		assert.Equal(t, "https://%PIPENV_WINDOWS_USER%@acme.example.com/windows-user", expanded)
	})

	t.Run("Windows %% collapses to a literal percent, like ntpath.expandvars", func(t *testing.T) {
		expanded, err := expandPipfileEnvVarsForOS("https://acme.example.com/repo%%20name", "jfrog", nil, "windows")
		require.NoError(t, err)
		assert.Equal(t, "https://acme.example.com/repo%20name", expanded)
	})

	t.Run("adjacent Windows vars are parsed as two separate references", func(t *testing.T) {
		environment := map[string]string{"PIPENV_A": "aaa", "PIPENV_B": "bbb"}
		expanded, err := expandPipfileEnvVarsForOS("%PIPENV_A%%PIPENV_B%", "jfrog", environment, "windows")
		require.NoError(t, err)
		assert.Equal(t, "aaabbb", expanded)
	})
}

func TestParsePipConfigIndexUrl(t *testing.T) {
	cases := []struct {
		name        string
		content     string
		wantRepo    string
		wantArtURL  string
		wantUser    string
		wantNoMatch bool
	}{
		{
			name: "artifactory index-url with credentials",
			content: "[global]\n" +
				"index-url = https://admin:mytoken@myrt.jfrogdev.org/artifactory/api/pypi/my-pip-repo/simple\n",
			wantRepo:   "my-pip-repo",
			wantArtURL: "https://myrt.jfrogdev.org/artifactory/",
			wantUser:   "admin",
		},
		{
			name:        "plain pypi.org — not an artifactory URL",
			content:     "[global]\nindex-url = https://pypi.org/simple\n",
			wantNoMatch: true,
		},
		{
			name:        "no index-url key",
			content:     "[global]\ntimeout = 60\n",
			wantNoMatch: true,
		},
		{
			name:        "empty file",
			content:     "",
			wantNoMatch: true,
		},
		{
			name: "index-url with no credentials",
			content: "[global]\n" +
				"index-url = https://myrt.example.com/artifactory/api/pypi/libs-pypi/simple\n",
			wantRepo:   "libs-pypi",
			wantArtURL: "https://myrt.example.com/artifactory/",
		},
		{
			name: "only global index-url is used regardless of section order",
			content: "[install]\n" +
				"index-url = https://wrong.example.com/artifactory/api/pypi/wrong/simple\n" +
				"[global]\n" +
				"index-url = https://right.example.com/artifactory/api/pypi/right/simple\n",
			wantRepo:   "right",
			wantArtURL: "https://right.example.com/artifactory/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "pip.conf")
			require.NoError(t, err)
			_, err = f.WriteString(tc.content)
			require.NoError(t, err)
			require.NoError(t, f.Close())

			sd, repo, _, err := ParsePipConfigIndexUrl(f.Name())
			require.NoError(t, err)
			if tc.wantNoMatch {
				assert.Empty(t, repo)
				assert.Nil(t, sd)
				return
			}
			assert.Equal(t, tc.wantRepo, repo)
			require.NotNil(t, sd)
			assert.Equal(t, tc.wantArtURL, sd.ArtifactoryUrl)
			if tc.wantUser != "" {
				assert.Equal(t, tc.wantUser, sd.User)
			}
		})
	}
}

func TestParsePipConfigIndexUrlMissingFile(t *testing.T) {
	// A missing pip.conf is not an error — just returns nil/empty (graceful no-op).
	t.Setenv("PIP_CONFIG_FILE", "")
	sd, repo, _, err := ParsePipConfigIndexUrl("/nonexistent/path/pip.conf")
	require.NoError(t, err)
	assert.Empty(t, repo)
	assert.Nil(t, sd)
}

func TestParsePipConfigIndexUrlExplicitFailures(t *testing.T) {
	t.Run("missing explicit file is silently skipped, like pip's own PIP_CONFIG_FILE handling", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing-pip.conf")
		t.Setenv("PIP_CONFIG_FILE", path)
		sd, repo, _, err := ParsePipConfigIndexUrl(path)
		require.NoError(t, err)
		assert.Empty(t, repo)
		assert.Nil(t, sd)
	})

	t.Run("malformed explicit Artifactory URL", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pip.conf")
		require.NoError(t, os.WriteFile(path, []byte("[global]\nindex-url = https://rt.example.com/artifactory/api/pypi/repo\n"), 0600))
		t.Setenv("PIP_CONFIG_FILE", path)
		_, _, _, err := ParsePipConfigIndexUrl(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valid Artifactory PyPI URL")
		assert.Contains(t, err.Error(), path)
	})

	t.Run("malformed INI", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pip.conf")
		require.NoError(t, os.WriteFile(path, []byte("[global\nindex-url = value\n"), 0600))
		t.Setenv("PIP_CONFIG_FILE", path)
		_, _, _, err := ParsePipConfigIndexUrl(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse")
	})

	t.Run("duplicate index-url within one [global] section is rejected, not silently collapsed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pip.conf")
		require.NoError(t, os.WriteFile(path, []byte(
			"[global]\nindex-url = https://a.example.com/artifactory/api/pypi/a/simple\nindex-url = https://b.example.com/artifactory/api/pypi/b/simple\n"), 0600))
		_, _, _, err := ParsePipConfigIndexUrl(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "index-url more than once")
	})

	t.Run("case-colliding [global] sections are rejected, not silently collapsed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pip.conf")
		require.NoError(t, os.WriteFile(path, []byte(
			"[GLOBAL]\nindex-url = https://a.example.com/artifactory/api/pypi/a/simple\n[global]\nindex-url = https://b.example.com/artifactory/api/pypi/b/simple\n"), 0600))
		_, _, _, err := ParsePipConfigIndexUrl(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "[global] more than once")
	})
}

func TestDefaultPipConfPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix pip config paths")
	}
	t.Run("legacy then modern, legacy first for lowest priority", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("PIP_CONFIG_FILE", "")
		legacyPath := filepath.Join(home, ".pip", "pip.conf")
		modernPath := filepath.Join(home, ".config", "pip", "pip.conf")
		assert.Equal(t, []string{legacyPath, modernPath}, DefaultPipConfPaths())
	})
	if runtime.GOOS == "darwin" {
		t.Run("macOS prefers Application Support only if it already exists", func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("PIP_CONFIG_FILE", "")
			legacyPath := filepath.Join(home, ".pip", "pip.conf")
			xdgModernPath := filepath.Join(home, ".config", "pip", "pip.conf")
			assert.Equal(t, []string{legacyPath, xdgModernPath}, DefaultPipConfPaths(),
				"falls back to ~/.config when Application Support/pip doesn't exist")

			appSupportDir := filepath.Join(home, "Library", "Application Support", "pip")
			require.NoError(t, os.MkdirAll(appSupportDir, 0700))
			appSupportPath := filepath.Join(appSupportDir, "pip.conf")
			assert.Equal(t, []string{legacyPath, appSupportPath}, DefaultPipConfPaths(),
				"prefers Application Support once the directory exists")
		})
	}
	t.Run("PIP_CONFIG_FILE overrides both when it exists", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		envPath := filepath.Join(t.TempDir(), "explicit-pip.conf")
		require.NoError(t, os.WriteFile(envPath, nil, 0600))
		t.Setenv("PIP_CONFIG_FILE", envPath)
		assert.Equal(t, []string{envPath}, DefaultPipConfPaths(),
			"legacy/modern are skipped entirely once PIP_CONFIG_FILE resolves to an existing file")
	})
	t.Run("PIP_CONFIG_FILE appended as override when file doesn't exist yet", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", "")
		envPath := filepath.Join(t.TempDir(), "not-yet-created.conf")
		t.Setenv("PIP_CONFIG_FILE", envPath)
		legacyPath := filepath.Join(home, ".pip", "pip.conf")
		modernPath := filepath.Join(home, ".config", "pip", "pip.conf")
		assert.Equal(t, []string{legacyPath, modernPath, envPath}, DefaultPipConfPaths())
	})
}

func TestParsePipConfigIndexUrlMergesAcrossPaths(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.conf")
	modern := filepath.Join(dir, "modern.conf")
	require.NoError(t, os.WriteFile(legacy, []byte(
		"[global]\nindex-url = https://legacy.example.com/artifactory/api/pypi/legacy-repo/simple\n"), 0600))

	t.Run("modern overrides legacy when both define index-url", func(t *testing.T) {
		require.NoError(t, os.WriteFile(modern, []byte(
			"[global]\nindex-url = https://modern.example.com/artifactory/api/pypi/modern-repo/simple\n"), 0600))
		sd, repo, sourcePath, err := ParsePipConfigIndexUrl(legacy, modern)
		require.NoError(t, err)
		require.NotNil(t, sd)
		assert.Equal(t, "modern-repo", repo)
		assert.Equal(t, modern, sourcePath)
	})

	t.Run("legacy value survives when modern file has no index-url", func(t *testing.T) {
		require.NoError(t, os.WriteFile(modern, []byte("[global]\ntimeout = 60\n"), 0600))
		sd, repo, sourcePath, err := ParsePipConfigIndexUrl(legacy, modern)
		require.NoError(t, err)
		require.NotNil(t, sd)
		assert.Equal(t, "legacy-repo", repo)
		assert.Equal(t, legacy, sourcePath)
	})

	t.Run("missing files are skipped without error", func(t *testing.T) {
		sd, repo, sourcePath, err := ParsePipConfigIndexUrl(filepath.Join(dir, "missing.conf"), legacy)
		require.NoError(t, err)
		require.NotNil(t, sd)
		assert.Equal(t, "legacy-repo", repo)
		assert.Equal(t, legacy, sourcePath)
	})
}

func TestRunPipenvInstallNonCurationKeepsExistingInvocation(t *testing.T) {
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\nprintf '%s\\n' \"$@\" > pipenv-args.txt\nprintf '%s' \"$PIPENV_SKIP_LOCK\" > pipenv-skip-lock.txt\n",
		"@echo off\necho %* > pipenv-args.txt\necho %PIPENV_SKIP_LOCK% > pipenv-skip-lock.txt\n",
	)
	t.Chdir(t.TempDir())
	t.Setenv("PIPENV_SKIP_LOCK", "1")

	server := &config.ServerDetails{ArtifactoryUrl: "https://rt.example.com/artifactory/"}
	require.NoError(t, runPipenvInstallFromRemoteRegistry(server, "repo", false))

	args, err := os.ReadFile("pipenv-args.txt")
	require.NoError(t, err)
	assert.Contains(t, string(args), "install")
	assert.Contains(t, string(args), "-d")
	assert.Contains(t, string(args), "--pypi-mirror")
	assert.Contains(t, string(args), "/api/pypi/repo/simple")
	skipLock, err := os.ReadFile("pipenv-skip-lock.txt")
	require.NoError(t, err)
	assert.Equal(t, "1", strings.TrimSpace(string(skipLock)))
}

func TestRunPipenvInstallFromRemoteRegistryCurationVersionGate(t *testing.T) {
	// A pipenv below the minimum version must be rejected before any install attempt.
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\necho 'pipenv, version 2021.5.29'\n",
		"@echo off\necho pipenv, version 2021.5.29\n",
	)
	err := runPipenvInstallFromRemoteRegistry(nil, "my-repo", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), CurationPipenvMinimumVersion)
}

func TestRunPipenvInstallFromRemoteRegistryCuration403Detection(t *testing.T) {
	// Pipenv emits "HTTP error 403" during install of a blocked package.
	// build-info-go's IsForbiddenOutput has no "pipenv" case, so we check the
	// pattern directly.
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\n"+
			"if [ \"$1\" = \"--version\" ]; then echo 'pipenv, version 2025.0.0'; exit 0; fi\n"+
			"echo 'CRITICAL:pipenv.patched.pip._internal.network.download:HTTP error 403 while getting https://rt.example.com/api/pypi/repo/simple/urllib3/'\n"+
			"echo '[ResolutionFailure]: ...'\n"+
			"exit 1\n",
		"@echo off\n"+
			"if \"%1\"==\"--version\" (echo pipenv, version 2025.0.0 & exit /b 0)\n"+
			"echo HTTP error 403 while getting https://rt.example.com/api/pypi/repo/simple/urllib3/\n"+
			"exit /b 1\n",
	)
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", fakeDir+string(os.PathListSeparator)+origPath)

	wd := t.TempDir()
	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(wd))
	defer func() { _ = os.Chdir(origWd) }()
	require.NoError(t, os.WriteFile(pipfileFile, []byte("[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n"), 0600))

	sd := &config.ServerDetails{ArtifactoryUrl: "https://rt.example.com/artifactory/"}
	err = runPipenvInstallFromRemoteRegistry(sd, "repo", true)
	require.Error(t, err)
	// Must contain the user-facing curation message, not just a raw install error.
	assert.Contains(t, err.Error(), "Failed to retrieve the dependencies tree")
}

func TestRunPipenvInstallFromRemoteRegistryNoLockFileSucceeds(t *testing.T) {
	// Unlike the earlier (incorrect) assumption, 'pipenv install' does NOT need a
	// pre-existing Pipfile.lock for curation. --pypi-mirror points at the audit
	// pass-through endpoint, which — like pip's and poetry's pass-through routes —
	// always returns the artifact (200) regardless of policy. So pipenv's internal
	// auto-lock-on-install (triggered when Pipfile.lock is missing) succeeds even
	// though it downloads wheels to compute hashes.
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'pipenv, version 2025.0.0'; exit 0; fi\nexit 0\n",
		"@echo off\nif \"%1\"==\"--version\" (echo pipenv, version 2025.0.0 & exit /b 0)\nexit /b 0\n",
	)
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", fakeDir+string(os.PathListSeparator)+origPath)

	// Run in a directory with NO Pipfile.lock — must not error just because of that.
	wd := t.TempDir()
	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(wd))
	defer func() { _ = os.Chdir(origWd) }()
	require.NoError(t, os.WriteFile(pipfileFile, []byte("[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n"), 0600))

	sd := &config.ServerDetails{ArtifactoryUrl: "https://rt.example.com/artifactory/"}
	require.NoError(t, runPipenvInstallFromRemoteRegistry(sd, "repo", true))
}

func TestRunPipenvInstallFromRemoteRegistryReturnsCvsBlockedError(t *testing.T) {
	// When pipenv's internal pip emits a CVS-filtered error ("No matching distribution
	// found" / "Could not find a version that satisfies the requirement"),
	// runPipenvInstallFromRemoteRegistry must wrap it as *CvsBlockedError so that
	// the curation-audit command can run the metadata-API fallback instead of
	// aborting with no report.
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\n"+
			"if [ \"$1\" = \"--version\" ]; then echo 'pipenv, version 2025.0.0'; exit 0; fi\n"+
			"echo 'CRITICAL:pipenv.patched.pip._internal.resolution.resolvelib.factory:Could not find a version that satisfies the requirement urllib3==2.0.7 (from versions: none)'\n"+
			"echo 'ERROR: No matching distribution found for urllib3==2.0.7'\n"+
			"exit 1\n",
		"@echo off\n"+
			"if \"%1\"==\"--version\" (echo pipenv, version 2025.0.0 & exit /b 0)\n"+
			"echo Could not find a version that satisfies the requirement urllib3==2.0.7\n"+
			"echo ERROR: No matching distribution found for urllib3==2.0.7\n"+
			"exit /b 1\n",
	)
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", fakeDir+string(os.PathListSeparator)+origPath)

	wd := t.TempDir()
	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(wd))
	defer func() { _ = os.Chdir(origWd) }()
	require.NoError(t, os.WriteFile(pipfileFile, []byte("[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n"), 0600))

	sd := &config.ServerDetails{ArtifactoryUrl: "https://rt.example.com/artifactory/"}
	err = runPipenvInstallFromRemoteRegistry(sd, "repo", true)
	require.Error(t, err)

	var cvsErr *CvsBlockedError
	require.ErrorAs(t, err, &cvsErr, "CVS-filtered pipenv error must be wrapped as *CvsBlockedError")
	require.Len(t, cvsErr.Packages, 1)
	assert.Equal(t, "urllib3", cvsErr.Packages[0].Name)
	assert.Equal(t, "2.0.7", cvsErr.Packages[0].Version)
}

func TestRunPipenvInstallKeepsCredentialsOutOfArgvAndErrors(t *testing.T) {
	fakeDir := t.TempDir()
	writeFakeExecutable(t, fakeDir, "pipenv",
		"#!/bin/sh\n"+
			"if [ \"$1\" = \"--version\" ]; then echo 'pipenv, version 2025.0.0'; exit 0; fi\n"+
			"printf '%s\\n' \"$@\" > pipenv-args.txt\n"+
			"printf 'PIPFILE=%s\\nSKIP=%s\\nIGNORE=%s\\n' \"$PIPENV_PIPFILE\" \"$PIPENV_SKIP_LOCK\" \"$PIPENV_IGNORE_PIPFILE\" > pipenv-env.txt\n"+
			"echo 'failed https://user:super-secret@rt.example.com/artifactory/api/curation/audit/api/pypi/repo/simple'\n"+
			"exit 1\n",
		"@echo off\n"+
			"if \"%1\"==\"--version\" (echo pipenv, version 2025.0.0 & exit /b 0)\n"+
			"echo %* > pipenv-args.txt\n"+
			"(echo PIPFILE=%PIPENV_PIPFILE%& echo SKIP=%PIPENV_SKIP_LOCK%& echo IGNORE=%PIPENV_IGNORE_PIPFILE%) > pipenv-env.txt\n"+
			"echo failed https://user:super-secret@rt.example.com/artifactory/api/curation/audit/api/pypi/repo/simple\n"+
			"exit /b 1\n",
	)
	t.Setenv("PATH", fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile(pipfileFile, []byte("[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n"), 0644))
	t.Setenv("PIPENV_PIPFILE", filepath.Join(t.TempDir(), "untrusted-Pipfile"))
	t.Setenv("PIPENV_SKIP_LOCK", "1")
	t.Setenv("PIPENV_IGNORE_PIPFILE", "1")

	server := &config.ServerDetails{
		ArtifactoryUrl: "https://rt.example.com/artifactory/",
		User:           "user",
		Password:       "super-secret", // #nosec G101 -- test fixture
	}
	err := runPipenvInstallFromRemoteRegistry(server, "repo", true)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret")

	args, readErr := os.ReadFile("pipenv-args.txt")
	require.NoError(t, readErr)
	assert.NotContains(t, string(args), "super-secret")
	assert.NotContains(t, string(args), "https://")

	environment, readErr := os.ReadFile("pipenv-env.txt")
	require.NoError(t, readErr)
	absolutePipfile, absErr := filepath.Abs(pipfileFile)
	require.NoError(t, absErr)
	assert.Contains(t, string(environment), "PIPFILE="+absolutePipfile)
	assert.Contains(t, string(environment), "SKIP=")
	assert.NotContains(t, string(environment), "SKIP=1")
	assert.Contains(t, string(environment), "IGNORE=")
	assert.NotContains(t, string(environment), "IGNORE=1")

	content, readErr := os.ReadFile(pipfileFile)
	require.NoError(t, readErr)
	assert.Contains(t, string(content), "super-secret")
	info, statErr := os.Stat(pipfileFile)
	require.NoError(t, statErr)
	if runtime.GOOS != "windows" {
		// Windows/NTFS has no owner-only permission bits to assert on; os.Chmod
		// there only toggles the read-only attribute, so Perm() always reports 0666.
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}

func TestProtectPipenvCurationEnvironment(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PIPENV_PIPFILE", "outside/Pipfile")
	t.Setenv("PIPENV_SKIP_LOCK", "1")
	t.Setenv("PIPENV_IGNORE_PIPFILE", "1")

	restore, err := protectPipenvCurationEnvironment(pipfileFile)
	require.NoError(t, err)
	absolutePipfile, err := filepath.Abs(pipfileFile)
	require.NoError(t, err)
	assert.Equal(t, absolutePipfile, os.Getenv("PIPENV_PIPFILE"))
	_, skipLockPresent := os.LookupEnv("PIPENV_SKIP_LOCK")
	assert.False(t, skipLockPresent)
	_, ignorePipfilePresent := os.LookupEnv("PIPENV_IGNORE_PIPFILE")
	assert.False(t, ignorePipfilePresent)

	require.NoError(t, restore())
	assert.Equal(t, "outside/Pipfile", os.Getenv("PIPENV_PIPFILE"))
	assert.Equal(t, "1", os.Getenv("PIPENV_SKIP_LOCK"))
	assert.Equal(t, "1", os.Getenv("PIPENV_IGNORE_PIPFILE"))
}

func TestParsePipfileLockPackages(t *testing.T) {
	t.Run("default and develop sections both parsed", func(t *testing.T) {
		fixture := []byte(`{
			"_meta": {"hash": {"sha256": "abc"}},
			"default": {
				"urllib3": {
					"version": "==2.0.7",
					"hashes": ["sha256:aaa", "sha256:bbb"]
				},
				"certifi": {
					"version": "==2023.7.22",
					"hashes": ["sha256:ccc"]
				}
			},
			"develop": {
				"pytest": {
					"version": "==7.4.0",
					"hashes": ["sha256:ddd"]
				}
			}
		}`)
		got, err := parsePipfileLockPackages(fixture)
		require.NoError(t, err)
		require.Len(t, got, 3)

		byName := map[string]pipfileLockPackage{}
		for _, p := range got {
			byName[p.Name] = p
		}
		require.Contains(t, byName, "urllib3")
		assert.Equal(t, "2.0.7", byName["urllib3"].Version)
		assert.ElementsMatch(t, []string{"sha256:aaa", "sha256:bbb"}, byName["urllib3"].Hashes)

		require.Contains(t, byName, "certifi")
		assert.Equal(t, "2023.7.22", byName["certifi"].Version)

		require.Contains(t, byName, "pytest")
		assert.Equal(t, "7.4.0", byName["pytest"].Version)
	})

	t.Run("hashless unknown entry fails closed", func(t *testing.T) {
		fixture := []byte(`{
			"default": {
				"somepkg": {"hashes": ["sha256:aaa"]}
			}
		}`)
		_, err := parsePipfileLockPackages(fixture)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "somepkg")
		assert.Contains(t, err.Error(), "unknown provenance")
	})

	t.Run("hashless registry entry fails closed", func(t *testing.T) {
		fixture := []byte(`{"default":{"somepkg":{"version":"==1.2.3","index":"jfrog"}}}`)
		_, err := parsePipfileLockPackages(fixture)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "somepkg")
		assert.Contains(t, err.Error(), "no hashes")
	})

	t.Run("local path and VCS entries are skipped", func(t *testing.T) {
		fixture := []byte(`{
			"default": {
				"localpkg": {"path": ".", "editable": true},
				"gitpkg": {"git": "https://example.com/repo.git", "ref": "abc"}
			}
		}`)
		got, err := parsePipfileLockPackages(fixture)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("direct file entry is rejected", func(t *testing.T) {
		fixture := []byte(`{"default":{"filepkg":{"file":"https://example.com/file.whl","hashes":["sha256:aaa"]}}}`)
		_, err := parsePipfileLockPackages(fixture)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "filepkg")
		assert.Contains(t, err.Error(), "direct-file")
	})

	t.Run("conflicting provenance is rejected", func(t *testing.T) {
		fixture := []byte(`{"default":{"badpkg":{"version":"==1.0","path":".","hashes":["sha256:aaa"]}}}`)
		_, err := parsePipfileLockPackages(fixture)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "badpkg")
		assert.Contains(t, err.Error(), "conflicting provenance")
	})

	t.Run("unknown provenance field is rejected", func(t *testing.T) {
		fixture := []byte(`{"default":{"mystery":{"artifact":"x","version":"==1.0","hashes":["sha256:aaa"]}}}`)
		_, err := parsePipfileLockPackages(fixture)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mystery")
		assert.Contains(t, err.Error(), "unknown lock fields")
	})

	t.Run("duplicate name+version across sections is deduplicated", func(t *testing.T) {
		fixture := []byte(`{
			"default": {
				"urllib3": {"version": "==2.0.7", "hashes": ["sha256:aaa"]}
			},
			"develop": {
				"urllib3": {"version": "==2.0.7", "hashes": ["sha256:aaa"]}
			}
		}`)
		got, err := parsePipfileLockPackages(fixture)
		require.NoError(t, err)
		assert.Len(t, got, 1)
	})

	t.Run("invalid json returns error", func(t *testing.T) {
		_, err := parsePipfileLockPackages([]byte("not json"))
		require.Error(t, err)
	})

	t.Run("missing dependency sections are rejected", func(t *testing.T) {
		_, err := parsePipfileLockPackages([]byte(`{}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no default or develop")
	})
}

func TestPickHrefByHashFragment(t *testing.T) {
	body := []byte(`<html><body>
<a href="../../packages/aa/bb/urllib3-2.0.6-py3-none-any.whl#sha256=old111">urllib3-2.0.6-py3-none-any.whl</a>
<a href="../../packages/cc/dd/urllib3-2.0.7-py3-none-any.whl#sha256=aaa111">urllib3-2.0.7-py3-none-any.whl</a>
</body></html>`)

	t.Run("returns href whose hash fragment matches", func(t *testing.T) {
		wanted := map[string]struct{}{"#sha256=aaa111": {}}
		got := pickHrefByHashFragment(body, wanted)
		assert.Equal(t, "../../packages/cc/dd/urllib3-2.0.7-py3-none-any.whl#sha256=aaa111", got)
	})

	t.Run("returns empty when no hash matches", func(t *testing.T) {
		wanted := map[string]struct{}{"#sha256=nonexistent": {}}
		got := pickHrefByHashFragment(body, wanted)
		assert.Equal(t, "", got)
	})

	t.Run("returns empty for empty body", func(t *testing.T) {
		got := pickHrefByHashFragment(nil, map[string]struct{}{"#sha256=aaa111": {}})
		assert.Equal(t, "", got)
	})
}

// TestBuildPipenvDownloadUrl_HTTP mirrors TestBuildPoetryDownloadUrl_HTTP: it spins
// up a mock Artifactory simple-index endpoint and verifies that
// buildPipenvDownloadUrl resolves the correct absolute URL by matching the
// sha256 hash fragment (Pipfile.lock hashes, not filenames like Poetry).
func TestBuildPipenvDownloadUrl_HTTP(t *testing.T) {
	const repo = "my-pip-repo"
	pkg := pipfileLockPackage{
		Name:    "urllib3",
		Version: "2.0.7",
		Hashes:  []string{"sha256:aaa111"},
	}

	t.Run("200 with matching hash returns absolute URL without fragment", func(t *testing.T) {
		server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/simple/urllib3/") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body>
<a href="../../packages/cc/dd/urllib3-2.0.7-py3-none-any.whl#sha256=aaa111">urllib3-2.0.7-py3-none-any.whl</a>
</body></html>`))
				return
			}
			t.Fatalf("unexpected request to %s", r.URL.Path)
		})
		defer server.Close()
		rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
		require.NoError(t, err)
		httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

		got, err := buildPipenvDownloadUrl(rtManager, &httpDetails, server.URL, repo, pkg)
		require.NoError(t, err)
		assert.Contains(t, got, "/packages/cc/dd/urllib3-2.0.7-py3-none-any.whl")
		assert.True(t, strings.HasPrefix(got, server.URL), "resolved URL must be absolute against the simple-index base, got %q", got)
		assert.NotContains(t, got, "#", "fragment must be stripped from the returned URL")
	})

	t.Run("non-200 from simple-index surfaces status code", func(t *testing.T) {
		server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		defer server.Close()
		rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
		require.NoError(t, err)
		httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

		_, err = buildPipenvDownloadUrl(rtManager, &httpDetails, server.URL, repo, pkg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "404")
		assert.Contains(t, err.Error(), "simple-index")
	})

	t.Run("200 with no matching hash returns error", func(t *testing.T) {
		server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>
<a href="../../packages/aa/bb/urllib3-1.0.0-py3-none-any.whl#sha256=different">urllib3-1.0.0-py3-none-any.whl</a>
</body></html>`))
		})
		defer server.Close()
		rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
		require.NoError(t, err)
		httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

		_, err = buildPipenvDownloadUrl(rtManager, &httpDetails, server.URL, repo, pkg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no matching href")
	})

	t.Run("uses normalized name in simple-index URL", func(t *testing.T) {
		var seenPath string
		server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			seenPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<a href="../../packages/aa/Flask_Babel-1.0.tar.gz#sha256=xyz">Flask_Babel-1.0.tar.gz</a>`))
		})
		defer server.Close()
		rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
		require.NoError(t, err)
		httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

		quirky := pipfileLockPackage{Name: "Flask_Babel", Version: "1.0", Hashes: []string{"sha256:xyz"}}
		_, err = buildPipenvDownloadUrl(rtManager, &httpDetails, server.URL, repo, quirky)
		require.NoError(t, err)
		assert.Contains(t, seenPath, "/simple/flask-babel/", "must use PEP 503 normalized name in the simple-index URL, got %q", seenPath)
	})
}

func TestBuildPipenvDownloadUrlsMapInputValidation(t *testing.T) {
	t.Run("nil server details returns error", func(t *testing.T) {
		_, err := buildPipenvDownloadUrlsMap(nil, "my-pip-repo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server details")
	})

	t.Run("empty artifactory URL returns error", func(t *testing.T) {
		_, err := buildPipenvDownloadUrlsMap(&config.ServerDetails{}, "my-pip-repo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server details")
	})

	t.Run("empty repository returns error", func(t *testing.T) {
		sd := &config.ServerDetails{ArtifactoryUrl: "https://rt.example.com/artifactory/"}
		_, err := buildPipenvDownloadUrlsMap(sd, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "repository")
	})
}

// TestBuildPipenvDownloadUrlRejectsCrossHostHref verifies that an absolute href
// in the simple-index response pointing at a different host than the configured
// Artifactory endpoint is rejected, rather than being handed back for an
// authenticated HEAD request against an unintended host.
func TestBuildPipenvDownloadUrlRejectsCrossHostHref(t *testing.T) {
	pkg := pipfileLockPackage{
		Name:    "urllib3",
		Version: "2.0.7",
		Hashes:  []string{"sha256:aaa111"},
	}
	server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<a href="https://evil.example.com/packages/urllib3-2.0.7.whl#sha256=aaa111">urllib3-2.0.7.whl</a>`))
	})
	defer server.Close()
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
	httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

	_, err = buildPipenvDownloadUrl(rtManager, &httpDetails, server.URL, "my-pip-repo", pkg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes the configured Artifactory endpoint")
}

func TestBuildPipenvDownloadUrlRejectsOutsideRepository(t *testing.T) {
	pkg := pipfileLockPackage{Name: "urllib3", Version: "2.0.7", Hashes: []string{"sha256:aaa111"}}
	server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<a href="/api/storage/private.whl#sha256=aaa111">private.whl</a>`))
	})
	defer server.Close()
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
	httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

	_, err = buildPipenvDownloadUrl(rtManager, &httpDetails, server.URL, "my-pip-repo", pkg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes the configured Artifactory endpoint")
}

func TestBuildPipenvDownloadUrlRejectsUnsafeRedirect(t *testing.T) {
	pkg := pipfileLockPackage{Name: "urllib3", Version: "2.0.7", Hashes: []string{"sha256:aaa111"}}
	var requests atomic.Int32
	server, serverDetails, _ := coreCommonTests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "/api/system/configuration", http.StatusFound)
	})
	defer server.Close()
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
	require.NoError(t, err)
	httpDetails := rtManager.GetConfig().GetServiceDetails().CreateHttpClientDetails()

	_, err = buildPipenvDownloadUrl(rtManager, &httpDetails, server.URL, "my-pip-repo", pkg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe redirect")
	assert.Equal(t, int32(1), requests.Load())
}

func TestRewriteCurationSourceInPipfile(t *testing.T) {
	writeTemp := func(t *testing.T, content string) string {
		dir := t.TempDir()
		p := filepath.Join(dir, "Pipfile")
		require.NoError(t, os.WriteFile(p, []byte(content), 0644))
		return p
	}
	readBack := func(t *testing.T, path string) string {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		return string(data)
	}

	t.Run("double-quoted source is rewritten and comments/formatting preserved", func(t *testing.T) {
		content := "[[source]]\n" +
			"# our internal mirror\n" +
			"url = \"https://acme.jfrog.io/artifactory/api/pypi/curation-repo/simple\"\n" +
			"verify_ssl = true\n" +
			"name = \"jfrog\"\n"
		p := writeTemp(t, content)

		found, err := rewriteCurationSourceInPipfile(p, "curation-repo", "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple")
		require.NoError(t, err)
		assert.True(t, found)

		updated := readBack(t, p)
		assert.Contains(t, updated, `url = "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple"`)
		assert.Contains(t, updated, "# our internal mirror", "comments must be preserved")
		assert.Contains(t, updated, "verify_ssl = true", "unrelated keys must be preserved")
		assert.Contains(t, updated, `name = "jfrog"`, "unrelated keys must be preserved")
	})

	t.Run("single-quoted source is rewritten", func(t *testing.T) {
		content := "[[source]]\n" +
			"url = 'https://acme.jfrog.io/artifactory/api/pypi/curation-repo/simple'\n" +
			"name = 'jfrog'\n"
		p := writeTemp(t, content)

		found, err := rewriteCurationSourceInPipfile(p, "curation-repo", "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Contains(t, readBack(t, p), "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple")
	})

	t.Run("only effective source is rewritten", func(t *testing.T) {
		content := "[[source]]\n" +
			"url = \"https://pypi.org/simple\"\n" +
			"name = \"pypi\"\n\n" +
			"[[source]]\n" +
			"url = \"https://bad-user-only@packages.example.com/simple\"\n" +
			"name = \"unused\"\n\n" +
			"[packages]\n" +
			"requests = \"*\"\n"
		p := writeTemp(t, content)

		found, err := rewriteCurationSourceInPipfile(p, "curation-repo", "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple")
		require.NoError(t, err)
		assert.True(t, found)

		updated := readBack(t, p)
		assert.Equal(t, 1, strings.Count(updated, `url = "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple"`))
		assert.NotContains(t, updated, "https://pypi.org/simple")
		assert.Contains(t, updated, "https://bad-user-only@packages.example.com/simple")
		assert.Contains(t, updated, `requests = "*"`, "sections after the source blocks must be preserved")
	})

	t.Run("external effective source is rejected", func(t *testing.T) {
		content := "[[source]]\nurl = \"https://packages.example.com/simple\"\nname = \"external\"\n"
		p := writeTemp(t, content)

		found, err := rewriteCurationSourceInPipfile(p, "curation-repo", "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple")
		require.Error(t, err)
		assert.False(t, found)
		assert.Equal(t, content, readBack(t, p))
	})

	t.Run("missing source gets a private default", func(t *testing.T) {
		p := writeTemp(t, "[packages]\nrequests = \"*\"\n")
		found, err := rewriteCurationSourceInPipfile(p, "curation-repo", "https://user:token@acme.jfrog.io/artifactory/api/curation/audit/api/pypi/curation-repo/simple")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Contains(t, readBack(t, p), `name = "jfrog-curation"`)
		info, err := os.Stat(p)
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			// Windows/NTFS has no owner-only permission bits to assert on; os.Chmod
			// there only toggles the read-only attribute, so Perm() always reports 0666.
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		}
	})

	t.Run("inline source array fails closed", func(t *testing.T) {
		content := "source = [{name = \"jfrog\", url = \"https://acme.jfrog.io/artifactory/api/pypi/curation-repo/simple\", verify_ssl = true}]\n\n" +
			"[packages]\nrequests = \"*\"\n"
		p := writeTemp(t, content)

		found, err := rewriteCurationSourceInPipfile(p, "curation-repo", "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple")
		require.Error(t, err)
		assert.False(t, found)
		assert.Contains(t, err.Error(), "could not map")
		assert.Equal(t, content, readBack(t, p))
	})

	t.Run("missing file returns found=false, no error", func(t *testing.T) {
		found, err := rewriteCurationSourceInPipfile(filepath.Join(t.TempDir(), "Pipfile"), "curation-repo", "https://acme.jfrog.io/artifactory/api/curation/audit/curation-repo/simple")
		require.NoError(t, err)
		assert.False(t, found)
	})
}

// TestParsePipfileArtifactorySourceEnvVarExpansion verifies that $VAR/${VAR}
// credentials embedded in a Pipfile [[source]] url — a pattern Pipenv itself
// supports and expands at runtime — are resolved from the environment.
func TestParsePipfileArtifactorySourceEnvVarExpansion(t *testing.T) {
	t.Setenv("PIPFILE_TEST_USER", "myuser")
	t.Setenv("PIPFILE_TEST_PASS", "mytoken")

	dir := t.TempDir()
	pipfilePath := filepath.Join(dir, "Pipfile")
	content := "[[source]]\n" +
		"url = \"https://$PIPFILE_TEST_USER:${PIPFILE_TEST_PASS}@myartifactory.jfrog.io/artifactory/api/pypi/my-pip-repo/simple\"\n" +
		"name = \"jfrog\"\n"
	require.NoError(t, os.WriteFile(pipfilePath, []byte(content), 0644))

	sd, repo, err := ParsePipfileArtifactorySource(pipfilePath)
	require.NoError(t, err)
	assert.Equal(t, "my-pip-repo", repo)
	require.NotNil(t, sd)
	assert.Equal(t, "myuser", sd.User)
	assert.Equal(t, "mytoken", sd.Password)
}
