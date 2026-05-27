package python

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/build-info-go/utils/pythonutils"
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
			name:                             "poetry: project installed before dep tree construction| install forbidden",
			testDir:                          filepath.Join("projects", "package-managers", "python", "poetry", "poetry"),
			technology:                       techutils.Poetry,
			installBeforeFetchingInitialDeps: true,
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

		require.NoError(t, setCurationSourceInPyproject(repoName, repoURL))

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

		require.NoError(t, setCurationSourceInPyproject(repoName, repoURL))

		written, err := os.ReadFile(pyprojectPath)
		require.NoError(t, err)
		out := string(written)

		// Quote-agnostic check: viper's TOML writer may emit either
		// single or double quotes around string values depending on
		// content. The names are what we care about, not the quoting.
		assert.True(t, strings.Contains(out, `"poetry-test"`) || strings.Contains(out, `'poetry-test'`),
			"user's source name must be preserved so poetry.lock stays in sync; got:\n%s", out)
		assert.Contains(t, out, repoURL, "URL must be rewritten to the curation pass-through")
		assert.False(t,
			strings.Contains(out, `name = "`+repoName+`"`) || strings.Contains(out, `name = '`+repoName+`'`),
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

		require.NoError(t, setCurationSourceInPyproject(repoName, repoURL))

		written, err := os.ReadFile(pyprojectPath)
		require.NoError(t, err)
		out := string(written)

		// Quote-agnostic checks — see note in the single-source subtest.
		assert.True(t,
			strings.Contains(out, `"primary-mirror"`) || strings.Contains(out, `'primary-mirror'`),
			"first source name must be preserved; got:\n%s", out)
		assert.True(t,
			strings.Contains(out, `"secondary-mirror"`) || strings.Contains(out, `'secondary-mirror'`),
			"second source name must be preserved; got:\n%s", out)
		assert.Contains(t, out, repoURL, "URLs must be rewritten to the curation pass-through")
		// The two original URLs must be gone — every source now points at
		// the curation pass-through.
		assert.NotContains(t, out, "/api/pypi/my-curation-repo/simple",
			"original non-curation URL on first source must be replaced")
		assert.NotContains(t, out, "/api/pypi/other-repo/simple",
			"original non-curation URL on second source must be replaced")
	})
}

func TestExtractPoetrySourceNames(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, extractPoetrySourceNames(nil))
	})
	t.Run("wrong type returns nil", func(t *testing.T) {
		assert.Nil(t, extractPoetrySourceNames("not-an-array"))
		assert.Nil(t, extractPoetrySourceNames(map[string]interface{}{"name": "x"}))
	})
	t.Run("entries without name are skipped", func(t *testing.T) {
		got := extractPoetrySourceNames([]interface{}{
			map[string]interface{}{"url": "https://x"},
			map[string]interface{}{"name": "named", "url": "https://y"},
			map[string]interface{}{"name": "   ", "url": "https://z"},
		})
		assert.Equal(t, []string{"named"}, got)
	})
	t.Run("duplicate names are deduped, order preserved", func(t *testing.T) {
		got := extractPoetrySourceNames([]interface{}{
			map[string]interface{}{"name": "a", "url": "https://1"},
			map[string]interface{}{"name": "b", "url": "https://2"},
			map[string]interface{}{"name": "a", "url": "https://3"},
		})
		assert.Equal(t, []string{"a", "b"}, got)
	})
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
