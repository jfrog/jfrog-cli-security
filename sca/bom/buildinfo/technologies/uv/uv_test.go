package uv

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/python"
	clientutils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvWithoutKey(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		key  string
		want []string
	}{
		{
			name: "removes matching entry",
			env:  []string{"FOO=1", "UV_DEFAULT_INDEX=https://example.com", "BAR=2"},
			key:  "UV_DEFAULT_INDEX",
			want: []string{"FOO=1", "BAR=2"},
		},
		{
			name: "key not present — returns unchanged",
			env:  []string{"FOO=1", "BAR=2"},
			key:  "UV_DEFAULT_INDEX",
			want: []string{"FOO=1", "BAR=2"},
		},
		{
			name: "removes all occurrences",
			env:  []string{"UV_DEFAULT_INDEX=a", "FOO=1", "UV_DEFAULT_INDEX=b"},
			key:  "UV_DEFAULT_INDEX",
			want: []string{"FOO=1"},
		},
		{
			name: "does not remove partial prefix match",
			env:  []string{"UV_DEFAULT_INDEX_EXTRA=x", "FOO=1"},
			key:  "UV_DEFAULT_INDEX",
			want: []string{"UV_DEFAULT_INDEX_EXTRA=x", "FOO=1"},
		},
		{
			name: "empty env",
			env:  []string{},
			key:  "UV_DEFAULT_INDEX",
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, envWithoutKey(tc.env, tc.key))
		})
	}
}

func TestParseTomlScalar(t *testing.T) {
	cases := []struct {
		line    string
		key     string
		wantVal string
		wantOk  bool
	}{
		{`name = "requests"`, "name", "requests", true},
		{`version = "1.2.3"`, "version", "1.2.3", true},
		{`name = "my-package"`, "version", "", false}, // wrong key
		{`name = 42`, "name", "", false},              // not a string
		{`name = `, "name", "", false},                // no value
		{`name`, "name", "", false},                   // no = sign
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			val, ok := parseTomlScalar(tc.line, tc.key)
			assert.Equal(t, tc.wantOk, ok)
			assert.Equal(t, tc.wantVal, val)
		})
	}
}

func TestParseUvTomlIndexUrls(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name: "standard uv.toml with [[index]]",
			content: `[[index]]
name = "uv-test-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"
default = true`,
			want: []string{"https://host/artifactory/api/pypi/uv-test-repo/simple"},
		},
		{
			name: "url with single quotes",
			content: `[[index]]
url = 'https://host/artifactory/api/pypi/my-repo/simple'`,
			want: []string{"https://host/artifactory/api/pypi/my-repo/simple"},
		},
		{
			name: "returns every [[index]] in file order",
			content: `[[index]]
url = "https://host/artifactory/api/pypi/first-repo/simple"

[[index]]
url = "https://host/artifactory/api/pypi/second-repo/simple"`,
			want: []string{
				"https://host/artifactory/api/pypi/first-repo/simple",
				"https://host/artifactory/api/pypi/second-repo/simple",
			},
		},
		{
			name:    "no [[index]] section",
			content: `[tool]\nsome = "value"`,
			want:    nil,
		},
		{
			name:    "empty content",
			content: "",
			want:    nil,
		},
		{
			name: "comments are ignored",
			content: `# this is a comment
[[index]]
# another comment
url = "https://host/artifactory/api/pypi/my-repo/simple"`,
			want: []string{"https://host/artifactory/api/pypi/my-repo/simple"},
		},
		{
			name: "explicit index is skipped even when defined first",
			content: `[[index]]
name = "pinned-only"
url = "https://host/artifactory/api/pypi/decoy-repo/simple"
explicit = true

[[index]]
name = "main"
url = "https://host/artifactory/api/pypi/real-repo/simple"`,
			want: []string{"https://host/artifactory/api/pypi/real-repo/simple"},
		},
		{
			name: "explicit index defined after the real one is still skipped",
			content: `[[index]]
name = "main"
url = "https://host/artifactory/api/pypi/real-repo/simple"

[[index]]
name = "pinned-only"
url = "https://host/artifactory/api/pypi/decoy-repo/simple"
explicit = true`,
			want: []string{"https://host/artifactory/api/pypi/real-repo/simple"},
		},
		{
			name: "only an explicit index exists — no general repo found",
			content: `[[index]]
name = "pinned-only"
url = "https://host/artifactory/api/pypi/decoy-repo/simple"
explicit = true`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseUvTomlIndexUrls(tc.content))
		})
	}
}

func TestParsePyprojectUvIndexUrls(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name: "standard pyproject.toml with [[tool.uv.index]]",
			content: `[project]
name = "my-app"

[[tool.uv.index]]
name = "uv-test-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"
default = true`,
			want: []string{"https://host/artifactory/api/pypi/uv-test-repo/simple"},
		},
		{
			name: "no [[tool.uv.index]] section",
			content: `[project]
name = "my-app"

[tool.uv]
publish-url = "https://host/artifactory/api/pypi/uv-test-repo"`,
			want: nil,
		},
		{
			name:    "empty content",
			content: "",
			want:    nil,
		},
		{
			name: "index pinning via [tool.uv.sources] — explicit index skipped",
			content: `[project]
name = "my-app"
dependencies = [
    "requests==2.19.1",
    "idna==2.7",
]

[tool.uv.sources]
idna = { index = "decoy-index" }

[[tool.uv.index]]
name = "decoy-index"
url = "https://host/artifactory/api/pypi/decoy-repo/simple"
explicit = true

[[tool.uv.index]]
name = "uv-test-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"`,
			want: []string{"https://host/artifactory/api/pypi/uv-test-repo/simple"},
		},
		{
			name: "multiple non-explicit indexes — all returned in order",
			content: `[project]
name = "my-app"

[[tool.uv.index]]
name = "public-pypi"
url = "https://pypi.org/simple"

[[tool.uv.index]]
name = "artifactory-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"`,
			want: []string{
				"https://pypi.org/simple",
				"https://host/artifactory/api/pypi/uv-test-repo/simple",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parsePyprojectUvIndexUrls(tc.content))
		})
	}
}

func TestFirstArtifactoryPypiConfig(t *testing.T) {
	t.Run("skips non-Artifactory candidates and picks the first Artifactory-shaped one", func(t *testing.T) {
		cfg, ok := firstArtifactoryPypiConfig([]string{
			"https://pypi.org/simple",
			"https://host/artifactory/api/pypi/uv-test-repo/simple",
		})
		require.True(t, ok)
		assert.Equal(t, "https://host/artifactory", cfg.ArtifactoryUrl)
		assert.Equal(t, "uv-test-repo", cfg.RepoName)
	})

	t.Run("Artifactory-shaped entry listed first is used directly", func(t *testing.T) {
		cfg, ok := firstArtifactoryPypiConfig([]string{
			"https://host/artifactory/api/pypi/uv-test-repo/simple",
			"https://pypi.org/simple",
		})
		require.True(t, ok)
		assert.Equal(t, "uv-test-repo", cfg.RepoName)
	})

	t.Run("no Artifactory-shaped candidate — not found", func(t *testing.T) {
		_, ok := firstArtifactoryPypiConfig([]string{"https://pypi.org/simple"})
		assert.False(t, ok)
	})

	t.Run("empty candidates — not found", func(t *testing.T) {
		_, ok := firstArtifactoryPypiConfig(nil)
		assert.False(t, ok)
	})
}

func setupUvRegistryFixture(t *testing.T) (projectDir, uvTomlPath string) {
	t.Helper()
	projectDir = t.TempDir()
	homeDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(homeDir, filepath.Dir(uvTomlConfigRelPath)), 0755))
	uvTomlPath = filepath.Join(homeDir, uvTomlConfigRelPath)
	t.Setenv("HOME", homeDir)
	t.Chdir(projectDir)
	return projectDir, uvTomlPath
}

func TestGetNativeUvRegistryConfig(t *testing.T) {
	t.Run("single unambiguous pyproject.toml entry is used directly", func(t *testing.T) {
		projectDir, _ := setupUvRegistryFixture(t)
		require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[[tool.uv.index]]
name = "artifactory-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"
`), 0644))

		cfg, err := GetNativeUvRegistryConfig()
		require.NoError(t, err)
		assert.Equal(t, "uv-test-repo", cfg.RepoName)
	})

	t.Run(
		"XRAY-146949: ambiguous pyproject.toml (multiple entries) is ignored — falls back to uv.toml, "+
			"even when one of the project's own entries would otherwise be picked",
		func(t *testing.T) {
			projectDir, uvTomlPath := setupUvRegistryFixture(t)
			require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[[tool.uv.index]]
name = "public-pypi"
url = "https://pypi.org/simple"

[[tool.uv.index]]
name = "maybe-wrong-host"
url = "https://untrusted-host/artifactory/api/pypi/uv-test-repo/simple"
`), 0644))
			require.NoError(t, os.WriteFile(uvTomlPath, []byte(`[[index]]
name = "uv-test-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"
default = true
`), 0644))

			cfg, err := GetNativeUvRegistryConfig()
			require.NoError(t, err)
			assert.Equal(t, "https://host/artifactory", cfg.ArtifactoryUrl)
		},
	)

	t.Run("no pyproject.toml entries falls back to uv.toml", func(t *testing.T) {
		projectDir, uvTomlPath := setupUvRegistryFixture(t)
		require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[project]
name = "my-app"
`), 0644))
		require.NoError(t, os.WriteFile(uvTomlPath, []byte(`[[index]]
name = "uv-test-repo"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"
default = true
`), 0644))

		cfg, err := GetNativeUvRegistryConfig()
		require.NoError(t, err)
		assert.Equal(t, "uv-test-repo", cfg.RepoName)
	})

	t.Run("ambiguous pyproject.toml and no usable uv.toml — error, not a guess", func(t *testing.T) {
		projectDir, _ := setupUvRegistryFixture(t)
		require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[[tool.uv.index]]
name = "public-pypi"
url = "https://pypi.org/simple"

[[tool.uv.index]]
name = "untrusted"
url = "https://untrusted-host/artifactory/api/pypi/uv-test-repo/simple"
`), 0644))
		// No uv.toml written at all.

		_, err := GetNativeUvRegistryConfig()
		require.Error(t, err)
	})
}

func TestStripNonExplicitPyprojectIndexes(t *testing.T) {
	t.Run("removes non-explicit index, keeps explicit index and everything else", func(t *testing.T) {
		content := `[project]
name = "my-app"
dependencies = [
    "requests==2.19.1",
]

[[tool.uv.index]]
name = "public-pypi"
url = "https://pypi.org/simple"

[[tool.uv.index]]
name = "pinned-only"
url = "https://host/artifactory/api/pypi/decoy-repo/simple"
explicit = true
`
		got := stripNonExplicitPyprojectIndexes(content)
		assert.NotContains(t, got, "public-pypi")
		assert.NotContains(t, got, "pypi.org")
		assert.Contains(t, got, "pinned-only")
		assert.Contains(t, got, "explicit = true")
		assert.Contains(t, got, `name = "my-app"`)
	})

	t.Run("no [[tool.uv.index]] section — content unchanged", func(t *testing.T) {
		content := "[project]\nname = \"my-app\"\n"
		assert.Equal(t, content, stripNonExplicitPyprojectIndexes(content))
	})

	t.Run("multiple non-explicit indexes all removed", func(t *testing.T) {
		content := `[[tool.uv.index]]
name = "one"
url = "https://pypi.org/simple"

[[tool.uv.index]]
name = "two"
url = "https://host/artifactory/api/pypi/uv-test-repo/simple"
`
		got := stripNonExplicitPyprojectIndexes(content)
		assert.NotContains(t, got, "tool.uv.index")
	})
}

func TestParseArtifactoryPypiUrl(t *testing.T) {
	cases := []struct {
		name        string
		rawUrl      string
		wantArti    string
		wantRepo    string
		wantErrSubs string
	}{
		{
			name:     "standard Artifactory PyPI URL",
			rawUrl:   "https://host/artifactory/api/pypi/my-repo/simple",
			wantArti: "https://host/artifactory",
			wantRepo: "my-repo",
		},
		{
			name:     "URL without trailing path",
			rawUrl:   "https://host/artifactory/api/pypi/my-repo",
			wantArti: "https://host/artifactory",
			wantRepo: "my-repo",
		},
		{
			name:        "no /api/pypi/ marker",
			rawUrl:      "https://pypi.org/simple",
			wantErrSubs: "does not match Artifactory PyPI format",
		},
		{
			name:        "missing repo name",
			rawUrl:      "https://host/artifactory/api/pypi/",
			wantErrSubs: "could not extract repo name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			artiUrl, repoName, err := parseArtifactoryPypiUrl(tc.rawUrl)
			if tc.wantErrSubs != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSubs)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantArti, artiUrl)
			assert.Equal(t, tc.wantRepo, repoName)
		})
	}
}

func TestParseUvVersionFromOutput(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "standard uv --version output",
			raw:  "uv 0.11.21 (5aa65dd7a 2026-06-11 aarch64-apple-darwin)",
			want: "0.11.21",
		},
		{
			name: "minimum supported version",
			raw:  "uv 0.6.17 (abc123 2025-01-01 x86_64-linux)",
			want: "0.6.17",
		},
		{
			name: "only binary name and version",
			raw:  "uv 1.0.0",
			want: "1.0.0",
		},
		{
			name: "empty string",
			raw:  "",
			want: "",
		},
		{
			name: "unexpected single token",
			raw:  "uv",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseUvVersionFromOutput(tc.raw))
		})
	}
}

func TestPickWheelURL(t *testing.T) {
	cases := []struct {
		name string
		urls []string
		want string
	}{
		{
			name: "prefers first wheel over sdist",
			urls: []string{
				"https://host/packages/pkg-1.0.tar.gz",
				"https://host/packages/pkg-1.0-py3-none-any.whl",
			},
			want: "https://host/packages/pkg-1.0-py3-none-any.whl",
		},
		{
			name: "returns sdist when no wheel",
			urls: []string{"https://host/packages/pkg-1.0.tar.gz"},
			want: "https://host/packages/pkg-1.0.tar.gz",
		},
		{
			name: "strips hash fragment before extension check",
			urls: []string{"https://host/packages/pkg-1.0-py3-none-any.whl#sha256=abc"},
			want: "https://host/packages/pkg-1.0-py3-none-any.whl#sha256=abc",
		},
		{
			name: "multiple wheels — returns first",
			urls: []string{
				"https://host/packages/pkg-1.0-cp310-cp310-linux_x86_64.whl",
				"https://host/packages/pkg-1.0-py3-none-any.whl",
			},
			want: "https://host/packages/pkg-1.0-cp310-cp310-linux_x86_64.whl",
		},
		{
			name: "empty list",
			urls: []string{},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pickWheelURL(tc.urls))
		})
	}
}

const sampleUvLock = `version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "urllib3" },
  { name = "certifi" },
]
sdist = { url = "https://host/artifactory/api/pypi/repo/packages/requests-2.19.1.tar.gz", hash = "sha256:abc", size = 131068 }
wheels = [
  { url = "https://host/artifactory/api/pypi/repo/packages/requests-2.19.1-py2.py3-none-any.whl", hash = "sha256:def", size = 91979 },
]

[[package]]
name = "urllib3"
version = "1.23"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://host/artifactory/api/pypi/repo/packages/urllib3-1.23.tar.gz", hash = "sha256:ghi", size = 228314 }
wheels = [
  { url = "https://host/artifactory/api/pypi/repo/packages/urllib3-1.23-py2.py3-none-any.whl", hash = "sha256:jkl", size = 133303 },
]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }
wheels = [
  { url = "https://host/artifactory/api/pypi/repo/packages/certifi-2024.1.1-py3-none-any.whl", hash = "sha256:mno", size = 100 },
]

[[package]]
name = "my-app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
  { name = "requests" },
  { name = "urllib3" },
]

[package.metadata]
requires-dist = [
  { name = "requests", specifier = "==2.19.1" },
]
`

func TestParseUvLock(t *testing.T) {
	packages := parseUvLock(sampleUvLock)
	require.Len(t, packages, 4)

	byName := make(map[string]uvPackage)
	for _, p := range packages {
		byName[p.Name] = p
	}

	t.Run("root package detected", func(t *testing.T) {
		root, ok := byName["my-app"]
		require.True(t, ok)
		assert.True(t, root.IsRoot)
		assert.Equal(t, "0.1.0", root.Version)
		assert.Contains(t, depNames(root.Dependencies), "requests")
		assert.Contains(t, depNames(root.Dependencies), "urllib3")
	})

	t.Run("wheel URL stored", func(t *testing.T) {
		pkg := byName["requests"]
		assert.False(t, pkg.IsRoot)
		assert.Equal(t, "2.19.1", pkg.Version)
		assert.Contains(t, pkg.DownloadURLs, "https://host/artifactory/api/pypi/repo/packages/requests-2.19.1-py2.py3-none-any.whl")
	})

	t.Run("sdist URL stored when present", func(t *testing.T) {
		pkg := byName["requests"]
		assert.Contains(t, pkg.DownloadURLs, "https://host/artifactory/api/pypi/repo/packages/requests-2.19.1.tar.gz")
	})

	t.Run("dependencies parsed", func(t *testing.T) {
		pkg := byName["requests"]
		assert.Contains(t, depNames(pkg.Dependencies), "urllib3")
		assert.Contains(t, depNames(pkg.Dependencies), "certifi")
	})

	t.Run("empty lock returns empty slice", func(t *testing.T) {
		assert.Empty(t, parseUvLock(""))
	})
}

func TestBuildUvDepTree(t *testing.T) {
	packages := parseUvLock(sampleUvLock)
	depTree, uniqueDeps := buildUvDepTree(packages)

	require.Len(t, depTree, 1)
	root := depTree[0]
	assert.Equal(t, "pypi://my-app:0.1.0", root.Id)

	t.Run("direct deps under root", func(t *testing.T) {
		ids := make([]string, 0, len(root.Nodes))
		for _, n := range root.Nodes {
			ids = append(ids, n.Id)
		}
		assert.Contains(t, ids, "pypi://requests:2.19.1")
		assert.Contains(t, ids, "pypi://urllib3:1.23")
	})

	t.Run("uniqueDeps contains all transitive packages", func(t *testing.T) {
		assert.Contains(t, uniqueDeps, "pypi://requests:2.19.1")
		assert.Contains(t, uniqueDeps, "pypi://urllib3:1.23")
		assert.Contains(t, uniqueDeps, "pypi://certifi:2024.1.1")
	})
}

func TestBuildUvDepTreeNoRoot(t *testing.T) {
	lockContent := `version = 1

[[package]]
name = "requests"
version = "2.28.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "urllib3" },
  { name = "certifi" },
]
wheels = [{ url = "https://host/packages/requests-2.28.0-py3-none-any.whl", hash = "sha256:x" }]

[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/packages/urllib3-2.0.0-py3-none-any.whl", hash = "sha256:y" }]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/packages/certifi-2024.1.1-py3-none-any.whl", hash = "sha256:z" }]

[[package]]
name = "standalone-tool"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/packages/standalone-tool-1.0.0-py3-none-any.whl", hash = "sha256:w" }]

[[package]]
name = "no-version-pkg"
source = { registry = "https://pypi.org/simple" }
`
	packages := parseUvLock(lockContent)

	t.Run("no package is marked as root", func(t *testing.T) {
		for _, p := range packages {
			assert.False(t, p.IsRoot, "package %s must not be mistaken for the root", p.Name)
		}
	})

	depTree, uniqueDeps := buildUvDepTree(packages)

	t.Run("wraps everything under a single synthetic root", func(t *testing.T) {
		require.Len(t, depTree, 1)
		assert.Equal(t, "root", depTree[0].Id)
	})

	t.Run("every versioned package is included, none dropped", func(t *testing.T) {
		assert.Contains(t, uniqueDeps, "pypi://requests:2.28.0")
		assert.Contains(t, uniqueDeps, "pypi://urllib3:2.0.0")
		assert.Contains(t, uniqueDeps, "pypi://certifi:2024.1.1")
		assert.Contains(t, uniqueDeps, "pypi://standalone-tool:1.0.0")
		assert.Len(t, uniqueDeps, 4, "the version-less package must be skipped, not counted")
	})

	t.Run("transitive dependencies are preserved under the synthetic root", func(t *testing.T) {
		root := depTree[0]
		requestsNode := findChildById(root, "pypi://requests:2.28.0")
		require.NotNil(t, requestsNode, "requests must be a direct child of the synthetic root")
		childIds := make([]string, 0, len(requestsNode.Nodes))
		for _, n := range requestsNode.Nodes {
			childIds = append(childIds, n.Id)
		}
		assert.Contains(t, childIds, "pypi://urllib3:2.0.0")
		assert.Contains(t, childIds, "pypi://certifi:2024.1.1")
	})

	t.Run("unrelated standalone package is still a direct child", func(t *testing.T) {
		root := depTree[0]
		assert.NotNil(t, findChildById(root, "pypi://standalone-tool:1.0.0"))
	})
}

func depNames(deps []uvDependency) []string {
	names := make([]string, len(deps))
	for i, d := range deps {
		names[i] = d.Name
	}
	return names
}

func findChildById(node *clientutils.GraphNode, id string) *clientutils.GraphNode {
	for _, n := range node.Nodes {
		if n.Id == id {
			return n
		}
	}
	return nil
}

func TestBuildUvDepTreeMultiVersionForkBothVersionsAudited(t *testing.T) {
	lockContent := `version = 1
requires-python = ">=3.9"

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/requests-2.19.1-py2.py3-none-any.whl", hash = "sha256:aaa" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/requests-2.31.0-py3-none-any.whl", hash = "sha256:bbb" }]

[[package]]
name = "uv-fork-test"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]
`
	packages := parseUvLock(lockContent)
	depTree, uniqueDeps := buildUvDepTree(packages)

	require.Len(t, depTree, 1)
	assert.Contains(t, uniqueDeps, "pypi://requests:2.19.1", "the older, potentially-blocked fork must not be dropped")
	assert.Contains(t, uniqueDeps, "pypi://requests:2.31.0", "the newer fork must also be present")
	assert.NotNil(t, findChildById(depTree[0], "pypi://requests:2.19.1"))
	assert.NotNil(t, findChildById(depTree[0], "pypi://requests:2.31.0"))
}

func TestBuildUvDepTreeMultiVersionForkPrecisePairing(t *testing.T) {
	lockContent := `version = 1
requires-python = ">=3.9"

[[package]]
name = "idna"
version = "2.7"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/idna-2.7-py2.py3-none-any.whl", hash = "sha256:aaa" }]

[[package]]
name = "idna"
version = "3.18"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/idna-3.18-py3-none-any.whl", hash = "sha256:bbb" }]

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/requests-2.19.1-py2.py3-none-any.whl", hash = "sha256:ccc" }]
dependencies = [
    { name = "idna", version = "2.7", source = { registry = "https://pypi.org/simple" } },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/requests-2.31.0-py3-none-any.whl", hash = "sha256:ddd" }]
dependencies = [
    { name = "idna", version = "3.18", source = { registry = "https://pypi.org/simple" } },
]

[[package]]
name = "uv-fork-precision-test"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests", version = "2.19.1", source = { registry = "https://pypi.org/simple" } },
    { name = "requests", version = "2.31.0", source = { registry = "https://pypi.org/simple" } },
]
`
	packages := parseUvLock(lockContent)
	depTree, uniqueDeps := buildUvDepTree(packages)

	require.Len(t, depTree, 1)
	assert.Contains(t, uniqueDeps, "pypi://requests:2.19.1")
	assert.Contains(t, uniqueDeps, "pypi://requests:2.31.0")

	requests1 := findChildById(depTree[0], "pypi://requests:2.19.1")
	require.NotNil(t, requests1)
	require.Len(t, requests1.Nodes, 1, "requests==2.19.1 must link to exactly one idna fork, not both")
	assert.Equal(t, "pypi://idna:2.7", requests1.Nodes[0].Id)

	requests2 := findChildById(depTree[0], "pypi://requests:2.31.0")
	require.NotNil(t, requests2)
	require.Len(t, requests2.Nodes, 1, "requests==2.31.0 must link to exactly one idna fork, not both")
	assert.Equal(t, "pypi://idna:3.18", requests2.Nodes[0].Id)
}

func TestParseUvLockWorkspaceRoot(t *testing.T) {
	lockContent := `version = 1
requires-python = ">=3.11"

[[package]]
name = "localpkg"
version = "0.1.0"
source = { editable = "local_pkg" }

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "https://pypi.org/simple" }
wheels = [
  { url = "https://host/artifactory/api/pypi/repo/packages/requests-2.19.1-py2.py3-none-any.whl", hash = "sha256:def" },
]

[[package]]
name = "uv-ca-test"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
  { name = "localpkg" },
  { name = "requests" },
]
`
	packages := parseUvLock(lockContent)
	byName := make(map[string]uvPackage)
	for _, p := range packages {
		byName[p.Name] = p
	}

	t.Run("virtual root at path . is the root", func(t *testing.T) {
		root, ok := byName["uv-ca-test"]
		require.True(t, ok)
		assert.True(t, root.IsRoot)
	})

	t.Run("editable workspace member is not the root", func(t *testing.T) {
		member, ok := byName["localpkg"]
		require.True(t, ok)
		assert.False(t, member.IsRoot)
	})

	t.Run("dep tree still contains real dependencies", func(t *testing.T) {
		depTree, uniqueDeps := buildUvDepTree(packages)
		require.Len(t, depTree, 1)
		assert.Equal(t, "pypi://uv-ca-test:0.1.0", depTree[0].Id)
		assert.NotEmpty(t, depTree[0].Nodes, "root's dependencies must not be dropped")
		assert.Contains(t, uniqueDeps, "pypi://requests:2.19.1")
	})
}

func TestBuildUvDepTreeWorkspaceMemberNotReachableFromRoot(t *testing.T) {
	lockContent := `version = 1
requires-python = ">=3.11"

[[package]]
name = "root-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
  { name = "requests" },
]

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/requests-2.19.1-py2.py3-none-any.whl", hash = "sha256:aaa" }]

[[package]]
name = "internal-tool"
version = "0.2.0"
source = { editable = "tools/internal-tool" }
dependencies = [
  { name = "pyyaml" },
]

[[package]]
name = "pyyaml"
version = "5.3.1"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://host/artifactory/api/pypi/repo/packages/PyYAML-5.3.1.tar.gz", hash = "sha256:bbb" }
`
	packages := parseUvLock(lockContent)
	depTree, uniqueDeps := buildUvDepTree(packages)

	t.Run("root subtree is still built normally", func(t *testing.T) {
		root := depTree[0]
		assert.Equal(t, "pypi://root-app:0.1.0", root.Id)
		assert.NotNil(t, findChildById(root, "pypi://requests:2.19.1"))
	})

	t.Run("unreachable workspace member becomes its own tree entry", func(t *testing.T) {
		var memberNode *clientutils.GraphNode
		for _, n := range depTree {
			if n.Id == "pypi://internal-tool:0.2.0" {
				memberNode = n
			}
		}
		require.NotNil(t, memberNode, "internal-tool must be audited even though root doesn't depend on it")
		assert.NotNil(t, findChildById(memberNode, "pypi://pyyaml:5.3.1"), "the member's own dependencies must be traversed too")
	})

	t.Run("member's dependencies are counted as unique deps", func(t *testing.T) {
		assert.Contains(t, uniqueDeps, "pypi://internal-tool:0.2.0")
		assert.Contains(t, uniqueDeps, "pypi://pyyaml:5.3.1")
	})
}

func TestBuildUvDepTreeWorkspaceMemberReachableFromRootNotDuplicated(t *testing.T) {
	lockContent := `version = 1
requires-python = ">=3.11"

[[package]]
name = "root-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
  { name = "localpkg" },
]

[[package]]
name = "localpkg"
version = "0.1.0"
source = { editable = "local_pkg" }
`
	packages := parseUvLock(lockContent)
	depTree, _ := buildUvDepTree(packages)

	require.Len(t, depTree, 1, "localpkg is already reachable from root — no duplicate sibling should be added")
	assert.NotNil(t, findChildById(depTree[0], "pypi://localpkg:0.1.0"))
}

func TestParseUvLockExtrasAndDependencyGroups(t *testing.T) {
	lockContent := `version = 1
requires-python = ">=3.11"

[[package]]
name = "idna"
version = "2.7"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/idna-2.7-py2.py3-none-any.whl", hash = "sha256:aaa" }]

[[package]]
name = "pyyaml"
version = "5.3.1"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://host/artifactory/api/pypi/repo/packages/PyYAML-5.3.1.tar.gz", hash = "sha256:bbb" }

[[package]]
name = "urllib3"
version = "1.23"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://host/artifactory/api/pypi/repo/packages/urllib3-1.23-py2.py3-none-any.whl", hash = "sha256:ccc" }]

[[package]]
name = "uv-ca-groups-test"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "pyyaml" },
]

[package.optional-dependencies]
extra1 = [
    { name = "idna" },
]

[package.dev-dependencies]
dev = [
    { name = "urllib3" },
]

[package.metadata]
requires-dist = [
    { name = "idna", marker = "extra == 'extra1'", specifier = "==2.7" },
    { name = "pyyaml", specifier = "==5.3.1" },
]

[package.metadata.requires-dev]
dev = [
    { name = "urllib3", specifier = "==1.23" },
]
`
	packages := parseUvLock(lockContent)
	byName := make(map[string]uvPackage)
	for _, p := range packages {
		byName[p.Name] = p
	}

	t.Run("root package's dependency list includes the base, extra, and dev-group members", func(t *testing.T) {
		root, ok := byName["uv-ca-groups-test"]
		require.True(t, ok)
		assert.ElementsMatch(t, []string{"pyyaml", "idna", "urllib3"}, depNames(root.Dependencies))
	})

	t.Run("metadata sub-table after the group tables is not mistaken for package data", func(t *testing.T) {
		// [package.metadata] must not add spurious entries beyond the 3 real ones.
		root := byName["uv-ca-groups-test"]
		assert.Len(t, root.Dependencies, 3)
	})

	depTree, uniqueDeps := buildUvDepTree(packages)

	t.Run("extra and dev-group members appear in the dependency tree", func(t *testing.T) {
		require.Len(t, depTree, 1)
		root := depTree[0]
		assert.NotNil(t, findChildById(root, "pypi://idna:2.7"), "extra member idna must be a child of the root")
		assert.NotNil(t, findChildById(root, "pypi://urllib3:1.23"), "dev-group member urllib3 must be a child of the root")
		assert.NotNil(t, findChildById(root, "pypi://pyyaml:5.3.1"))
	})

	t.Run("extra and dev-group members are counted as unique deps", func(t *testing.T) {
		assert.Contains(t, uniqueDeps, "pypi://idna:2.7")
		assert.Contains(t, uniqueDeps, "pypi://urllib3:1.23")
	})
}

func TestBuildUvDownloadUrlsMap(t *testing.T) {
	artiBase := "https://host/artifactory"
	packages := parseUvLock(sampleUvLock)

	params := technologies.BuildInfoBomGeneratorParams{
		ServerDetails:          &config.ServerDetails{ArtifactoryUrl: artiBase + "/"},
		DependenciesRepository: "repo",
	}

	urls := buildUvDownloadUrlsMap(params, packages)

	t.Run("wheel URL preferred over sdist", func(t *testing.T) {
		assert.Equal(t,
			"https://host/artifactory/api/pypi/repo/packages/requests-2.19.1-py2.py3-none-any.whl",
			urls["pypi://requests:2.19.1"],
		)
	})

	t.Run("root package skipped", func(t *testing.T) {
		_, ok := urls["pypi://my-app:0.1.0"]
		assert.False(t, ok)
	})

	t.Run("all non-root packages resolved", func(t *testing.T) {
		assert.Contains(t, urls, "pypi://requests:2.19.1")
		assert.Contains(t, urls, "pypi://urllib3:1.23")
		assert.Contains(t, urls, "pypi://certifi:2024.1.1")
	})
}

func TestBuildUvDownloadUrlsMapStripsCurationPrefix(t *testing.T) {
	lockContent := `version = 1

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "https://host/artifactory/api/curation/audit/api/pypi/repo/simple" }
wheels = [{ url = "https://host/artifactory/api/curation/audit/api/pypi/repo/packages/requests-2.19.1-py3-none-any.whl", hash = "sha256:x" }]

[[package]]
name = "my-app"
version = "0.1.0"
source = { editable = "." }
`
	packages := parseUvLock(lockContent)
	params := technologies.BuildInfoBomGeneratorParams{
		ServerDetails:          &config.ServerDetails{ArtifactoryUrl: "https://host/artifactory/"},
		DependenciesRepository: "repo",
	}

	urls := buildUvDownloadUrlsMap(params, packages)

	assert.Equal(t,
		"https://host/artifactory/api/pypi/repo/packages/requests-2.19.1-py3-none-any.whl",
		urls["pypi://requests:2.19.1"],
	)
}

func TestBuildUvCurationIndexUrlReferenceTokenNoUsername(t *testing.T) {
	serverDetails := &config.ServerDetails{
		ArtifactoryUrl: "https://host/artifactory/",
		AccessToken:    "reference-token-without-jwt-claims",
	}

	indexUrl, err := buildUvCurationIndexUrl(serverDetails, "repo")
	require.NoError(t, err)

	assert.Contains(t, indexUrl, "reference-token-without-jwt-claims@",
		"the access token must be embedded as credentials even without an extractable username")
}

// TestMaskPassword covers the helper both generateUvLock and checkUvLockState rely on to
// keep the credentials embedded in UV_DEFAULT_INDEX out of debug logs and error messages.
func TestMaskPassword(t *testing.T) {
	t.Run("password present — masked wherever it appears in s", func(t *testing.T) {
		rawIndexUrl := "https://user:s3cr3t-token@host/artifactory/api/curation/audit/api/pypi/repo/simple"
		out := "fetching https://user:s3cr3t-token@host/artifactory/... : 403 Forbidden (token=s3cr3t-token)"

		masked := maskPassword(out, rawIndexUrl)

		assert.NotContains(t, masked, "s3cr3t-token")
		assert.Contains(t, masked, "https://user:***@host/artifactory/")
		assert.Contains(t, masked, "token=***")
	})

	t.Run("no password in rawIndexUrl — s returned unchanged", func(t *testing.T) {
		out := "some uv output with no secrets"
		assert.Equal(t, out, maskPassword(out, "https://host/artifactory/api/pypi/repo/simple"))
	})

	t.Run("empty rawIndexUrl — s returned unchanged", func(t *testing.T) {
		out := "some uv output"
		assert.Equal(t, out, maskPassword(out, ""))
	})

	t.Run("unparseable rawIndexUrl — s returned unchanged", func(t *testing.T) {
		out := "some uv output"
		assert.Equal(t, out, maskPassword(out, "://not a url"))
	})
}

func TestBuildUvDownloadUrlsMapSkipsNonArtifactoryUrls(t *testing.T) {
	lockContent := `version = 1

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/packages/requests-2.19.1-py3-none-any.whl", hash = "sha256:x" }]

[[package]]
name = "my-app"
version = "0.1.0"
source = { editable = "." }
`
	packages := parseUvLock(lockContent)
	params := technologies.BuildInfoBomGeneratorParams{
		ServerDetails:          &config.ServerDetails{ArtifactoryUrl: "https://host/artifactory/"},
		DependenciesRepository: "repo",
	}

	urls := buildUvDownloadUrlsMap(params, packages)

	_, ok := urls["pypi://requests:2.19.1"]
	assert.False(t, ok, "public PyPI URL must not be included in the curation HEAD-probe map")
}

func TestBuildDependencyTreeRejectsAuditMode(t *testing.T) {
	params := technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd: false,
	}
	_, _, _, err := BuildDependencyTree(params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jf curation-audit")
}

func TestClassifyUvCurationLockError_WheelFetchBlocked(t *testing.T) {
	outStr := "error: Failed to fetch: `https://host/artifactory/api/curation/audit/api/pypi/repo/packages/langsmith-0.10.0-py3-none-any.whl`" +
		"\n  Caused by: HTTP status client error (403 Forbidden) for url (https://host/artifactory/api/curation/audit/api/pypi/repo/packages/langsmith-0.10.0-py3-none-any.whl)"
	cause := errors.New("'uv lock' against Artifactory failed: exit status 1 — " + outStr)

	err := classifyUvCurationLockError(outStr, cause)

	var cvsErr *python.CvsBlockedError
	assert.False(t, errors.As(err, &cvsErr), "generic wheel-403 must NOT be treated as a partial-table CvsBlockedError, got: %v", err)
	assert.ErrorIs(t, err, cause)
}

func TestClassifyUvCurationLockError_CvsStrippedVersion(t *testing.T) {
	outStr := "error: Because there is no version of telnyx==4.87.1 and your project depends on telnyx==4.87.1, we can conclude that your project's requirements are unsatisfiable."
	cause := errors.New("'uv lock' against Artifactory failed: exit status 1 — " + outStr)

	err := classifyUvCurationLockError(outStr, cause)

	var cvsErr *python.CvsBlockedError
	require.True(t, errors.As(err, &cvsErr))
	require.Len(t, cvsErr.Packages, 1)
	assert.Equal(t, "telnyx", cvsErr.Packages[0].Name)
	assert.Equal(t, "4.87.1", cvsErr.Packages[0].Version)
}

func TestClassifyUvCurationLockError_UnrecognizedFailure(t *testing.T) {
	outStr := "error: No solution found when resolving dependencies: some unrelated conflict"
	cause := errors.New("'uv lock' against Artifactory failed: exit status 1 — " + outStr)

	err := classifyUvCurationLockError(outStr, cause)

	assert.Same(t, cause, err)
}

// writeFakeUvExecutable puts a fake "uv" on PATH that:
//   - "uv --version"           -> prints a fake version, exit 0.
//   - "uv lock --check"        -> exit 0 (always reports the lock as already in sync).
//   - "uv lock --script <name>" -> records the UV_DEFAULT_INDEX it was invoked with, writes
//     marker into ./<name>.lock identifying that index, exit 0.
//   - "uv lock"                 -> same, but writes ./uv.lock instead.
//
// Every invocation is appended to the file at the FAKE_UV_LOG env var so the test can
// assert whether "uv lock" (the real regeneration, not the --check probe) ran.
func writeFakeUvExecutable(t *testing.T, dir string) {
	t.Helper()
	name := filepath.Join(dir, "uv")
	script := `#!/bin/sh
echo "CALL:$*" >> "$FAKE_UV_LOG"
if [ "$1" = "--version" ]; then
  echo "uv 0.11.21 (fake)"
  exit 0
fi
if [ "$1" = "lock" ] && [ "$2" = "--check" ]; then
  exit 0
fi
if [ "$1" = "lock" ] && [ "$2" = "--script" ]; then
  echo "REGENERATED_WITH_INDEX=$UV_DEFAULT_INDEX" >> "$FAKE_UV_LOG"
  echo "regenerated-lock-via-$UV_DEFAULT_INDEX" > "$3.lock"
  exit 0
fi
if [ "$1" = "lock" ]; then
  echo "REGENERATED_WITH_INDEX=$UV_DEFAULT_INDEX" >> "$FAKE_UV_LOG"
  echo "regenerated-lock-via-$UV_DEFAULT_INDEX" > uv.lock
  exit 0
fi
exit 1
`
	if runtime.GOOS == "windows" {
		name += ".bat"
		script = `@echo off
echo CALL:%* >> "%FAKE_UV_LOG%"
if "%~1"=="--version" (
  echo uv 0.11.21 (fake)
  exit /b 0
)
if "%~1"=="lock" if "%~2"=="--check" (
  exit /b 0
)
if "%~1"=="lock" if "%~2"=="--script" (
  echo REGENERATED_WITH_INDEX=%UV_DEFAULT_INDEX% >> "%FAKE_UV_LOG%"
  echo regenerated-lock-via-%UV_DEFAULT_INDEX% > "%~3.lock"
  exit /b 0
)
if "%~1"=="lock" (
  echo REGENERATED_WITH_INDEX=%UV_DEFAULT_INDEX% >> "%FAKE_UV_LOG%"
  echo regenerated-lock-via-%UV_DEFAULT_INDEX% > uv.lock
  exit /b 0
)
exit /b 1
`
	}
	require.NoError(t, os.WriteFile(name, []byte(script), 0755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

const (
	testUvArtifactoryUrl = "https://arti.example.com"
	testUvRepoName       = "pypi-remote"
	testUvArtiIndexUrl   = "https://arti.example.com/api/curation/audit/api/pypi/pypi-remote/simple"
)

// TestGenerateUvLockInTempDir_UnverifiedLock_Regenerates is a regression test for a
// critical bypass: a committed uv.lock that's already in sync with pyproject.toml (`uv
// lock --check` passes) but resolved from an unrecognized registry (here, public PyPI)
// must still be re-resolved through the curation gateway — "in sync" alone says nothing
// about which index produced it. Before the fix, this case (the old `default:` branch)
// never called generateUvLock at all, so the returned lock content was just the untouched
// committed file, and no package was ever routed through Artifactory.
func TestGenerateUvLockInTempDir_UnverifiedLock_Regenerates(t *testing.T) {
	fakeBinDir := t.TempDir()
	writeFakeUvExecutable(t, fakeBinDir)

	logPath := filepath.Join(t.TempDir(), "fake_uv.log")
	t.Setenv("FAKE_UV_LOG", logPath)

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = []
`), 0644))
	committedLock := `version = 1
requires-python = ">=3.9"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.19.1"
source = { registry = "https://pypi.org/simple" }
`
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "uv.lock"), []byte(committedLock), 0644))

	content, err := generateUvLockInTempDir(projectDir, testUvArtifactoryUrl, testUvRepoName, testUvArtiIndexUrl)
	require.NoError(t, err)

	assert.NotEqual(t, committedLock, content,
		"a lock resolved from an unrecognized registry must never be reused as-is — it must be re-resolved through the curation gateway")
	assert.Equal(t, "regenerated-lock-via-"+testUvArtiIndexUrl, strings.TrimSpace(content))

	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err, "expected 'uv lock' to actually run, but no invocation was logged")
	log := string(logBytes)
	assert.Contains(t, log, "CALL:lock --check", "sanity check: the staleness probe should still run")
	assert.Contains(t, log, "REGENERATED_WITH_INDEX="+testUvArtiIndexUrl,
		"'uv lock' must run against the curation gateway when the existing lock's registry isn't verified")
}

// TestGenerateUvLockInTempDir_VerifiedLock_Reused covers the optimization: when the lock
// is in sync AND every package's recorded registry is already this Artifactory repo (plain
// or curation pass-through form), re-resolving would be redundant — the later HEAD-probe
// step re-checks each package's current policy status straight from these URLs regardless.
// 'uv lock' must not run again in this case.
func TestGenerateUvLockInTempDir_VerifiedLock_Reused(t *testing.T) {
	fakeBinDir := t.TempDir()
	writeFakeUvExecutable(t, fakeBinDir)

	logPath := filepath.Join(t.TempDir(), "fake_uv.log")
	t.Setenv("FAKE_UV_LOG", logPath)

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = []
`), 0644))
	plainBase, passThroughBase := uvArtifactoryRegistryBases(testUvArtifactoryUrl, testUvRepoName)
	committedLock := fmt.Sprintf(`version = 1
requires-python = ">=3.9"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.34.2"
source = { registry = %q }

[[package]]
name = "certifi"
version = "2026.5.20"
source = { registry = %q }
`, plainBase, passThroughBase)
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "uv.lock"), []byte(committedLock), 0644))

	content, err := generateUvLockInTempDir(projectDir, testUvArtifactoryUrl, testUvRepoName, testUvArtiIndexUrl)
	require.NoError(t, err)

	assert.Equal(t, committedLock, content,
		"a lock already verified as resolved from this Artifactory repo must be reused as-is")

	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err, "expected the staleness probe to run, but no invocation was logged")
	log := string(logBytes)
	assert.Contains(t, log, "CALL:lock --check", "sanity check: the staleness probe should still run")
	assert.NotContains(t, log, "REGENERATED_WITH_INDEX=",
		"'uv lock' must not run again once the existing lock is verified as already resolved from this repo")
}

// TestGenerateUvLockInTempDir_NoLock_Generates covers the no-uv.lock-yet case
// (checkUvLockState's lockNeedsGenerate branch), which always calls generateUvLock
// unconditionally — there's nothing to verify when no lock exists yet.
func TestGenerateUvLockInTempDir_NoLock_Generates(t *testing.T) {
	fakeBinDir := t.TempDir()
	writeFakeUvExecutable(t, fakeBinDir)

	logPath := filepath.Join(t.TempDir(), "fake_uv.log")
	t.Setenv("FAKE_UV_LOG", logPath)

	projectDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte(`[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = []
`), 0644))
	content, err := generateUvLockInTempDir(projectDir, testUvArtifactoryUrl, testUvRepoName, testUvArtiIndexUrl)
	require.NoError(t, err)

	assert.Equal(t, "regenerated-lock-via-"+testUvArtiIndexUrl, strings.TrimSpace(content))

	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err, "expected 'uv lock' to actually run, but no invocation was logged")
	log := string(logBytes)
	assert.NotContains(t, log, "CALL:lock --check",
		"sanity check: checkUvLockState should skip the --check probe when there's no lock file yet")
	assert.Contains(t, log, "REGENERATED_WITH_INDEX="+testUvArtiIndexUrl,
		"'uv lock' must run against the curation gateway when generating a fresh lock")
}

const pep723ScriptContent = `# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "six==1.16.0",
# ]
# ///

import six
`

func TestBuildDependencyTreeForScript_RejectsNonPyFile(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "notascript.txt")
	require.NoError(t, os.WriteFile(scriptPath, []byte(pep723ScriptContent), 0644))

	_, _, _, err := buildDependencyTreeForScript(technologies.BuildInfoBomGeneratorParams{ScriptPath: scriptPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PEP 723")
}

func TestBuildDependencyTreeForScript_RejectsMissingPep723Metadata(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "plain.py")
	require.NoError(t, os.WriteFile(scriptPath, []byte("import six\n"), 0644))

	_, _, _, err := buildDependencyTreeForScript(technologies.BuildInfoBomGeneratorParams{ScriptPath: scriptPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PEP 723")
}

// writeFakeUvExecutableForScriptLock fakes "uv lock --script" to write a lock with one
// resolved "six" package, so tests can exercise the full parse -> tree -> URLs pipeline.
func writeFakeUvExecutableForScriptLock(t *testing.T, dir, artifactoryUrl, repoName string) {
	t.Helper()
	lockContent := fmt.Sprintf(`version = 1
requires-python = ">=3.11"

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "%[1]s/api/curation/audit/api/pypi/%[2]s/simple" }
wheels = [
    { url = "%[1]s/api/curation/audit/api/pypi/%[2]s/packages/six-1.16.0-py3-none-any.whl" },
]
`, strings.TrimSuffix(artifactoryUrl, "/"), repoName)

	name := filepath.Join(dir, "uv")
	script := "#!/bin/sh\n" +
		`if [ "$1" = "--version" ]; then echo "uv 0.11.21 (fake)"; exit 0; fi` + "\n" +
		`if [ "$1" = "lock" ] && [ "$2" = "--script" ]; then cat > "$3.lock" << 'LOCKEOF'` + "\n" +
		lockContent +
		"LOCKEOF\nexit 0\nfi\nexit 1\n"
	if runtime.GOOS == "windows" {
		t.Skip("fake uv script uses a POSIX heredoc; skip this test on Windows")
	}
	require.NoError(t, os.WriteFile(name, []byte(script), 0755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// writeFakeUvExecutableForEmptyScriptLock fakes "uv lock --script" to write an empty lock,
// so the "nothing to audit" guard in buildDependencyTreeForScript can be tested.
func writeFakeUvExecutableForEmptyScriptLock(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake uv script uses a POSIX heredoc; skip this test on Windows")
	}
	name := filepath.Join(dir, "uv")
	script := "#!/bin/sh\n" +
		`if [ "$1" = "--version" ]; then echo "uv 0.11.21 (fake)"; exit 0; fi` + "\n" +
		`if [ "$1" = "lock" ] && [ "$2" = "--script" ]; then cat > "$3.lock" << 'LOCKEOF'` + "\n" +
		"version = 1\nrequires-python = \">=3.11\"\n" +
		"LOCKEOF\nexit 0\nfi\nexit 1\n"
	require.NoError(t, os.WriteFile(name, []byte(script), 0755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestBuildDependencyTreeForScript_NoDependencies: a script with no dependencies resolves
// to an empty lock, so buildDependencyTreeForScript must return a clear error, not an
// empty/misleading result.
func TestBuildDependencyTreeForScript_NoDependencies(t *testing.T) {
	fakeBinDir := t.TempDir()
	writeFakeUvExecutableForEmptyScriptLock(t, fakeBinDir)

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "no_deps_script.py")
	require.NoError(t, os.WriteFile(scriptPath, []byte("# /// script\n# requires-python = \">=3.11\"\n# ///\n\nprint(\"hi\")\n"), 0644))

	_, _, _, err := buildDependencyTreeForScript(technologies.BuildInfoBomGeneratorParams{ScriptPath: scriptPath})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no dependencies to audit")
}

// TestBuildDependencyTreeForScript_ResolvesThroughGateway is the happy-path test: a valid
// PEP 723 script resolves through the curation gateway into a dep tree with a clean
// (pass-through-prefix-stripped) download URL.
func TestBuildDependencyTreeForScript_ResolvesThroughGateway(t *testing.T) {
	fakeBinDir := t.TempDir()
	const artifactoryUrl = "https://arti.example.com"
	const repoName = "pypi-remote"
	writeFakeUvExecutableForScriptLock(t, fakeBinDir, artifactoryUrl, repoName)

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "demo_script.py")
	require.NoError(t, os.WriteFile(scriptPath, []byte(pep723ScriptContent), 0644))

	params := technologies.BuildInfoBomGeneratorParams{
		ScriptPath:             scriptPath,
		ServerDetails:          &config.ServerDetails{ArtifactoryUrl: artifactoryUrl + "/"},
		DependenciesRepository: repoName,
	}

	depTree, uniqueDeps, downloadUrls, err := buildDependencyTreeForScript(params)
	require.NoError(t, err)

	require.Len(t, depTree, 1, "no editable/virtual root in a script lock -> synthetic root")
	assert.Equal(t, "root", depTree[0].Id)
	require.Len(t, depTree[0].Nodes, 1)
	sixId := python.PythonPackageTypeIdentifier + "six:1.16.0"
	assert.Equal(t, sixId, depTree[0].Nodes[0].Id)
	assert.Contains(t, uniqueDeps, sixId)
	assert.Equal(t, artifactoryUrl+"/api/pypi/"+repoName+"/packages/six-1.16.0-py3-none-any.whl", downloadUrls[sixId],
		"the curation pass-through prefix must be stripped from the download URL")
}
