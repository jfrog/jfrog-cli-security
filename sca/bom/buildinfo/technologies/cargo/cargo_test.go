package cargo

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipIfCargoUnavailable skips t if cargo can't actually run -- exec.LookPath alone isn't enough,
// since a rustup shim can exist on PATH with no default toolchain configured (e.g. some CI images).
func skipIfCargoUnavailable(t *testing.T) {
	t.Helper()
	if exec.Command("cargo", "--version").Run() != nil {
		t.Skip("cargo not available")
	}
}

func TestBuildDependencyTreeRejectsNonCurationInvocation(t *testing.T) {
	t.Setenv("PATH", "")
	_, _, err := BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{IsCurationCmd: false})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "could not find the 'cargo' executable")
}

// A project-shipped .cargo/config.toml must not survive the copy, or it would override the isolated CARGO_HOME.
func TestBuildDependencyTreeProjectLocalCargoConfigOverridesCurationRedirect(t *testing.T) {
	skipIfCargoUnavailable(t)
	projectDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(projectDir, ".cargo"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".cargo", "config.toml"), []byte(`
[net]
retry = 0

[source.crates-io]
replace-with = "evil-mirror"

[source.evil-mirror]
registry = "sparse+http://127.0.0.1:9/index/"
`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "Cargo.toml"), []byte(`
[package]
name = "probe"
version = "0.1.0"
edition = "2021"

[dependencies]
libc = "0.2"
`), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(projectDir, "src"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "src", "main.rs"), []byte("fn main() {}"), 0600))

	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	defer func() { require.NoError(t, os.Chdir(prevWd)) }()

	server := &config.ServerDetails{ArtifactoryUrl: "https://curation.example.com/artifactory/", User: "admin", Password: "pw"}
	_, _, err = BuildDependencyTree(technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		ServerDetails:          server,
		DependenciesRepository: "curation-repo",
	})

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "evil-mirror",
		"curation isolation must not be overridable by a .cargo/config.toml the audited project ships itself")
}

// writeCargoPackage writes a minimal lib crate at dir/name with path-only dependencies (no network needed).
func writeCargoPackage(t *testing.T, root, name string, pathDeps map[string]string) {
	t.Helper()
	dir := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "lib.rs"), []byte(""), 0600))

	depsBlock := ""
	for depName, path := range pathDeps {
		depsBlock += depName + " = { path = " + `"` + path + `"` + " }\n"
	}
	content := "[package]\nname = \"" + name + "\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
	if depsBlock != "" {
		content += "\n[dependencies]\n" + depsBlock
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(content), 0600))
}

// hermeticCargoEnv points HOME/CARGO_HOME at fresh temp dirs, isolating the test from the machine's own config.
func hermeticCargoEnv(t *testing.T) {
	t.Helper()
	// Preserve RUSTUP_HOME -- wiping HOME alone orphans CI's rustup-shimmed cargo from its toolchain.
	if os.Getenv("RUSTUP_HOME") == "" {
		if realHome, err := os.UserHomeDir(); err == nil {
			t.Setenv("RUSTUP_HOME", filepath.Join(realHome, ".rustup"))
		}
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CARGO_HOME", t.TempDir())
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(prevWd)) })
}

func curationParams() technologies.BuildInfoBomGeneratorParams {
	return technologies.BuildInfoBomGeneratorParams{
		IsCurationCmd:          true,
		ServerDetails:          &config.ServerDetails{ArtifactoryUrl: "https://curation.example.com/artifactory/", User: "admin", Password: "pw"},
		DependenciesRepository: "curation-repo",
	}
}

// Auditing a member of a root-crate workspace must report the member's own deps, not the root crate's.
func TestBuildDependencyTreeRootCrateWorkspaceMemberScoping(t *testing.T) {
	skipIfCargoUnavailable(t)
	hermeticCargoEnv(t)
	root := t.TempDir()
	writeCargoPackage(t, root, "leaf-a", nil)
	writeCargoPackage(t, root, "leaf-c", nil)
	writeCargoPackage(t, root, "member-b", map[string]string{"leaf-c": "../leaf-c"})
	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte(`
[package]
name = "root-crate"
version = "0.1.0"
edition = "2021"

[dependencies]
leaf-a = { path = "leaf-a" }

[workspace]
members = ["member-b", "leaf-a", "leaf-c"]
`), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "src"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "src", "lib.rs"), []byte(""), 0600))

	chdir(t, filepath.Join(root, "member-b"))
	trees, uniqueDeps, err := BuildDependencyTree(curationParams())
	require.NoError(t, err)

	require.Len(t, trees, 1)
	assert.Equal(t, PackageTypeIdentifier+"member-b:0.1.0", trees[0].Id)
	assert.Contains(t, uniqueDeps, PackageTypeIdentifier+"leaf-c:0.1.0")
	assert.NotContains(t, uniqueDeps, PackageTypeIdentifier+"leaf-a:0.1.0",
		"auditing member-b must not report the root crate's own dependency")
}

// Auditing a member of a virtual-manifest workspace must not report sibling members' dependencies too.
func TestBuildDependencyTreeVirtualWorkspaceMemberScoping(t *testing.T) {
	skipIfCargoUnavailable(t)
	hermeticCargoEnv(t)
	root := t.TempDir()
	writeCargoPackage(t, root, "leaf-x", nil)
	writeCargoPackage(t, root, "leaf-y", nil)
	writeCargoPackage(t, root, "member-x", map[string]string{"leaf-x": "../leaf-x"})
	writeCargoPackage(t, root, "member-y", map[string]string{"leaf-y": "../leaf-y"})
	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte(`
[workspace]
members = ["member-x", "leaf-x", "member-y", "leaf-y"]
`), 0600))

	chdir(t, filepath.Join(root, "member-x"))
	trees, uniqueDeps, err := BuildDependencyTree(curationParams())
	require.NoError(t, err)

	require.Len(t, trees, 1)
	assert.Equal(t, PackageTypeIdentifier+"member-x:0.1.0", trees[0].Id)
	assert.Contains(t, uniqueDeps, PackageTypeIdentifier+"leaf-x:0.1.0")
	assert.NotContains(t, uniqueDeps, PackageTypeIdentifier+"leaf-y:0.1.0",
		"auditing member-x must not report sibling member-y's dependency")
}

// Two distinct members of the same workspace must each get their own report; only a literal repeat is a duplicate.
func TestBuildDependencyTreeDistinctMembersBothReported(t *testing.T) {
	skipIfCargoUnavailable(t)
	hermeticCargoEnv(t)
	root := t.TempDir()
	writeCargoPackage(t, root, "leaf-x", nil)
	writeCargoPackage(t, root, "leaf-y", nil)
	writeCargoPackage(t, root, "member-x", map[string]string{"leaf-x": "../leaf-x"})
	writeCargoPackage(t, root, "member-y", map[string]string{"leaf-y": "../leaf-y"})
	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte(`
[workspace]
members = ["member-x", "leaf-x", "member-y", "leaf-y"]
`), 0600))

	chdir(t, filepath.Join(root, "member-x"))
	_, uniqueDepsX, err := BuildDependencyTree(curationParams())
	require.NoError(t, err)
	assert.Contains(t, uniqueDepsX, PackageTypeIdentifier+"leaf-x:0.1.0")

	chdir(t, filepath.Join(root, "member-y"))
	_, uniqueDepsY, err := BuildDependencyTree(curationParams())
	require.NoError(t, err, "a distinct member must not be deduped against a different member's audit")
	assert.Contains(t, uniqueDepsY, PackageTypeIdentifier+"leaf-y:0.1.0")

	chdir(t, filepath.Join(root, "member-x"))
	_, _, err = BuildDependencyTree(curationParams())
	require.ErrorIs(t, err, ErrCargoWorkspaceAlreadyAudited, "a literal repeat of the same directory must still be caught")
}

// The isolated config must always wire its own crates-io replacement, since a global ambient one is invisible once CARGO_HOME redirects.
func TestProtectCargoCurationEnvironmentAlwaysOverridesCratesIo(t *testing.T) {
	ambientCargoHome := t.TempDir()
	projectDir := t.TempDir()

	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	ambientConfig := `[source.crates-io]
replace-with = "artifactory"

[source.artifactory]
registry = "sparse+https://ambient.example.com/artifactory/api/cargo/cargo-remote/index/"
`
	require.NoError(t, os.WriteFile(filepath.Join(ambientCargoHome, "config.toml"), []byte(ambientConfig), 0600))
	t.Setenv("CARGO_HOME", ambientCargoHome)

	server := &config.ServerDetails{ArtifactoryUrl: "https://curation.example.com/artifactory/", User: "admin", Password: "pw"}
	restore, err := protectCargoCurationEnvironment(server, "curation-repo")
	require.NoError(t, err)
	defer func() { require.NoError(t, restore()) }()

	written, err := os.ReadFile(filepath.Join(os.Getenv("CARGO_HOME"), "config.toml")) // #nosec G703 -- test-controlled temp CARGO_HOME, not attacker input
	require.NoError(t, err)
	assert.Contains(t, string(written), "[source.crates-io]")
	assert.Contains(t, string(written), "replace-with")
}

// An ambient registries name unsafe for a bare TOML key must not be reused as-is -- it must not corrupt the isolated config.
func TestProtectCargoCurationEnvironmentRejectsUnsafeAmbientRegistriesName(t *testing.T) {
	ambientCargoHome := t.TempDir()
	projectDir := t.TempDir()

	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	ambientConfig := `[registry]
default = "evil name]"

[registries."evil name]"]
index = "sparse+https://ambient.example.com/artifactory/api/cargo/cargo-remote/index/"
`
	require.NoError(t, os.WriteFile(filepath.Join(ambientCargoHome, "config.toml"), []byte(ambientConfig), 0600))
	t.Setenv("CARGO_HOME", ambientCargoHome)

	server := &config.ServerDetails{ArtifactoryUrl: "https://curation.example.com/artifactory/", User: "admin", Password: "pw"}
	restore, err := protectCargoCurationEnvironment(server, "curation-repo")
	require.NoError(t, err)
	defer func() { require.NoError(t, restore()) }()

	written, err := os.ReadFile(filepath.Join(os.Getenv("CARGO_HOME"), "config.toml")) // #nosec G703 -- test-controlled temp CARGO_HOME, not attacker input
	require.NoError(t, err)
	assert.NotContains(t, string(written), "evil name",
		"an unsafe ambient registries name must not be spliced unescaped into the isolated config")

	var decoded map[string]interface{}
	_, decErr := toml.Decode(string(written), &decoded)
	require.NoError(t, decErr, "the isolated config.toml must always be valid TOML, written:\n%s", string(written))
}

func TestEnsureCargoLockfileWrapsUnderlyingError(t *testing.T) {
	err := ensureCargoLockfile("/definitely/not/a/real/cargo/binary/xyz", t.TempDir())
	require.Error(t, err)
	require.NotNil(t, errors.Unwrap(err),
		"ensureCargoLockfile error must wrap the underlying exec error with %w so errors.Is/errors.As can see the cause")
}

func TestCargoBasicAuthTokenPrefersPassword(t *testing.T) {
	token, err := cargoBasicAuthToken(&config.ServerDetails{User: "admin", Password: "pw123", AccessToken: "tok456"})
	require.NoError(t, err)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:pw123")), token)
}

func TestCargoBasicAuthTokenFallsBackToAccessToken(t *testing.T) {
	token, err := cargoBasicAuthToken(&config.ServerDetails{User: "admin", AccessToken: "tok456"})
	require.NoError(t, err)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:tok456")), token)
}

func TestCargoBasicAuthTokenErrorsWithNeither(t *testing.T) {
	_, err := cargoBasicAuthToken(&config.ServerDetails{User: "admin"})
	require.Error(t, err)
	assert.Equal(t, "cargo: Artifactory server has no password or access token configured for curation authentication", err.Error())
}

func TestCargoBasicAuthTokenErrorsOnNilServer(t *testing.T) {
	_, err := cargoBasicAuthToken(nil)
	require.Error(t, err)
}

func TestParseArtifactoryCargoIndexUrl(t *testing.T) {
	tests := []struct {
		name        string
		rawUrl      string
		wantArtiUrl string
		wantRepo    string
		wantErr     bool
	}{
		{
			name:        "valid sparse url",
			rawUrl:      "sparse+https://host/artifactory/api/cargo/my-repo/index/",
			wantArtiUrl: "https://host/artifactory",
			wantRepo:    "my-repo",
		},
		{
			name:        "valid url without sparse+ prefix",
			rawUrl:      "https://host/artifactory/api/cargo/my-repo/index/",
			wantArtiUrl: "https://host/artifactory",
			wantRepo:    "my-repo",
		},
		{
			name:        "repo name has trailing path segments",
			rawUrl:      "sparse+https://host/artifactory/api/cargo/my-repo/index/config.json",
			wantArtiUrl: "https://host/artifactory",
			wantRepo:    "my-repo",
		},
		{
			name:    "missing /api/cargo/ marker",
			rawUrl:  "sparse+https://host/artifactory/api/pypi/my-repo/simple/",
			wantErr: true,
		},
		{
			name:    "empty repo name",
			rawUrl:  "sparse+https://host/artifactory/api/cargo//index/",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseArtifactoryCargoIndexUrl(tt.rawUrl)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantArtiUrl, cfg.ArtifactoryUrl)
			assert.Equal(t, tt.wantRepo, cfg.RepoName)
		})
	}
}

func TestParseCargoConfigRegistry(t *testing.T) {
	tests := []struct {
		name             string
		content          string
		wantOk           bool
		wantArtiUrl      string
		wantRepo         string
		wantRegistryName string
	}{
		{
			name: "crates-io replace-with chain wins",
			content: `[source.crates-io]
replace-with = "artifactory-remote"

[source.artifactory-remote]
registry = "sparse+https://host/artifactory/api/cargo/repo-a/index/"

[registry]
default = "artifactory"

[registries.artifactory]
index = "sparse+https://host/artifactory/api/cargo/repo-b/index/"
`,
			wantOk:      true,
			wantArtiUrl: "https://host/artifactory",
			wantRepo:    "repo-a",
		},
		{
			name: "registry default chain",
			content: `[registry]
default = "artifactory"

[registries.artifactory]
index = "sparse+https://host/artifactory/api/cargo/repo-b/index/"
`,
			wantOk:           true,
			wantArtiUrl:      "https://host/artifactory",
			wantRepo:         "repo-b",
			wantRegistryName: "artifactory",
		},
		{
			name: "bare source entry",
			content: `[source.artifactory-remote]
registry = "sparse+https://host/artifactory/api/cargo/repo-c/index/"
`,
			wantOk:      true,
			wantArtiUrl: "https://host/artifactory",
			wantRepo:    "repo-c",
		},
		{
			name: "bare registries entry",
			content: `[registries.artifactory]
index = "sparse+https://host/artifactory/api/cargo/repo-d/index/"
`,
			wantOk:           true,
			wantArtiUrl:      "https://host/artifactory",
			wantRepo:         "repo-d",
			wantRegistryName: "artifactory",
		},
		{
			name:    "no artifactory registry configured",
			content: `[source.crates-io]` + "\n",
			wantOk:  false,
		},
		{
			name:    "invalid toml",
			content: `not valid toml [[[`,
			wantOk:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, ok := parseCargoConfigRegistry(tt.content)
			require.Equal(t, tt.wantOk, ok)
			if !tt.wantOk {
				return
			}
			assert.Equal(t, tt.wantArtiUrl, cfg.ArtifactoryUrl)
			assert.Equal(t, tt.wantRepo, cfg.RepoName)
			assert.Equal(t, tt.wantRegistryName, cfg.AmbientRegistriesName)
		})
	}
}

func TestFindProjectCargoConfig(t *testing.T) {
	t.Run("found in current dir", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, ".cargo"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, ".cargo", "config.toml"), []byte(""), 0600))

		path, found := findProjectCargoConfig(root)
		require.True(t, found)
		assert.Equal(t, filepath.Join(root, ".cargo", "config.toml"), path)
	})

	t.Run("found by walking up to parent", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, ".cargo"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, ".cargo", "config.toml"), []byte(""), 0600))
		nested := filepath.Join(root, "a", "b", "c")
		require.NoError(t, os.MkdirAll(nested, 0755))

		path, found := findProjectCargoConfig(nested)
		require.True(t, found)
		assert.Equal(t, filepath.Join(root, ".cargo", "config.toml"), path)
	})

	t.Run("legacy extension-less config file", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, ".cargo"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, ".cargo", "config"), []byte(""), 0600))

		path, found := findProjectCargoConfig(root)
		require.True(t, found)
		assert.Equal(t, filepath.Join(root, ".cargo", "config"), path)
	})

	t.Run("not found stops at HOME", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		nested := filepath.Join(home, "projects", "myapp")
		require.NoError(t, os.MkdirAll(nested, 0755))

		_, found := findProjectCargoConfig(nested)
		assert.False(t, found)
	})
}

func TestReadEffectiveCargoConfig(t *testing.T) {
	t.Run("project-local wins over CARGO_HOME", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		cargoHome := t.TempDir()
		t.Setenv("CARGO_HOME", cargoHome)
		require.NoError(t, os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte("# global"), 0600))

		projectDir, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(projectDir, ".cargo"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".cargo", "config.toml"), []byte("# project-local"), 0600))

		prevWd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(projectDir))
		defer func() { require.NoError(t, os.Chdir(prevWd)) }()

		content, sourcePath, err := readEffectiveCargoConfig()
		require.NoError(t, err)
		assert.Equal(t, "# project-local", content)
		assert.Equal(t, filepath.Join(projectDir, ".cargo", "config.toml"), sourcePath)
	})

	t.Run("falls back to CARGO_HOME when no project-local config exists", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		cargoHome := t.TempDir()
		t.Setenv("CARGO_HOME", cargoHome)
		require.NoError(t, os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte("# global"), 0600))

		projectDir := t.TempDir()
		prevWd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(projectDir))
		defer func() { require.NoError(t, os.Chdir(prevWd)) }()

		content, sourcePath, err := readEffectiveCargoConfig()
		require.NoError(t, err)
		assert.Equal(t, "# global", content)
		assert.Equal(t, filepath.Join(cargoHome, "config.toml"), sourcePath)
	})

	t.Run("errors when neither exists", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("CARGO_HOME", filepath.Join(home, ".cargo-does-not-exist"))

		projectDir := t.TempDir()
		prevWd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(projectDir))
		defer func() { require.NoError(t, os.Chdir(prevWd)) }()

		_, _, err = readEffectiveCargoConfig()
		require.Error(t, err)
	})

	t.Run("a project-local config silent on registries falls through to CARGO_HOME's, like firecracker-microvm's", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		cargoHome, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		t.Setenv("CARGO_HOME", cargoHome)
		require.NoError(t, os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(`
[source.crates-io]
replace-with = "artifactory"

[source.artifactory]
registry = "sparse+https://acme.jfrog.io/artifactory/api/cargo/cargo-remote/index/"
`), 0600))

		projectDir, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(projectDir, ".cargo"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".cargo", "config.toml"), []byte(`
[build]
target-dir = "target"

[net]
retry = 2

[env]
FOO = "bar"
`), 0600))

		prevWd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(projectDir))
		defer func() { require.NoError(t, os.Chdir(prevWd)) }()

		content, sourcePath, err := readEffectiveCargoConfig()
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(cargoHome, "config.toml"), sourcePath,
			"a project-local config that never mentions a registry must not hide CARGO_HOME's")
		_, ok := parseCargoConfigRegistry(content)
		assert.True(t, ok)
	})
}

func TestDetectConflictingCargoSources(t *testing.T) {
	t.Run("same repo under different names is rejected", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		cargoHome := t.TempDir()
		t.Setenv("CARGO_HOME", cargoHome)
		require.NoError(t, os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(`[source.global-name]
registry = "sparse+https://host/artifactory/api/cargo/shared-repo/index/"
`), 0600))

		projectDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(projectDir, ".cargo"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".cargo", "config.toml"), []byte(`[source.project-name]
registry = "sparse+https://host/artifactory/api/cargo/shared-repo/index/"
`), 0600))

		prevWd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(projectDir))
		defer func() { require.NoError(t, os.Chdir(prevWd)) }()

		err = DetectConflictingCargoSources()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configured under different names")
	})

	t.Run("same name across both files is not a conflict", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		cargoHome := t.TempDir()
		t.Setenv("CARGO_HOME", cargoHome)
		require.NoError(t, os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(`[source.artifactory-remote]
registry = "sparse+https://host/artifactory/api/cargo/shared-repo/index/"
`), 0600))

		projectDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(projectDir, ".cargo"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(projectDir, ".cargo", "config.toml"), []byte(`[source.artifactory-remote]
registry = "sparse+https://host/artifactory/api/cargo/shared-repo/index/"
`), 0600))

		prevWd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(projectDir))
		defer func() { require.NoError(t, os.Chdir(prevWd)) }()

		require.NoError(t, DetectConflictingCargoSources())
	})

	t.Run("no ambient config at all is not a conflict", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("CARGO_HOME", filepath.Join(home, ".cargo-does-not-exist"))

		projectDir := t.TempDir()
		prevWd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(projectDir))
		defer func() { require.NoError(t, os.Chdir(prevWd)) }()

		require.NoError(t, DetectConflictingCargoSources())
	})
}

func TestReadRootPackageName(t *testing.T) {
	t.Run("returns the declared package name", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(`[package]
name = "my-crate"
version = "0.1.0"
`), 0600))
		assert.Equal(t, "my-crate", readRootPackageName(dir))
	})

	t.Run("returns empty string for a virtual workspace manifest", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(`[workspace]
members = ["crate-a", "crate-b"]
`), 0600))
		assert.Equal(t, "", readRootPackageName(dir))
	})

	t.Run("returns empty string when Cargo.toml is missing", func(t *testing.T) {
		dir := t.TempDir()
		assert.Equal(t, "", readRootPackageName(dir))
	})
}

func TestParseCargoDependencyEntry(t *testing.T) {
	tests := []struct {
		name        string
		edge        string
		wantName    string
		wantVersion string
	}{
		{name: "bare name", edge: "libc", wantName: "libc", wantVersion: ""},
		{name: "name and version", edge: "libc 0.2.155 (registry+https://...)", wantName: "libc", wantVersion: "0.2.155"},
		{name: "empty edge", edge: "", wantName: "", wantVersion: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version := parseCargoDependencyEntry(tt.edge)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

func TestResolveCargoDependency(t *testing.T) {
	byName := map[string][]*cargoPackage{
		"libc": {{Name: "libc", Version: "0.2.155"}},
		"windows-sys": {
			{Name: "windows-sys", Version: "0.48.0"},
			{Name: "windows-sys", Version: "0.52.0"},
		},
	}

	t.Run("single candidate matches by name alone", func(t *testing.T) {
		deps := resolveCargoDependency(byName, "libc")
		require.Len(t, deps, 1)
		assert.Equal(t, "0.2.155", deps[0].Version)
	})

	t.Run("exact version disambiguates among multiple candidates", func(t *testing.T) {
		deps := resolveCargoDependency(byName, "windows-sys 0.52.0")
		require.Len(t, deps, 1)
		assert.Equal(t, "0.52.0", deps[0].Version)
	})

	t.Run("unmatched version falls back to every candidate", func(t *testing.T) {
		deps := resolveCargoDependency(byName, "windows-sys 0.99.0")
		assert.Len(t, deps, 2)
	})

	t.Run("unknown name returns nil", func(t *testing.T) {
		assert.Nil(t, resolveCargoDependency(byName, "does-not-exist"))
	})
}

func TestFindLocalPackage(t *testing.T) {
	t.Run("returns the local candidate", func(t *testing.T) {
		candidates := []*cargoPackage{
			{Name: "libc", Version: "0.2.100", Source: "registry+https://..."},
			{Name: "libc", Version: "0.1.0", Source: ""},
		}
		local := findLocalPackage(candidates)
		require.NotNil(t, local)
		assert.Equal(t, "0.1.0", local.Version)
	})

	t.Run("falls back to the first candidate when none is local", func(t *testing.T) {
		candidates := []*cargoPackage{
			{Name: "libc", Version: "0.2.100", Source: "registry+https://..."},
		}
		local := findLocalPackage(candidates)
		require.NotNil(t, local)
		assert.Equal(t, "0.2.100", local.Version)
	})

	t.Run("returns nil for an empty slice", func(t *testing.T) {
		assert.Nil(t, findLocalPackage(nil))
	})
}

func TestBuildCargoDepTree(t *testing.T) {
	t.Run("single project package builds the tree from its own dependency edges", func(t *testing.T) {
		lock := cargoLockFile{
			Packages: []cargoPackage{
				{Name: "my-crate", Version: "0.1.0", Dependencies: []string{"libc"}},
				{Name: "libc", Version: "0.2.155", Source: "registry+https://..."},
			},
		}
		trees, uniqueDeps, err := buildCargoDepTree(lock, "my-crate")
		require.NoError(t, err)
		require.Len(t, trees, 1)
		assert.Equal(t, PackageTypeIdentifier+"my-crate:0.1.0", trees[0].Id)
		require.Len(t, trees[0].Nodes, 1)
		assert.Equal(t, PackageTypeIdentifier+"libc:0.2.155", trees[0].Nodes[0].Id)
		assert.Contains(t, uniqueDeps, PackageTypeIdentifier+"libc:0.2.155")
	})

	t.Run("virtual workspace unions every local package under a synthetic root", func(t *testing.T) {
		lock := cargoLockFile{
			Packages: []cargoPackage{
				{Name: "crate-a", Version: "0.1.0", Dependencies: []string{"libc"}},
				{Name: "crate-b", Version: "0.1.0", Dependencies: []string{"libc"}},
				{Name: "libc", Version: "0.2.155", Source: "registry+https://..."},
			},
		}
		trees, uniqueDeps, err := buildCargoDepTree(lock, "")
		require.NoError(t, err)
		require.Len(t, trees, 1)
		assert.Equal(t, "root", trees[0].Id)
		assert.Len(t, trees[0].Nodes, 2)
		assert.Contains(t, uniqueDeps, PackageTypeIdentifier+"libc:0.2.155")
	})

	t.Run("errors when no local package can be identified", func(t *testing.T) {
		lock := cargoLockFile{
			Packages: []cargoPackage{
				{Name: "libc", Version: "0.2.155", Source: "registry+https://..."},
			},
		}
		_, _, err := buildCargoDepTree(lock, "")
		require.Error(t, err)
	})

	t.Run("a shared dependency's subtree is expanded once, not once per path reaching it", func(t *testing.T) {
		// Diamond fan-in: each level's two packages depend on both of the level below's, doubling paths to the bottom.
		const levels = 12
		pkgs := []cargoPackage{
			{Name: "leaf-a", Version: "0.1.0"},
			{Name: "leaf-b", Version: "0.1.0"},
		}
		prevA, prevB := "leaf-a", "leaf-b"
		for i := 1; i <= levels; i++ {
			a, b := fmt.Sprintf("a%d", i), fmt.Sprintf("b%d", i)
			pkgs = append(pkgs,
				cargoPackage{Name: a, Version: "0.1.0", Dependencies: []string{prevA, prevB}},
				cargoPackage{Name: b, Version: "0.1.0", Dependencies: []string{prevA, prevB}},
			)
			prevA, prevB = a, b
		}
		pkgs = append(pkgs, cargoPackage{Name: "root-crate", Version: "0.1.0", Dependencies: []string{prevA, prevB}})

		trees, uniqueDeps, err := buildCargoDepTree(cargoLockFile{Packages: pkgs}, "root-crate")
		require.NoError(t, err)
		require.Len(t, trees, 1)

		var countNodes func(n *xrayUtils.GraphNode) int
		countNodes = func(n *xrayUtils.GraphNode) int {
			total := 1
			for _, c := range n.Nodes {
				total += countNodes(c)
			}
			return total
		}
		total := countNodes(trees[0])
		assert.Less(t, total, 6*levels,
			"a shared diamond dependency must be expanded once, not once per path (got a node count consistent with exponential re-expansion)")
		assert.Len(t, uniqueDeps, 2*levels+2, "every distinct package must still be reported exactly once")
	})
}

func TestLockMatchesDeclaredDependencies(t *testing.T) {
	writeLock := func(t *testing.T, dir, content string) string {
		t.Helper()
		path := filepath.Join(dir, "Cargo.lock")
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
		return path
	}

	t.Run("exact pin matching the locked version is not stale", func(t *testing.T) {
		lockPath := writeLock(t, t.TempDir(), `
[[package]]
name = "mycrate"
version = "0.1.0"
dependencies = ["foo"]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
		declared := map[string]map[string]string{"mycrate": {"foo": "=1.0.0"}}
		assert.True(t, lockMatchesDeclaredDependencies(lockPath, declared))
	})

	t.Run("exact pin with a space after '=' matching the locked version is not stale", func(t *testing.T) {
		lockPath := writeLock(t, t.TempDir(), `
[[package]]
name = "mycrate"
version = "0.1.0"
dependencies = ["foo"]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
		declared := map[string]map[string]string{"mycrate": {"foo": "= 1.0.0"}}
		assert.True(t, lockMatchesDeclaredDependencies(lockPath, declared))
	})

	t.Run("exact pin no longer matching the locked version is stale", func(t *testing.T) {
		lockPath := writeLock(t, t.TempDir(), `
[[package]]
name = "mycrate"
version = "0.1.0"
dependencies = ["foo"]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
		declared := map[string]map[string]string{"mycrate": {"foo": "=2.0.0"}}
		assert.False(t, lockMatchesDeclaredDependencies(lockPath, declared))
	})

	t.Run("caret/bare requirement satisfied by the locked version is not stale", func(t *testing.T) {
		lockPath := writeLock(t, t.TempDir(), `
[[package]]
name = "mycrate"
version = "0.1.0"
dependencies = ["foo"]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
		for _, req := range []string{"1.0", "^1.0"} {
			declared := map[string]map[string]string{"mycrate": {"foo": req}}
			assert.True(t, lockMatchesDeclaredDependencies(lockPath, declared), "requirement %q should be verified as satisfied", req)
		}
	})

	// No semver parser handles these shapes, so they can never be verified against the lock.
	t.Run("non-caret requirement shapes are always treated as unverifiable, forcing regeneration", func(t *testing.T) {
		lockPath := writeLock(t, t.TempDir(), `
[[package]]
name = "mycrate"
version = "0.1.0"
dependencies = ["foo"]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
		for _, req := range []string{"~1.0", ">=1.0", "1.0.*"} {
			declared := map[string]map[string]string{"mycrate": {"foo": req}}
			assert.False(t, lockMatchesDeclaredDependencies(lockPath, declared), "requirement %q must not be treated as matching", req)
		}
	})

	t.Run("added declared dependency not yet in the lock is stale", func(t *testing.T) {
		lockPath := writeLock(t, t.TempDir(), `
[[package]]
name = "mycrate"
version = "0.1.0"
dependencies = []
`)
		declared := map[string]map[string]string{"mycrate": {"foo": "=1.0.0"}}
		assert.False(t, lockMatchesDeclaredDependencies(lockPath, declared))
	})

	t.Run("removed dependency still present in the lock is stale", func(t *testing.T) {
		lockPath := writeLock(t, t.TempDir(), `
[[package]]
name = "mycrate"
version = "0.1.0"
dependencies = ["foo"]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
		declared := map[string]map[string]string{"mycrate": {}}
		assert.False(t, lockMatchesDeclaredDependencies(lockPath, declared))
	})
}

func TestCaretBounds(t *testing.T) {
	tests := []struct {
		req          string
		lower, upper [3]int
		ok           bool
	}{
		{req: "1.2.3", lower: [3]int{1, 2, 3}, upper: [3]int{2, 0, 0}, ok: true},
		{req: "^1.2.3", lower: [3]int{1, 2, 3}, upper: [3]int{2, 0, 0}, ok: true},
		{req: "1.2", lower: [3]int{1, 2, 0}, upper: [3]int{2, 0, 0}, ok: true},
		{req: "1", lower: [3]int{1, 0, 0}, upper: [3]int{2, 0, 0}, ok: true},
		{req: "0.2.3", lower: [3]int{0, 2, 3}, upper: [3]int{0, 3, 0}, ok: true},
		{req: "0.2", lower: [3]int{0, 2, 0}, upper: [3]int{0, 3, 0}, ok: true},
		{req: "0.0.3", lower: [3]int{0, 0, 3}, upper: [3]int{0, 0, 4}, ok: true},
		{req: "0.0", lower: [3]int{0, 0, 0}, upper: [3]int{0, 1, 0}, ok: true},
		{req: "0", lower: [3]int{0, 0, 0}, upper: [3]int{1, 0, 0}, ok: true},
		{req: "0.0.0", lower: [3]int{0, 0, 0}, upper: [3]int{0, 0, 1}, ok: true},
		{req: "~1.2.3", ok: false},
		{req: "1.2.*", ok: false},
		{req: ">=1.2.3", ok: false},
		{req: "1.2.3-alpha", ok: false},
		{req: "1.2.3+build5", ok: false},
		{req: "1.2.3.4", ok: false},
		{req: "-1.2.3", ok: false},
		{req: "", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.req, func(t *testing.T) {
			lower, upper, ok := caretBounds(tt.req)
			require.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.lower, lower)
				assert.Equal(t, tt.upper, upper)
			}
		})
	}
}

func TestVersionSatisfiesCaret(t *testing.T) {
	lower, upper, ok := caretBounds("1.2.3")
	require.True(t, ok)

	assert.True(t, versionSatisfiesCaret("1.2.3", lower, upper), "at the lower bound")
	assert.True(t, versionSatisfiesCaret("1.9.9", lower, upper), "inside the range")
	assert.False(t, versionSatisfiesCaret("1.2.2", lower, upper), "below the lower bound")
	assert.False(t, versionSatisfiesCaret("2.0.0", lower, upper), "at the exclusive upper bound")
	assert.False(t, versionSatisfiesCaret("1.2", lower, upper), "malformed version")
}
