package pnpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureDir is relative to the repository root; in tests we use
// technologies.CreateTestWorkspace to cd into the fixture, but for pure parser
// tests we want to read files without changing the working directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	// Walk up until we find the go.mod root, then descend into testdata.
	// Assumes tests run from within the module tree.
	dir, err := filepath.Abs("../../../../..")
	require.NoError(t, err)
	return filepath.Join(dir, "tests", "testdata", "projects", "package-managers", "pnpm", "pnpm-project")
}

// TestParsePnpmLockFileSimple exercises the simple fixture (two top-level deps, no transitives).
func TestParsePnpmLockFileSimple(t *testing.T) {
	dir := testdataDir(t)
	projects, err := parsePnpmLockFile(dir, ".")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	p := projects[0]
	assert.Equal(t, "pnpm-example", p.Name)
	assert.Equal(t, "1.0.0", p.Version)

	require.Contains(t, p.Dependencies, "xml")
	assert.Equal(t, "1.0.1", p.Dependencies["xml"].Version)

	require.Contains(t, p.DevDependencies, "json")
	assert.Equal(t, "9.0.6", p.DevDependencies["json"].Version)
}

// TestParsePnpmLockFileComplex tests scoped packages, peer-dep suffixes, and transitives.
func TestParsePnpmLockFileComplex(t *testing.T) {
	dir := testdataDir(t)
	// Swap the simple lockfile for the complex one temporarily.
	simpleLock := filepath.Join(dir, "pnpm-lock.yaml")
	complexLock := filepath.Join(dir, "pnpm-lock-complex.yaml")
	origContent, readErr := os.ReadFile(simpleLock)
	require.NoError(t, readErr)
	complexContent, readErr := os.ReadFile(complexLock)
	require.NoError(t, readErr)

	require.NoError(t, os.WriteFile(filepath.Clean(simpleLock), complexContent, 0644))    // #nosec G703 -- simpleLock is constructed from a test-controlled directory, not user input
	t.Cleanup(func() { _ = os.WriteFile(filepath.Clean(simpleLock), origContent, 0644) }) // #nosec G703 -- simpleLock is constructed from a test-controlled directory, not user input

	projects, err := parsePnpmLockFile(dir, ".")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	p := projects[0]
	assert.Equal(t, "pnpm-example", p.Name)
	assert.Equal(t, "1.0.0", p.Version)

	// prod: xml (no transitives)
	require.Contains(t, p.Dependencies, "xml")
	assert.Equal(t, "1.0.1", p.Dependencies["xml"].Version)
	assert.Empty(t, p.Dependencies["xml"].Dependencies)

	// prod: @scope/pkg — peer suffix stripped from version
	require.Contains(t, p.Dependencies, "@scope/pkg")
	scopedPkg := p.Dependencies["@scope/pkg"]
	assert.Equal(t, "2.0.0", scopedPkg.Version, "peer-dep suffix must be stripped from version")

	// @scope/pkg has two transitive deps: @peer/dep and transitive-a
	require.Contains(t, scopedPkg.Dependencies, "@peer/dep")
	assert.Equal(t, "1.0.0", scopedPkg.Dependencies["@peer/dep"].Version)
	require.Contains(t, scopedPkg.Dependencies, "transitive-a")
	assert.Equal(t, "1.2.3", scopedPkg.Dependencies["transitive-a"].Version)

	// dev: json
	require.Contains(t, p.DevDependencies, "json")
	assert.Equal(t, "9.0.6", p.DevDependencies["json"].Version)
}

// TestParsePnpmLockFileOptionalDependencies ensures optionalDependencies (e.g. sharp,
// fsevents) are curated as production dependencies, not silently dropped.
func TestParsePnpmLockFileOptionalDependencies(t *testing.T) {
	dir := t.TempDir()
	lock := "lockfileVersion: '9.0'\n" +
		"importers:\n" +
		"  .:\n" +
		"    dependencies:\n" +
		"      xml:\n" +
		"        specifier: 1.0.1\n" +
		"        version: 1.0.1\n" +
		"    optionalDependencies:\n" +
		"      fsevents:\n" +
		"        specifier: ^2.3.3\n" +
		"        version: 2.3.3\n" +
		"snapshots:\n" +
		"  xml@1.0.1: {}\n" +
		"  fsevents@2.3.3: {}\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lock), 0o644))

	projects, err := parsePnpmLockFile(dir, ".")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	deps := projects[0].Dependencies
	require.Contains(t, deps, "xml")
	require.Contains(t, deps, "fsevents", "optionalDependencies must be curated as prod deps")
	assert.Equal(t, "2.3.3", deps["fsevents"].Version)
}

func viteFixtureDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../../../..")
	require.NoError(t, err)
	return filepath.Join(dir, "tests", "testdata", "projects", "package-managers", "pnpm", "vite")
}

// TestParsePnpmLockFileVite is a smoke test using a trimmed copy of vitejs/vite's
// pnpm-lock.yaml. The fixture carries top-level blocks absent from the hand-crafted
// fixtures (patchedDependencies, overrides, packageExtensionsChecksum), so it would
// catch a regression such as switching to strict YAML decoding (KnownFields(true)).
// The fixture has 3 importers (root ".", packages/vite, packages/create-vite); they
// are collapsed into a single root project with the two members nested as direct
// dependencies, mirroring npm's whole-workspace-at-root behaviour.
func TestParsePnpmLockFileVite(t *testing.T) {
	projects, err := parsePnpmLockFile(viteFixtureDir(t), ".")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	root := projects[0]
	// Root's own devDependencies are preserved.
	assert.Contains(t, root.DevDependencies, "@types/node")
	assert.Contains(t, root.DevDependencies, "eslint")

	// Each workspace member is nested under the root as a direct dependency, with its
	// own deps (prod + dev merged) carried in the member node.
	require.Contains(t, root.Dependencies, "packages/vite")
	assert.Contains(t, root.Dependencies["packages/vite"].Dependencies, "rolldown")
	require.Contains(t, root.Dependencies, "packages/create-vite")
	assert.Contains(t, root.Dependencies["packages/create-vite"].Dependencies, "cross-spawn")
}

// TestParsePnpmLockFileMemberScope verifies that scoping to a single member importer
// returns only that member's dependencies (not the root's or other members'), used when
// `jf ca --working-dirs=<member>` targets one workspace package.
func TestParsePnpmLockFileMemberScope(t *testing.T) {
	projects, err := parsePnpmLockFile(viteFixtureDir(t), "packages/vite")
	require.NoError(t, err)
	require.Len(t, projects, 1)

	member := projects[0]
	// Only the member's own dependency is present.
	require.Contains(t, member.Dependencies, "rolldown")
	// The root's and sibling member's deps must NOT leak into the scoped result.
	assert.NotContains(t, member.Dependencies, "eslint")
	assert.NotContains(t, member.DevDependencies, "eslint")
	assert.NotContains(t, member.Dependencies, "cross-spawn")

	// An unknown importer is reported clearly rather than silently returning everything.
	_, err = parsePnpmLockFile(viteFixtureDir(t), "packages/does-not-exist")
	assert.Error(t, err)
}

// TestSplitPnpmRef checks peer-suffix stripping and scoped name handling.
func TestSplitPnpmRef(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"1.0.1", "", "1.0.1"},
		{"2.0.0(@peer/dep@1.0.0)", "", "2.0.0"},
		{"@scope/pkg@2.0.0(@peer@1.0)", "@scope/pkg", "2.0.0"},
		{"xml@1.0.1", "xml", "1.0.1"},
	}
	for _, tc := range tests {
		name, version := splitPnpmRef(tc.input)
		assert.Equal(t, tc.wantName, name, "name for %q", tc.input)
		assert.Equal(t, tc.wantVersion, version, "version for %q", tc.input)
	}
}

// TestValidateLockfileVersion ensures only lockfileVersion 9.0+ (the 'snapshots'
// format this parser understands) is accepted, and older formats are rejected
// rather than silently yielding an incomplete dependency tree.
func TestValidateLockfileVersion(t *testing.T) {
	// Accepted: 9.0 and later (pnpm 9/10 'snapshots' format).
	assert.NoError(t, validateLockfileVersion("9.0"))
	assert.NoError(t, validateLockfileVersion("'9.0'"))
	assert.NoError(t, validateLockfileVersion("10.0"))
	// Rejected: 5.x–8.x use a differently-shaped 'packages' block.
	assert.Error(t, validateLockfileVersion("5.4"))
	assert.Error(t, validateLockfileVersion("6.0"))
	assert.Error(t, validateLockfileVersion("'6.0'"))
	assert.Error(t, validateLockfileVersion("8.0"))
	// Rejected: missing or unparsable.
	assert.Error(t, validateLockfileVersion(""))
	assert.Error(t, validateLockfileVersion("abc"))
}

// TestBuildSnapshotKey covers plain, scoped, and aliased refs. Aliased cases mirror
// real pnpm 10 output: the alias target ref is itself the key and must be used as-is.
func TestBuildSnapshotKey(t *testing.T) {
	assert.Equal(t, "xml@1.0.1", buildSnapshotKey("xml", "1.0.1"))
	assert.Equal(t, "@scope/pkg@2.0.0", buildSnapshotKey("@scope/pkg", "2.0.0"))
	assert.Equal(t, "@scope/pkg@2.0.0(@peer/dep@1.0.0)", buildSnapshotKey("@scope/pkg", "2.0.0(@peer/dep@1.0.0)"))
	assert.Equal(t, "transitive-a@1.2.3", buildSnapshotKey("transitive-a", "1.2.3"))
	// Aliased scoped target: "my-babel": "npm:@babel/code-frame@^7".
	assert.Equal(t, "@babel/code-frame@7.29.7", buildSnapshotKey("my-babel", "@babel/code-frame@7.29.7"))
	// Aliased unscoped target: "my-lodash": "npm:lodash.merge@^4".
	assert.Equal(t, "lodash.merge@4.6.2", buildSnapshotKey("my-lodash", "lodash.merge@4.6.2"))
	assert.Equal(t, "@babel/code-frame@7.29.7(react@18.0.0)", buildSnapshotKey("my-babel", "@babel/code-frame@7.29.7(react@18.0.0)"))
}

// TestSpecifiersDiffer verifies bidirectional specifier comparison: added, removed,
// and changed deps all count as drift, while a matching set does not.
func TestSpecifiersDiffer(t *testing.T) {
	lock := map[string]pnpmLockDep{"xml": {Specifier: "1.0.1"}, "json": {Specifier: "9.0.6"}}

	assert.False(t, specifiersDiffer(map[string]string{"xml": "1.0.1", "json": "9.0.6"}, lock), "identical sets must not drift")
	assert.True(t, specifiersDiffer(map[string]string{"xml": "2.0.0", "json": "9.0.6"}, lock), "changed specifier must drift")
	assert.True(t, specifiersDiffer(map[string]string{"xml": "1.0.1"}, lock), "removed dep (lock has extra) must drift")
	assert.True(t, specifiersDiffer(map[string]string{"xml": "1.0.1", "json": "9.0.6", "extra": "1.0.0"}, lock), "added dep must drift")
	assert.True(t, specifiersDiffer(map[string]string{"xml": "1.0.1", "other": "9.0.6"}, lock), "same count, renamed dep must drift")
	assert.False(t, specifiersDiffer(nil, nil), "both empty must not drift")
}

// TestLockfileSpecifiersDrift exercises the file-level drift check on the directory's
// own lockfile ("." importer), including the removed-dependency case.
func TestLockfileSpecifiersDrift(t *testing.T) {
	writeProject := func(t *testing.T, pkgJSON, lock string) (dir, lockPath string) {
		t.Helper()
		dir = t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644))
		lockPath = filepath.Join(dir, "pnpm-lock.yaml")
		require.NoError(t, os.WriteFile(lockPath, []byte(lock), 0o644))
		return dir, lockPath
	}

	t.Run("in sync — no drift", func(t *testing.T) {
		dir, lockPath := writeProject(t,
			`{"dependencies":{"xml":"1.0.1"}}`,
			"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      xml:\n        specifier: 1.0.1\n        version: 1.0.1\nsnapshots: {}\n")
		assert.False(t, lockfileSpecifiersDrift(dir, lockPath))
	})

	t.Run("removed dep still in lockfile — drift", func(t *testing.T) {
		dir, lockPath := writeProject(t,
			`{"dependencies":{"xml":"1.0.1"}}`,
			"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      xml:\n        specifier: 1.0.1\n        version: 1.0.1\n      json:\n        specifier: 9.0.6\n        version: 9.0.6\nsnapshots: {}\n")
		assert.True(t, lockfileSpecifiersDrift(dir, lockPath))
	})

	t.Run("added dep not yet in lockfile — drift", func(t *testing.T) {
		dir, lockPath := writeProject(t,
			`{"dependencies":{"xml":"1.0.1","json":"9.0.6"}}`,
			"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      xml:\n        specifier: 1.0.1\n        version: 1.0.1\nsnapshots: {}\n")
		assert.True(t, lockfileSpecifiersDrift(dir, lockPath))
	})

	t.Run("changed specifier — drift", func(t *testing.T) {
		dir, lockPath := writeProject(t,
			`{"dependencies":{"xml":"2.0.0"}}`,
			"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      xml:\n        specifier: 1.0.1\n        version: 1.0.1\nsnapshots: {}\n")
		assert.True(t, lockfileSpecifiersDrift(dir, lockPath))
	})

	t.Run("added optional dep not yet in lockfile — drift", func(t *testing.T) {
		dir, lockPath := writeProject(t,
			`{"dependencies":{"xml":"1.0.1"},"optionalDependencies":{"fsevents":"^2.3.3"}}`,
			"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      xml:\n        specifier: 1.0.1\n        version: 1.0.1\nsnapshots: {}\n")
		assert.True(t, lockfileSpecifiersDrift(dir, lockPath))
	})

	t.Run("read error returns false", func(t *testing.T) {
		assert.False(t, lockfileSpecifiersDrift(t.TempDir(), filepath.Join(t.TempDir(), "missing.yaml")))
	})
}
