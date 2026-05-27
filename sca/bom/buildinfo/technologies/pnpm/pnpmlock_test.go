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
	projects, err := parsePnpmLockFile(dir)
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

	require.NoError(t, os.WriteFile(simpleLock, complexContent, 0644))
	t.Cleanup(func() { _ = os.WriteFile(simpleLock, origContent, 0644) })

	projects, err := parsePnpmLockFile(dir)
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

// TestValidateLockfileVersion ensures old lockfile versions are rejected and modern ones accepted.
func TestValidateLockfileVersion(t *testing.T) {
	assert.NoError(t, validateLockfileVersion("6.0"))
	assert.NoError(t, validateLockfileVersion("'6.0'"))
	assert.NoError(t, validateLockfileVersion("9.0"))
	assert.NoError(t, validateLockfileVersion("'9.0'"))
	assert.Error(t, validateLockfileVersion("5.4"))
	assert.Error(t, validateLockfileVersion(""))
}

// TestBuildSnapshotKey checks that scoped and non-scoped package references
// produce the correct snapshot lookup key.
func TestBuildSnapshotKey(t *testing.T) {
	// Plain version (most common in importers block).
	assert.Equal(t, "xml@1.0.1", buildSnapshotKey("xml", "1.0.1"))
	// Scoped package with plain version.
	assert.Equal(t, "@scope/pkg@2.0.0", buildSnapshotKey("@scope/pkg", "2.0.0"))
	// Scoped package with peer-dep suffix (common for peer-requiring packages).
	assert.Equal(t, "@scope/pkg@2.0.0(@peer/dep@1.0.0)", buildSnapshotKey("@scope/pkg", "2.0.0(@peer/dep@1.0.0)"))
	// Non-scoped package with peer-dep suffix from a snapshot's dependencies map.
	assert.Equal(t, "transitive-a@1.2.3", buildSnapshotKey("transitive-a", "1.2.3"))
}
