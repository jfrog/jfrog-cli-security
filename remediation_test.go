package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/remediation/sca/packageupdaters"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	testutils "github.com/jfrog/jfrog-cli-security/tests/utils"
	integrationUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// remediationProjectDir returns the path to a remediation test project under
// tests/testdata/projects/package-managers/<tech>/<subdir>.
func remediationProjectDir(tech, subdir string) string {
	return filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers", tech, subdir)
}

// newFixDetails builds a FixDetails value for use in remediation integration tests.
func newFixDetails(tech techutils.Technology, pkg, currentVersion, fixedVersion string, isDirect bool, evidencePaths ...string) *packageupdaters.FixDetails {
	var evidences []formats.Location
	for _, p := range evidencePaths {
		if p != "" {
			evidences = append(evidences, formats.Location{File: p})
		}
	}
	return &packageupdaters.FixDetails{
		Technology:                tech,
		ImpactedDependencyName:    pkg,
		ImpactedDependencyVersion: currentVersion,
		SuggestedFixedVersion:     fixedVersion,
		IsDirectDependency:        isDirect,
		Components: []formats.ComponentRow{
			{
				Name:      pkg,
				Version:   currentVersion,
				Evidences: evidences,
			},
		},
	}
}

// TestRemediationNpm verifies that the npm package updater applies a direct-dependency fix to
// package.json and regenerates package-lock.json.
func TestRemediationNpm(t *testing.T) {
	integrationUtils.InitRemediationTest(t)

	tmpDir, cleanup := testutils.CreateTestProjectEnvAndChdir(t, remediationProjectDir("npm", "remediation"))
	defer cleanup()
	_ = tmpDir

	fix := newFixDetails(techutils.Npm, "minimist", "1.2.5", "1.2.6", true, "package.json", "package-lock.json")
	updater, supported := packageupdaters.GetCompatiblePackageUpdater(fix)
	require.True(t, supported)

	lockBefore, err := os.ReadFile("package-lock.json")
	require.NoError(t, err)

	require.NoError(t, updater.UpdateDependency(fix))

	descriptor, err := os.ReadFile("package.json")
	require.NoError(t, err)
	assert.Contains(t, string(descriptor), "1.2.6", "package.json should contain the fixed version")

	lockAfter, err := os.ReadFile("package-lock.json")
	require.NoError(t, err)
	assert.NotEqual(t, lockBefore, lockAfter, "package-lock.json should be regenerated")
}

// TestRemediationMaven verifies that the maven package updater updates the pom.xml version.
func TestRemediationMaven(t *testing.T) {
	integrationUtils.InitRemediationTest(t)

	_, cleanup := testutils.CreateTestProjectEnvAndChdir(t, remediationProjectDir("maven", "remediation"))
	defer cleanup()

	fix := newFixDetails(techutils.Maven, "commons-io:commons-io", "", "2.7", true, filepath.Join("multi1", "pom.xml"))
	updater, supported := packageupdaters.GetCompatiblePackageUpdater(fix)
	require.True(t, supported)

	require.NoError(t, updater.UpdateDependency(fix))

	pom, err := os.ReadFile(filepath.Join("multi1", "pom.xml"))
	require.NoError(t, err)
	assert.Contains(t, string(pom), "2.7", "pom.xml should contain the fixed version")
}

// TestRemediationGo verifies that the go package updater updates go.mod and regenerates go.sum.
func TestRemediationGo(t *testing.T) {
	integrationUtils.InitRemediationTest(t)

	tmpDir, cleanup := testutils.CreateTestProjectEnvAndChdir(t, remediationProjectDir("go", "remediation"))
	defer cleanup()

	// The go test-data files are stored with a .txt suffix to avoid Go toolchain interference.
	for _, txtFile := range []string{"go.mod.txt", "go.sum.txt", "main.go.txt"} {
		target := strings.TrimSuffix(filepath.Join(tmpDir, txtFile), ".txt")
		require.NoError(t, os.Rename(filepath.Join(tmpDir, txtFile), target))
	}

	fix := newFixDetails(techutils.Go, "golang.org/x/crypto", "", "0.0.0-20201216223049-8b5274cf687f", false, "go.mod")
	updater, supported := packageupdaters.GetCompatiblePackageUpdater(fix)
	require.True(t, supported)

	goSumBefore, err := os.ReadFile("go.sum")
	require.NoError(t, err)

	require.NoError(t, updater.UpdateDependency(fix))

	goMod, err := os.ReadFile("go.mod")
	require.NoError(t, err)
	assert.Contains(t, string(goMod), "0.0.0-20201216223049-8b5274cf687f", "go.mod should contain the fixed version")

	goSumAfter, err := os.ReadFile("go.sum")
	require.NoError(t, err)
	assert.NotEqual(t, goSumBefore, goSumAfter, "go.sum should be regenerated")
}

// TestRemediationUnsupportedIndirect verifies that indirect dependency fix attempts return
// ErrUnsupportedFix for package managers that do not support it.
func TestRemediationUnsupportedIndirect(t *testing.T) {
	integrationUtils.InitRemediationTest(t)

	// Go supports indirect updates via `go get` and does not return ErrUnsupportedFix for indirect deps.
	for _, tech := range []techutils.Technology{techutils.Npm, techutils.Maven} {
		t.Run(tech.String(), func(t *testing.T) {
			fix := newFixDetails(tech, "some-package", "1.0.0", "1.0.1", false)
			updater, supported := packageupdaters.GetCompatiblePackageUpdater(fix)
			if !supported {
				// If not supported at factory level, that is acceptable.
				return
			}
			err := updater.UpdateDependency(fix)
			require.Error(t, err)
			var unsupported *packageupdaters.ErrUnsupportedFix
			assert.ErrorAs(t, err, &unsupported, "expected ErrUnsupportedFix for indirect dependency")
		})
	}
}

// TestRemediationNpmRollback verifies that the npm package updater rolls back package.json
// when npm install fails (e.g. invalid dependency graph in the rollback test project).
func TestRemediationNpmRollback(t *testing.T) {
	integrationUtils.InitRemediationTest(t)

	_, cleanup := testutils.CreateTestProjectEnvAndChdir(t, remediationProjectDir("npm", "remediation-rollback"))
	defer cleanup()

	descriptorBefore, err := os.ReadFile("package.json")
	require.NoError(t, err)

	fix := newFixDetails(techutils.Npm, "minimist", "1.2.5", "1.2.6", true, "package.json", "package-lock.json")
	updater, supported := packageupdaters.GetCompatiblePackageUpdater(fix)
	require.True(t, supported)

	err = updater.UpdateDependency(fix)
	require.Error(t, err, "expected an error from the rollback project")

	descriptorAfter, err := os.ReadFile("package.json")
	require.NoError(t, err)
	assert.Equal(t, descriptorBefore, descriptorAfter, "package.json should be rolled back to its original state")
}
