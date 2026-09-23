package packageupdaters

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

func TestPipPackageRegex(t *testing.T) {
	integration.InitUnitTest(t)
	var pipPackagesRegexTests = []pipPackageRegexTest{
		{"oslo.config", "oslo.config>=1.12.1,<1.13"},
		{"oslo.utils", "oslo.utils<5.0,>=4.0.0"},
		{"paramiko", "paramiko==2.7.2"},
		{"passlib", "passlib<=1.7.4"},
		{"PassLib", "passlib<=1.7.4"},
		{"prance", "prance>=0.9.0"},
		{"prompt-toolkit", "prompt-toolkit~=1.0.15"},
		{"pyinotify", "pyinotify>0.9.6"},
		{"pyjwt", "pyjwt>1.7.1"},
		{"PyJWT", "pyjwt>1.7.1"},
		{"urllib3", "urllib3 > 1.1.9, < 1.5.*"},
	}
	for _, pack := range pipPackagesRegexTests {
		re := regexp.MustCompile(PythonPackageRegexPrefix + "(" + pack.packageName + "|" + strings.ToLower(pack.packageName) + ")" + PythonPackageRegexSuffix)
		found := re.FindString(requirementsFile)
		assert.Equal(t, pack.expectedRequirement, strings.ToLower(found))
	}
}

// TestHandlePoetryPreservesRangeConstraintWhenItAdmitsFix guards the byte-identical
// acceptance criterion: when the declared range already admits the fix version, only
// poetry.lock should change - pyproject.toml must come back out exactly as it went in.
func TestHandlePoetryPreservesRangeConstraintWhenItAdmitsFix(t *testing.T) {
	integration.InitRemediationTest(t)
	cleanup := createTempDirAndChdir(t, "poetry", true, "range-admits-fix")
	defer cleanup()

	originalManifest, err := os.ReadFile("pyproject.toml")
	assert.NoError(t, err)

	updater := &PythonPackageUpdater{}
	err = updater.handlePoetry(createFixDetails(techutils.Poetry, "requests", "2.31.0", "2.32.4", true, "pyproject.toml"))
	assert.NoError(t, err)

	fixedManifest, err := os.ReadFile("pyproject.toml")
	assert.NoError(t, err)
	assert.Equal(t, string(originalManifest), string(fixedManifest), "pyproject.toml must stay byte-identical when the existing constraint already admits the fix version")

	lockedVersion, err := lockedPackageVersion("poetry.lock", "requests")
	assert.NoError(t, err)
	assert.Equal(t, "2.32.4", lockedVersion, "the lock must land on the fix version, not merely the newest version the range allows")
}

// TestHandlePoetryWidensConstraintWhenItDoesNotAdmitFix guards against the silent-revert
// failure mode: restoring a constraint that doesn't admit the fix version reverts the lock
// back to the old version while 'poetry check --lock' still exits 0. The fix must widen the
// constraint instead and verify the locked version directly, not trust that exit code.
func TestHandlePoetryWidensConstraintWhenItDoesNotAdmitFix(t *testing.T) {
	integration.InitRemediationTest(t)
	cleanup := createTempDirAndChdir(t, "poetry", true, "range-below-fix")
	defer cleanup()

	updater := &PythonPackageUpdater{}
	err := updater.handlePoetry(createFixDetails(techutils.Poetry, "jinja2", "2.11.3", "3.1.6", true, "pyproject.toml"))
	assert.NoError(t, err)

	lockedVersion, err := lockedPackageVersion("poetry.lock", "jinja2")
	assert.NoError(t, err)
	assert.Equal(t, "3.1.6", lockedVersion, "the original ^2.11 constraint doesn't admit 3.1.6 - the fix must widen it rather than silently reverting")
}

// TestHandlePoetryTargetsGroupDependencyWithoutDuplicating guards against the same class of
// bug 'poetry add' has: adding a dependency without --group duplicates it into the main
// [tool.poetry.dependencies] table while leaving the original group declaration untouched,
// corrupting the manifest with two conflicting constraints for the same package.
func TestHandlePoetryTargetsGroupDependencyWithoutDuplicating(t *testing.T) {
	integration.InitRemediationTest(t)
	cleanup := createTempDirAndChdir(t, "poetry", true, "group-dependency")
	defer cleanup()

	updater := &PythonPackageUpdater{}
	err := updater.handlePoetry(createFixDetails(techutils.Poetry, "requests", "2.31.0", "2.32.4", true, "pyproject.toml"))
	assert.NoError(t, err)

	manifest, err := os.ReadFile("pyproject.toml")
	assert.NoError(t, err)
	assert.NotContains(t, string(manifest), "[tool.poetry.dependencies]\npython = \"^3.10\"\nrequests", "must not duplicate the dependency into the main table")
	assert.Contains(t, string(manifest), "requests = \"^2.31\"", "the group declaration's constraint form is preserved since ^2.31 admits 2.32.4")

	lockedVersion, err := lockedPackageVersion("poetry.lock", "requests")
	assert.NoError(t, err)
	assert.Equal(t, "2.32.4", lockedVersion)
}

// TestHandleUvSubstringCollisionSafe guards against fixing "attrs" from also matching
// (and wrongly bumping) "cattrs", which shares "attrs" as a suffix.
func TestHandleUvSubstringCollisionSafe(t *testing.T) {
	integration.InitRemediationTest(t)
	cleanup := createTempDirAndChdir(t, "uv", true, "substring-collision")
	defer cleanup()

	updater := &PythonPackageUpdater{}
	err := updater.handleUv(createFixDetails(techutils.Uv, "attrs", "23.2.0", "24.1.0", true, ""))
	assert.NoError(t, err)

	content, readErr := os.ReadFile("pyproject.toml")
	assert.NoError(t, readErr)
	assert.Contains(t, string(content), `cattrs==23.2.3`, "unrelated package sharing a name suffix must be untouched")
	assert.Contains(t, string(content), `attrs==24.1.0`, "the actual impacted package must be fixed")
}

// TestHandleUvFixesAllDeclarations guards against fixing only the first of several
// declarations of the same package (e.g. in both [project].dependencies and a
// [dependency-groups] table), which would leave 'uv lock' unsatisfiable.
func TestHandleUvFixesAllDeclarations(t *testing.T) {
	integration.InitRemediationTest(t)
	cleanup := createTempDirAndChdir(t, "uv", true, "duplicate-declaration")
	defer cleanup()

	updater := &PythonPackageUpdater{}
	err := updater.handleUv(createFixDetails(techutils.Uv, "pyjwt", "1.7.1", "2.4.0", true, ""))
	assert.NoError(t, err)

	content, readErr := os.ReadFile("pyproject.toml")
	assert.NoError(t, readErr)
	assert.NotContains(t, string(content), "1.7.1", "no declaration should be left at the old version")
	assert.Equal(t, 2, strings.Count(string(content), "2.4.0"), "both declarations must be updated")
}
