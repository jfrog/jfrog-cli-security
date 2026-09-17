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
