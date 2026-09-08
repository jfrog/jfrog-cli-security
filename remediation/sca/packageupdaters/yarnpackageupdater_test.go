package packageupdaters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindYarnLockfileRoot(t *testing.T) {
	integration.InitUnitTest(t)

	t.Run("root project - marker next to descriptor", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, yarnLockFileName), []byte(""), 0644))

		found, err := FindYarnLockfileRoot(root)
		require.NoError(t, err)
		assert.Equal(t, root, found)
	})

	t.Run("workspace member - marker at an ancestor", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, yarnLockFileName), []byte(""), 0644))
		memberDir := filepath.Join(root, "packages", "member-a")
		require.NoError(t, os.MkdirAll(memberDir, 0755))

		found, err := FindYarnLockfileRoot(memberDir)
		require.NoError(t, err)
		assert.Equal(t, root, found)
	})

	t.Run("no marker anywhere up to the filesystem root", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		_, err := FindYarnLockfileRoot(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), yarnLockFileName)
	})

	t.Run("alternate markers are also recognized", func(t *testing.T) {
		t.Parallel()
		for _, marker := range []string{".yarnrc.yml", ".yarnrc", ".yarn"} {
			t.Run(marker, func(t *testing.T) {
				t.Parallel()
				root := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(root, marker), []byte(""), 0644))

				found, err := FindYarnLockfileRoot(root)
				require.NoError(t, err)
				assert.Equal(t, root, found)
			})
		}
	})
}

func TestYarnLockRegenerationEnv(t *testing.T) {
	integration.InitUnitTest(t)
	t.Parallel()
	yarn := &YarnPackageUpdater{}
	env := EnvWithCorepackIntegrityWorkaround(yarn.BuildEnvWithOverrides(YarnInstallEnvOverrides))
	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	assert.Equal(t, "false", envMap[yarnEnableImmutableInstallsEnv])
	assert.Equal(t, "0", envMap["COREPACK_INTEGRITY_KEYS"])
}

func TestYarnUnsupportedVersionMessage(t *testing.T) {
	integration.InitUnitTest(t)
	t.Parallel()
	err := &ErrUnsupportedFix{
		PackageName:  "lodash",
		FixedVersion: "4.17.21",
		ErrorType:    UnsupportedFixReason,
		Reason:       "yarn 1.22.19 has no lockfile-only install mode (requires yarn >= 3.0.0)",
	}
	assert.Contains(t, err.Error(), "lodash")
	assert.Contains(t, err.Error(), "4.17.21")
	assert.Contains(t, err.Error(), "requires yarn >= 3.0.0")
}
