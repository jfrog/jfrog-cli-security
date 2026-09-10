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

		found, err := findYarnLockfileRoot(root)
		require.NoError(t, err)
		assert.Equal(t, root, found)
	})

	t.Run("workspace member - marker at an ancestor", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, yarnLockFileName), []byte(""), 0644))
		memberDir := filepath.Join(root, "packages", "member-a")
		require.NoError(t, os.MkdirAll(memberDir, 0755))

		found, err := findYarnLockfileRoot(memberDir)
		require.NoError(t, err)
		assert.Equal(t, root, found)
	})

	t.Run("no marker anywhere up to the filesystem root", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		_, err := findYarnLockfileRoot(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), yarnLockFileName)
	})

	t.Run("other yarn markers alone are not sufficient", func(t *testing.T) {
		t.Parallel()
		for _, marker := range []string{".yarnrc.yml", ".yarnrc", ".yarn"} {
			t.Run(marker, func(t *testing.T) {
				t.Parallel()
				root := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(root, marker), []byte(""), 0644))

				_, err := findYarnLockfileRoot(root)
				require.Error(t, err)
			})
		}
	})

	t.Run("member's own non-lockfile marker does not stop the walk early", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, yarnLockFileName), []byte(""), 0644))
		memberDir := filepath.Join(root, "packages", "member-a")
		require.NoError(t, os.MkdirAll(memberDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(memberDir, ".yarnrc.yml"), []byte(""), 0644))

		found, err := findYarnLockfileRoot(memberDir)
		require.NoError(t, err)
		assert.Equal(t, root, found)
	})
}

func TestCleanupYarnInstallArtifacts(t *testing.T) {
	integration.InitUnitTest(t)

	t.Run("removes artifacts that did not exist before", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, yarnDirName), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, yarnDirName, yarnInstallStateFileName), []byte(""), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(root, yarnPnpFileName), []byte(""), 0644))

		cleanupYarnInstallArtifacts(root, yarnInstallArtifactSnapshot{})

		assert.NoFileExists(t, filepath.Join(root, yarnDirName, yarnInstallStateFileName))
		assert.NoFileExists(t, filepath.Join(root, yarnPnpFileName))
	})

	t.Run("leaves install-state.gz alone when it already existed before this install", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, yarnDirName), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, yarnDirName, yarnInstallStateFileName), []byte("pre-existing"), 0644))

		cleanupYarnInstallArtifacts(root, yarnInstallArtifactSnapshot{installStateExisted: true})

		assert.FileExists(t, filepath.Join(root, yarnDirName, yarnInstallStateFileName))
	})

	t.Run("leaves a pre-existing .pnp.cjs alone", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, yarnPnpFileName), []byte("pre-existing"), 0644))

		cleanupYarnInstallArtifacts(root, yarnInstallArtifactSnapshot{pnpCjsExisted: true})

		assert.FileExists(t, filepath.Join(root, yarnPnpFileName))
	})
}

func TestRestoreOptionalFile(t *testing.T) {
	integration.InitUnitTest(t)

	t.Run("restores original content when the file existed before", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "yarn.lock")
		require.NoError(t, os.WriteFile(path, []byte("partially-written-by-a-failed-install"), 0644))

		require.NoError(t, restoreOptionalFile(path, []byte("original content"), true))

		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "original content", string(content))
	})

	t.Run("removes a file that did not exist before", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "yarn.lock")
		require.NoError(t, os.WriteFile(path, []byte("newly-created-by-a-failed-install"), 0644))

		require.NoError(t, restoreOptionalFile(path, nil, false))

		assert.NoFileExists(t, path)
	})

	t.Run("removing a non-existent file is not an error", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "yarn.lock")
		require.NoError(t, restoreOptionalFile(path, nil, false))
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
