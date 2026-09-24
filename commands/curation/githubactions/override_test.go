package githubactions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tarEntry is one entry of a test archive: a file with content, a directory, or a symlink.
type tarEntry struct {
	name     string
	content  string
	dir      bool
	linkname string
}

func buildTarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.content)), Typeflag: tar.TypeReg}
		switch {
		case e.dir:
			hdr = &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tar.TypeDir}
		case e.linkname != "":
			hdr = &tar.Header{Name: e.name, Linkname: e.linkname, Mode: 0o777, Typeflag: tar.TypeSymlink}
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if hdr.Typeflag == tar.TypeReg {
			_, err := tw.Write([]byte(e.content))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// actionArchive is a well-formed archive shaped like Artifactory's: one top-level directory.
func actionArchive(t *testing.T) []byte {
	t.Helper()
	return buildTarGz(t,
		tarEntry{name: "checkout-" + branchTip + "/", dir: true},
		tarEntry{name: "checkout-" + branchTip + "/action.yml", content: "name: curated\n"},
		tarEntry{name: "checkout-" + branchTip + "/dist/", dir: true},
		tarEntry{name: "checkout-" + branchTip + "/dist/index.js", content: "curated();\n"},
	)
}

// runnerCache lays out _actions/actions/checkout/<ref> holding stale content, with the runner's
// "<last ref segment>.completed" marker beside it, and returns the ref directory.
func runnerCache(t *testing.T, ref string) string {
	t.Helper()
	actionDir := filepath.Join(t.TempDir(), "_actions", "actions", "checkout", filepath.FromSlash(ref))
	require.NoError(t, os.MkdirAll(actionDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte("name: original\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "stale.js"), []byte("stale();\n"), 0o644))
	require.NoError(t, os.WriteFile(actionDir+watermarkSuffix, nil, 0o644))
	return actionDir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

// assertOriginalIntact checks a failed replacement left the runner's copy as it was.
func assertOriginalIntact(t *testing.T, actionDir string) {
	t.Helper()
	assert.Equal(t, "name: original\n", readFile(t, filepath.Join(actionDir, "action.yml")))
	assert.FileExists(t, filepath.Join(actionDir, "stale.js"))
	assert.FileExists(t, actionDir+watermarkSuffix)
	assertNoWorkDirLeft(t, actionDir)
}

func assertNoWorkDirLeft(t *testing.T, actionDir string) {
	t.Helper()
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(actionDir), overrideTempPattern))
	require.NoError(t, err)
	assert.Empty(t, leftovers, "ReplaceActionContent left its working directory behind")
}

func TestReplaceActionContent(t *testing.T) {
	tests := []struct {
		name string
		ref  string
	}{
		{name: "verify when the ref is a bare name then its directory is replaced", ref: "v4"},
		// The runner names the directory after the literal ref, so the prefixed form must be
		// written where the runner put it - never at the stripped short name.
		{name: "verify when the ref is fully qualified then the literal directory is replaced", ref: "refs/tags/v4"},
		{name: "verify when the ref is a slashed branch then the nested directory is replaced", ref: "releases/v4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionDir := runnerCache(t, tt.ref)

			err := ReplaceActionContent(actionDir, bytes.NewReader(actionArchive(t)))

			require.NoError(t, err)
			assert.Equal(t, "name: curated\n", readFile(t, filepath.Join(actionDir, "action.yml")))
			assert.Equal(t, "curated();\n", readFile(t, filepath.Join(actionDir, "dist", "index.js")))
			assert.NoFileExists(t, filepath.Join(actionDir, "stale.js"), "stale content from the replaced version survived")
			assert.NoDirExists(t, filepath.Join(actionDir, "checkout-"+branchTip), "the archive's top-level directory was not stripped")
			assert.FileExists(t, actionDir+watermarkSuffix, "the runner's .completed marker was removed")
			assertNoWorkDirLeft(t, actionDir)
		})
	}
}

func TestReplaceActionContentRejectsArchive(t *testing.T) {
	top := "checkout-" + branchTip + "/"
	// The hostile entry is surrounded by legitimate content on purpose. The archiver on its own
	// silently drops an escaping entry and extracts the rest, so an archive holding only the hostile
	// entry would come out empty and be refused as empty - passing even with the Zip Slip
	// inspection switched off. With real content beside it, only the inspection rejecting the whole
	// archive leaves the original in place.
	withLegitimateContent := func(hostile tarEntry) []tarEntry {
		return []tarEntry{
			{name: top, dir: true},
			{name: top + "action.yml", content: "name: hostile\n"},
			hostile,
			{name: top + "index.js", content: "hostile();\n"},
		}
	}
	tests := []struct {
		name    string
		archive func(t *testing.T) []byte
	}{
		{
			name: "verify when an entry escapes the destination then nothing is replaced",
			archive: func(t *testing.T) []byte {
				return buildTarGz(t, withLegitimateContent(tarEntry{name: top + "../../evil.txt", content: "x"})...)
			},
		},
		{
			name: "verify when a symlink points outside the destination then nothing is replaced",
			archive: func(t *testing.T) []byte {
				return buildTarGz(t, withLegitimateContent(tarEntry{name: top + "link", linkname: "../../../../etc"})...)
			},
		},
		{
			name: "verify when the archive holds only its top-level directory then nothing is replaced",
			archive: func(t *testing.T) []byte {
				return buildTarGz(t, tarEntry{name: top, dir: true})
			},
		},
		{
			name:    "verify when the body is not a gzip archive then nothing is replaced",
			archive: func(t *testing.T) []byte { return []byte(`{"errors":[{"status":500}]}`) },
		},
		{
			name: "verify when the archive is truncated then nothing is replaced",
			archive: func(t *testing.T) []byte {
				full := actionArchive(t)
				return full[:len(full)/2]
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionDir := runnerCache(t, "v4")

			err := ReplaceActionContent(actionDir, bytes.NewReader(tt.archive(t)))

			assert.Error(t, err)
			assertOriginalIntact(t, actionDir)
			assert.NoFileExists(t, filepath.Join(filepath.Dir(actionDir), "evil.txt"))
		})
	}
}

func TestReplaceActionContentMissingDirectory(t *testing.T) {
	t.Run("verify when the action directory does not exist then it errors without creating it", func(t *testing.T) {
		actionDir := filepath.Join(t.TempDir(), "absent")

		err := ReplaceActionContent(actionDir, bytes.NewReader(actionArchive(t)))

		assert.True(t, errors.Is(err, os.ErrNotExist), "ReplaceActionContent() error = %v, want os.ErrNotExist", err)
		assert.NoDirExists(t, actionDir)
	})
}

func TestReplaceActionContentRestoresOnFailedSwap(t *testing.T) {
	t.Run("verify when moving the new content in fails then the original is restored", func(t *testing.T) {
		actionDir := runnerCache(t, "v4")
		calls := 0
		rename = func(oldpath, newpath string) error {
			calls++
			if calls == 2 {
				return errors.New("injected rename failure")
			}
			return os.Rename(oldpath, newpath)
		}
		t.Cleanup(func() { rename = os.Rename })

		err := ReplaceActionContent(actionDir, bytes.NewReader(actionArchive(t)))

		assert.ErrorContains(t, err, "original restored")
		assertOriginalIntact(t, actionDir)
	})
}

func TestReplaceActionContentSymlinkedDirectory(t *testing.T) {
	t.Run("verify when the runner symlinked the action directory then the link is replaced and its target untouched", func(t *testing.T) {
		shared := filepath.Join(t.TempDir(), "archive-cache", "checkout")
		require.NoError(t, os.MkdirAll(shared, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(shared, "action.yml"), []byte("name: shared\n"), 0o644))
		actionDir := filepath.Join(t.TempDir(), "_actions", "actions", "checkout", "v4")
		require.NoError(t, os.MkdirAll(filepath.Dir(actionDir), 0o755))
		require.NoError(t, os.Symlink(shared, actionDir))

		err := ReplaceActionContent(actionDir, bytes.NewReader(actionArchive(t)))

		require.NoError(t, err)
		info, err := os.Lstat(actionDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir() && info.Mode()&os.ModeSymlink == 0, "action directory is still a symlink")
		assert.Equal(t, "name: curated\n", readFile(t, filepath.Join(actionDir, "action.yml")))
		assert.Equal(t, "name: shared\n", readFile(t, filepath.Join(shared, "action.yml")), "the shared archive cache was modified")
	})
}
