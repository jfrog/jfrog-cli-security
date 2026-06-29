package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanDir_BasicDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", `
from transformers import AutoModel
model = AutoModel.from_pretrained("org/model-a", revision="v1")
`)
	result, err := ScanDir(dir)
	require.NoError(t, err)
	require.Len(t, result.Discovered, 1)
	assert.Equal(t, "org/model-a", result.Discovered[0].RepoID)
	assert.Empty(t, result.Unresolved)
}

func TestScanDir_Dedup(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.py", `from_pretrained("org/model", revision="v1")`)
	writeFile(t, dir, "b.py", `from_pretrained("org/model", revision="v1")`)
	result, err := ScanDir(dir)
	require.NoError(t, err)
	assert.Len(t, result.Discovered, 1, "same model in two files should deduplicate")
	assert.Len(t, result.Discovered[0].Sources, 2, "both source locations should be recorded")
}

func TestScanDir_ExcludeVenv(t *testing.T) {
	dir := t.TempDir()
	venv := filepath.Join(dir, ".venv")
	require.NoError(t, os.MkdirAll(venv, 0755))
	writeFile(t, venv, "excluded.py", `from_pretrained("org/should-not-appear")`)
	writeFile(t, dir, "real.py", `from_pretrained("org/real-model")`)
	result, err := ScanDir(dir)
	require.NoError(t, err)
	require.Len(t, result.Discovered, 1)
	assert.Equal(t, "org/real-model", result.Discovered[0].RepoID)
}

func TestScanDir_UnresolvedWarning(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dynamic.py", `from_pretrained(args.model_name)`)
	result, err := ScanDir(dir)
	require.NoError(t, err)
	assert.Empty(t, result.Discovered)
	require.Len(t, result.Unresolved, 1)

	warn := FormatWarnings(result.Unresolved)
	assert.Contains(t, warn, "WARN:")
	assert.Contains(t, warn, "--hugging-face-model")
}

func TestScanDir_MixedResolved(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "mixed.py", `
from_pretrained("org/good-model", revision="v1")
from_pretrained(config.model_id)
snapshot_download(repo_id="org/dataset", repo_type="dataset")
`)
	result, err := ScanDir(dir)
	require.NoError(t, err)
	assert.Len(t, result.Discovered, 2)
	assert.Len(t, result.Unresolved, 1)
}

func TestFormatWarnings_Empty(t *testing.T) {
	assert.Equal(t, "", FormatWarnings(nil))
	assert.Equal(t, "", FormatWarnings([]UnresolvedSite{}))
}

func TestFormatWarnings_Content(t *testing.T) {
	sites := []UnresolvedSite{
		{Location: Location{File: "trainer.py", Line: 42}, Snippet: "from_pretrained(args.m)", Reason: "non-literal repo_id"},
	}
	out := FormatWarnings(sites)
	assert.True(t, strings.HasPrefix(out, "WARN:"))
	assert.Contains(t, out, "trainer.py:42")
	assert.Contains(t, out, "non-literal repo_id")
	assert.Contains(t, out, "--hugging-face-model")
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0644))
}
