package discovery

import (
	"os"
	"path/filepath"
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
	assert.Contains(t, warn, "could not be statically resolved")
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
	// Only the model lands in Discovered; the dataset is separated out.
	require.Len(t, result.Discovered, 1)
	assert.Equal(t, "org/good-model", result.Discovered[0].RepoID)
	require.Len(t, result.Datasets, 1)
	assert.Equal(t, "org/dataset", result.Datasets[0].RepoID)
	assert.Len(t, result.Unresolved, 1)
}

func TestScanDir_DatasetsNotAudited(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "data.py", `
from datasets import load_dataset
ds = load_dataset("squad", revision="1.0.0")
`)
	result, err := ScanDir(dir)
	require.NoError(t, err)
	assert.Empty(t, result.Discovered, "datasets must not be handed to the curation walker")
	require.Len(t, result.Datasets, 1)
	assert.Equal(t, "squad", result.Datasets[0].RepoID)
}

func TestFormatDatasetWarning_Empty(t *testing.T) {
	assert.Equal(t, "", FormatDatasetWarning(nil))
	assert.Equal(t, "", FormatDatasetWarning([]DiscoveredModel{}))
}

func TestFormatDatasetWarning_Content(t *testing.T) {
	datasets := []DiscoveredModel{
		{RepoID: "squad", Revision: "1.0.0", RepoType: RepoTypeDataset,
			Sources: []Location{{File: "data.py", Line: 3}}},
	}
	out := FormatDatasetWarning(datasets)
	assert.Contains(t, out, "1 Hugging Face dataset reference(s) found but NOT audited")
	assert.Contains(t, out, "curation does not currently cover datasets (Catalog limitation)")
	assert.Contains(t, out, "Only models are evaluated")
	assert.Contains(t, out, "data.py:3")
	assert.Contains(t, out, "squad")
}

func TestScanDir_SkipsUnparsableFileAndWarns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "real.py", `from_pretrained("org/real-model")`)
	writeFile(t, dir, "bad.ipynb", `{not valid json`)

	result, err := ScanDir(dir)
	require.NoError(t, err, "a single unparsable file must not fail the whole scan")

	// The good file is still fully scanned despite the bad one.
	require.Len(t, result.Discovered, 1)
	assert.Equal(t, "org/real-model", result.Discovered[0].RepoID)

	// The bad file is recorded as skipped rather than silently dropped.
	require.Len(t, result.Skipped, 1)
	assert.Equal(t, "bad.ipynb", result.Skipped[0].Path)
	assert.NotEmpty(t, result.Skipped[0].Err)

	warn := FormatSkippedFilesWarning(result.Skipped)
	assert.Contains(t, warn, "1 source file(s) could not be scanned")
	assert.Contains(t, warn, "PARTIAL")
	assert.Contains(t, warn, "bad.ipynb")
}

func TestFormatSkippedFilesWarning_Empty(t *testing.T) {
	assert.Equal(t, "", FormatSkippedFilesWarning(nil))
	assert.Equal(t, "", FormatSkippedFilesWarning([]SkippedFile{}))
}

func TestScanDir_ExcludeDist(t *testing.T) {
	dir := t.TempDir()
	dist := filepath.Join(dir, "dist")
	require.NoError(t, os.MkdirAll(dist, 0755))
	writeFile(t, dist, "excluded.py", `from_pretrained("org/should-not-appear")`)
	writeFile(t, dir, "real.py", `from_pretrained("org/real-model")`)
	result, err := ScanDir(dir)
	require.NoError(t, err)
	require.Len(t, result.Discovered, 1)
	assert.Equal(t, "org/real-model", result.Discovered[0].RepoID)
}

func TestScanDir_ExcludeIpynbCheckpoints(t *testing.T) {
	dir := t.TempDir()
	checkpoints := filepath.Join(dir, ".ipynb_checkpoints")
	require.NoError(t, os.MkdirAll(checkpoints, 0755))
	writeFile(t, checkpoints, "stale-checkpoint.ipynb", `{"cells":[]}`)
	writeFile(t, dir, "real.py", `from_pretrained("org/real-model")`)
	result, err := ScanDir(dir)
	require.NoError(t, err)
	require.Len(t, result.Discovered, 1)
	assert.Equal(t, "org/real-model", result.Discovered[0].RepoID)
	assert.Empty(t, result.Skipped, "checkpoint dir should be skipped by the walk, not reported as unreadable")
}

func TestScanDir_SkipsOversizedFileAndWarns(t *testing.T) {
	dir := t.TempDir()
	huge := make([]byte, maxScannableFileSize+1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "huge.py"), huge, 0644))
	writeFile(t, dir, "real.py", `from_pretrained("org/real-model")`)

	result, err := ScanDir(dir)
	require.NoError(t, err, "an oversized file must not fail the whole scan")

	require.Len(t, result.Discovered, 1)
	assert.Equal(t, "org/real-model", result.Discovered[0].RepoID)

	require.Len(t, result.Skipped, 1)
	assert.Equal(t, "huge.py", result.Skipped[0].Path)
	assert.Contains(t, result.Skipped[0].Err, "exceeds")
}

func TestScanDir_IgnoresUnsupportedExtensions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", `from_pretrained("org/should-not-appear")`)
	writeFile(t, dir, "requirements.txt", `transformers==4.0.0`)
	writeFile(t, dir, "real.py", `from_pretrained("org/real-model")`)

	result, err := ScanDir(dir)
	require.NoError(t, err)
	require.Len(t, result.Discovered, 1)
	assert.Equal(t, "org/real-model", result.Discovered[0].RepoID)
	assert.Empty(t, result.Skipped, "unsupported extensions are ignored, not reported as skipped/unreadable")
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
	assert.Contains(t, out, "could not be statically resolved")
	assert.Contains(t, out, "trainer.py:42")
	assert.Contains(t, out, "non-literal repo_id")
	assert.Contains(t, out, "--hugging-face-model")
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0644))
}
