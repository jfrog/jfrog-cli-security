package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePythonSource_Literals(t *testing.T) {
	src := `
from transformers import AutoModel
model = AutoModel.from_pretrained("mcpotato/42-eicar-street", revision="main")
`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "mcpotato/42-eicar-street", disc[0].RepoID)
	assert.Equal(t, "main", disc[0].Revision)
	assert.False(t, disc[0].RevisionDefaulted)
	assert.Equal(t, RepoTypeModel, disc[0].RepoType)
	assert.Empty(t, unres)
}

func TestParsePythonSource_RevisionDefaulted(t *testing.T) {
	src := `snapshot_download(repo_id="bert-base-uncased")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "bert-base-uncased", disc[0].RepoID)
	assert.Equal(t, DefaultRevision, disc[0].Revision)
	assert.True(t, disc[0].RevisionDefaulted)
	assert.Empty(t, unres)
}

func TestParsePythonSource_Dataset(t *testing.T) {
	src := `from datasets import load_dataset
ds = load_dataset("squad", revision="1.0.0")`
	disc, unres := ParsePythonSource(src, "train.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "squad", disc[0].RepoID)
	assert.Equal(t, "1.0.0", disc[0].Revision)
	assert.Equal(t, RepoTypeDataset, disc[0].RepoType)
	assert.Empty(t, unres)
}

func TestParsePythonSource_SnapshotDownloadWithRepoType(t *testing.T) {
	src := `snapshot_download(repo_id="org/ds", revision="v2", repo_type="dataset")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, RepoTypeDataset, disc[0].RepoType)
	assert.Equal(t, "v2", disc[0].Revision)
	assert.Empty(t, unres)
}

// TestParsePythonSource_ApostropheInComment guards against a regression where an
// apostrophe inside a '#' comment (e.g. "tab's") was treated as an open string
// literal in countParenDepthChange, leaving paren depth stuck and gluing every
// following statement onto the comment line — which silently dropped real calls.
func TestParsePythonSource_ApostropheInComment(t *testing.T) {
	src := `from huggingface_hub import snapshot_download

# Whole-repo download (matches the "Resolve" tab's snapshot_download example).
LLAMA = snapshot_download(repo_id="meta-llama/Llama-2-7b-hf", revision="main")

# A reference we EXPECT curation to block (it's malicious).
UNSAFE = snapshot_download(repo_id="mcpotato/42-eicar-street", revision="8fb61c4d511e9aaff0ea55396a124aa292830efc")
`
	disc, unres := ParsePythonSource(src, "app.py", nil)
	require.Len(t, disc, 2)
	assert.Equal(t, "meta-llama/Llama-2-7b-hf", disc[0].RepoID)
	assert.Equal(t, "main", disc[0].Revision)
	assert.Equal(t, "mcpotato/42-eicar-street", disc[1].RepoID)
	assert.Equal(t, "8fb61c4d511e9aaff0ea55396a124aa292830efc", disc[1].Revision)
	assert.Empty(t, unres)
}

func TestParsePythonSource_ConstantTable(t *testing.T) {
	src := `
MODEL_ID = "org/my-model"
from transformers import AutoTokenizer
tok = AutoTokenizer.from_pretrained(MODEL_ID, revision="abc123")
`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "org/my-model", disc[0].RepoID)
	assert.Equal(t, "abc123", disc[0].Revision)
	assert.Empty(t, unres)
}

func TestParsePythonSource_DynamicRepoID(t *testing.T) {
	src := `from transformers import AutoModel
model = AutoModel.from_pretrained(args.model_name)`
	disc, unres := ParsePythonSource(src, "trainer.py", nil)
	assert.Empty(t, disc)
	require.Len(t, unres, 1)
	assert.Contains(t, unres[0].Reason, "non-literal")
	assert.Equal(t, "trainer.py", unres[0].Location.File)
}

func TestParsePythonSource_FStringRepoID(t *testing.T) {
	src := `from_pretrained(f"{ORG}/{name}")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	assert.Empty(t, disc)
	require.Len(t, unres, 1)
	assert.Equal(t, "f-string repo_id", unres[0].Reason)
}

func TestParsePythonSource_DynamicRevision(t *testing.T) {
	src := `snapshot_download(repo_id="org/model", revision=args.rev)`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "org/model", disc[0].RepoID)
	assert.True(t, disc[0].RevisionDynamic)
	assert.Equal(t, DefaultRevision, disc[0].Revision) // falls back to main
	assert.Empty(t, unres)
}

func TestParsePythonSource_HfHubDownload(t *testing.T) {
	src := `hf_hub_download(repo_id="org/model", filename="model.bin", revision="v1")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "org/model", disc[0].RepoID)
	assert.Equal(t, "v1", disc[0].Revision)
	assert.Empty(t, unres)
}

func TestParsePythonSource_MultipleModels(t *testing.T) {
	src := `
from transformers import AutoModel, AutoTokenizer
model = AutoModel.from_pretrained("org/model-a", revision="v1")
tok   = AutoTokenizer.from_pretrained("org/model-b")
`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	assert.Len(t, disc, 2)
	assert.Empty(t, unres)
}

func TestParsePythonSource_CommentsIgnored(t *testing.T) {
	src := `# from_pretrained("should-not-match")
model = AutoModel.from_pretrained("org/real-model")`
	disc, _ := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "org/real-model", disc[0].RepoID)
}

func TestBuildConstTable_Reassignment(t *testing.T) {
	src := `
MODEL = "first-value"
MODEL = "second-value"
`
	table := buildConstTable(src)
	_, exists := table["MODEL"]
	assert.False(t, exists, "reassigned name should be removed from constant table")
}

func TestBuildConstTable_SingleAssignment(t *testing.T) {
	src := `BASE = "org/model"`
	table := buildConstTable(src)
	assert.Equal(t, "org/model", table["BASE"])
}
