package discovery

import (
	"os"
	"path/filepath"
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

func TestParsePythonSource_LoadDatasetPathKwarg(t *testing.T) {
	src := `load_dataset(path="squad", revision="1.0.0")`
	disc, unres := ParsePythonSource(src, "train.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "squad", disc[0].RepoID)
	assert.Equal(t, "1.0.0", disc[0].Revision)
	assert.Equal(t, RepoTypeDataset, disc[0].RepoType)
	assert.Empty(t, unres)
}

func TestParsePythonSource_TripleQuotedString(t *testing.T) {
	src := `load_dataset("""squad""", revision="1.0.0")`
	disc, unres := ParsePythonSource(src, "train.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "squad", disc[0].RepoID)
	assert.Equal(t, "1.0.0", disc[0].Revision)
	assert.Empty(t, unres)
}

func Test_unquotePythonString(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{`"squad"`, "squad", true},
		{`"""squad"""`, "squad", true},
		{`'''squad'''`, "squad", true},
		{"args.model", "", false},
	}
	for _, tt := range tests {
		got, ok := unquotePythonString(tt.in)
		assert.Equal(t, tt.ok, ok, "input %q", tt.in)
		if ok {
			assert.Equal(t, tt.want, got, "input %q", tt.in)
		}
	}
}

func TestParsePythonSource_SnapshotDownloadWithRepoType(t *testing.T) {
	src := `snapshot_download(repo_id="org/ds", revision="v2", repo_type="dataset")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, RepoTypeDataset, disc[0].RepoType)
	assert.Equal(t, "v2", disc[0].Revision)
	assert.Empty(t, unres)
}

func TestParsePythonSource_SnapshotDownloadWithExplicitModelRepoType(t *testing.T) {
	src := `snapshot_download(repo_id="org/model", repo_type="model")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, RepoTypeModel, disc[0].RepoType)
	assert.Empty(t, unres)
}

// TestParsePythonSource_DynamicRepoTypeIsUnresolved: a runtime repo_type value
// must not be silently emitted under the default (model) type.
func TestParsePythonSource_DynamicRepoTypeIsUnresolved(t *testing.T) {
	discovered, unresolved := ParsePythonSource(
		`snapshot_download(repo_id="org/data", repo_type=args.repo_type)`,
		"app.py", nil)
	assert.Empty(t, discovered)
	require.Len(t, unresolved, 1)
	assert.Equal(t, "non-literal repo_type", unresolved[0].Reason)
}

// TestParsePythonSource_UnsupportedRepoTypeIsUnresolved: "space" is a real HF
// repo_type this scanner doesn't model, so it must be flagged as unresolved.
func TestParsePythonSource_UnsupportedRepoTypeIsUnresolved(t *testing.T) {
	src := `snapshot_download(repo_id="org/my-space", repo_type="space")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	assert.Empty(t, disc)
	require.Len(t, unres, 1)
	assert.Equal(t, "unsupported repo_type", unres[0].Reason)
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

// TestParsePythonSource_SnippetRedactsArgumentValues verifies that the warning
// snippet for an unresolved reference keeps bare variable references (useful for
// identifying the call site) but never contains a quoted literal, since it is
// printed to CI logs and a literal may embed a real secret.
func TestParsePythonSource_SnippetRedactsArgumentValues(t *testing.T) {
	src := `from_pretrained(args.model_name, token="hf_abcdef123456")`
	disc, unres := ParsePythonSource(src, "trainer.py", nil)
	assert.Empty(t, disc)
	require.Len(t, unres, 1)
	assert.NotContains(t, unres[0].Snippet, "hf_abcdef123456")
	assert.Equal(t, "args.model_name, token=<redacted>", unres[0].Snippet)
}

// TestParsePythonSource_SnippetRedactsNestedLiteral verifies that a literal nested
// inside a call expression (not just a direct keyword value) is still redacted.
func TestParsePythonSource_SnippetRedactsNestedLiteral(t *testing.T) {
	src := `from_pretrained(args.model_name, token=get_token("hf_abcdef123456"))`
	disc, unres := ParsePythonSource(src, "trainer.py", nil)
	assert.Empty(t, disc)
	require.Len(t, unres, 1)
	assert.NotContains(t, unres[0].Snippet, "hf_abcdef123456")
	assert.Equal(t, "args.model_name, token=<redacted>", unres[0].Snippet)
}

func TestParsePythonSource_FStringRepoID(t *testing.T) {
	src := `from_pretrained(f"{ORG}/{name}")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	assert.Empty(t, disc)
	require.Len(t, unres, 1)
	assert.Equal(t, "f-string repo_id", unres[0].Reason)
}

func TestParsePythonSource_LocalPathAdvisory(t *testing.T) {
	cases := []struct {
		name string
		arg  string
	}{
		{"absolute", `"/opt/models/gpt2"`},
		{"relative-dot", `"./models/gpt2"`},
		{"relative-dotdot", `"../models/gpt2"`},
		{"home", `"~/models/gpt2"`},
		{"windows", `"C:\\models\\gpt2"`},
		{"multi-slash", `"models/foo/gpt2"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "from transformers import AutoModel\nmodel = AutoModel.from_pretrained(" + tc.arg + ")"
			disc, unres := ParsePythonSource(src, "app.py", nil)
			assert.Empty(t, disc, "local path must not be audited as a repo id")
			require.Len(t, unres, 1)
			assert.Equal(t, "local filesystem path", unres[0].Reason)
		})
	}
}

func TestParsePythonSource_RepoIDNotMistakenForLocalPath(t *testing.T) {
	src := `from transformers import AutoModel
model = AutoModel.from_pretrained("openai-community/gpt2")`
	disc, unres := ParsePythonSource(src, "app.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "openai-community/gpt2", disc[0].RepoID)
	assert.Empty(t, unres)
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

// TestBuildConstTable_ReassignmentViaNonLiteralExpression verifies that a name
// reassigned via a non-literal expression (e.g. an env-var override) is also
// removed from the constant table, not just a second bare-literal reassignment.
func TestBuildConstTable_ReassignmentViaNonLiteralExpression(t *testing.T) {
	src := `
MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_ID = os.getenv("HF_MODEL_ID", MODEL_ID)
`
	table := buildConstTable(src)
	_, exists := table["MODEL_ID"]
	assert.False(t, exists, "reassignment via a non-literal expression should invalidate the constant")
}

// TestBuildConstTable_ReassignmentViaCompoundAssignment verifies that a name
// mutated via a compound assignment (e.g. "+=") is also removed from the
// constant table, not just a plain "NAME = ..." reassignment.
func TestBuildConstTable_ReassignmentViaCompoundAssignment(t *testing.T) {
	src := `
MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_ID += "-v2"
`
	table := buildConstTable(src)
	_, exists := table["MODEL_ID"]
	assert.False(t, exists, "reassignment via a compound assignment should invalidate the constant")
}

// TestBuildConstTable_ReassignmentViaChainedAssignment verifies that a name
// reassigned as the middle/right target of a chained assignment (e.g.
// "MODEL_ID = FALLBACK_ID = ..."), not just as the line-leading target, is
// also removed from the constant table.
func TestBuildConstTable_ReassignmentViaChainedAssignment(t *testing.T) {
	src := `
FALLBACK_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_ID = FALLBACK_ID = "org/other-model"
`
	table := buildConstTable(src)
	_, exists := table["FALLBACK_ID"]
	assert.False(t, exists, "reassignment as a chained-assignment target should invalidate the constant")
}

// TestBuildConstTable_ChainedComparisonNotMistakenForAssignment guards against
// a false positive: a chained comparison ("a == b == c") must not be mistaken
// for a chained assignment reassigning "b".
func TestBuildConstTable_ChainedComparisonNotMistakenForAssignment(t *testing.T) {
	src := `
MODEL_ID = "org/my-model"
if MODEL_ID == FALLBACK == "unused":
    pass
`
	table := buildConstTable(src)
	val, exists := table["MODEL_ID"]
	assert.True(t, exists, "chained comparison must not be mistaken for chained assignment")
	assert.Equal(t, "org/my-model", val)
}

// TestParsePythonSource_EnvOverrideInvalidatesLiteral is the reviewer's regression
// case: a common deployment pattern keeps a checked-in fallback model but overrides
// it via an environment variable. The runtime model must be reported as unresolved
// instead of auditing the stale fallback literal.
func TestParsePythonSource_EnvOverrideInvalidatesLiteral(t *testing.T) {
	t.Parallel()
	src := `
import os
from transformers import AutoModel

MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_ID = os.getenv("HF_MODEL_ID", MODEL_ID)
model = AutoModel.from_pretrained(MODEL_ID)
`
	discovered, unresolved := ParsePythonSource(src, "serve.py", nil)
	assert.Empty(t, discovered, "the runtime model is selected by HF_MODEL_ID")
	require.Len(t, unresolved, 1)
	assert.Equal(t, "non-literal repo_id", unresolved[0].Reason)
}

func TestParsePythonSource_PipelineKeywordModel(t *testing.T) {
	src := `from transformers import pipeline
classifier = pipeline("text-classification", model="typeform/distilbert-base-uncased-mnli")
`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "typeform/distilbert-base-uncased-mnli", disc[0].RepoID)
	assert.Equal(t, DefaultRevision, disc[0].Revision)
	assert.True(t, disc[0].RevisionDefaulted)
	assert.Equal(t, RepoTypeModel, disc[0].RepoType)
	assert.Empty(t, unres)
}

func TestParsePythonSource_PipelineWithRevision(t *testing.T) {
	src := `classifier = pipeline("text-classification", model="org/model", revision="v1")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	require.Len(t, disc, 1)
	assert.Equal(t, "org/model", disc[0].RepoID)
	assert.Equal(t, "v1", disc[0].Revision)
	assert.False(t, disc[0].RevisionDefaulted)
	assert.Empty(t, unres)
}

func TestParsePythonSource_PipelineNoModel(t *testing.T) {
	// pipeline("task") with no model= kwarg — nothing to audit, nothing to warn.
	src := `pipe = pipeline("text-generation")`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	assert.Empty(t, disc)
	assert.Empty(t, unres)
}

func TestParsePythonSource_PipelineTaskStringNotMistakenForModelID(t *testing.T) {
	// Regression for critical finding: pipeline("text-generation") must NOT record
	// "text-generation" as a model id. The first positional arg is the task string,
	// not a repo id; keywordOnly=true on the pipeline callPattern suppresses the
	// positional fallback so no bogus probe is emitted.
	taskOnlyCases := []string{
		`pipeline("text-generation")`,
		`pipeline("text-classification")`,
		`pipeline("question-answering")`,
		`pipeline("summarization")`,
		`pipeline("translation_en_to_fr")`,
	}
	for _, src := range taskOnlyCases {
		t.Run(src, func(t *testing.T) {
			disc, unres := ParsePythonSource(src, "test.py", nil)
			assert.Empty(t, disc, "task string must not be recorded as a model id")
			assert.Empty(t, unres, "absent model= kwarg must not produce an unresolved warning")
		})
	}
}

func TestParsePythonSource_PipelineDynamicModel(t *testing.T) {
	// pipeline("task", model=args.model) — model= is present but dynamic → unresolved warning.
	src := `pipe = pipeline("text-classification", model=args.model)`
	disc, unres := ParsePythonSource(src, "test.py", nil)
	assert.Empty(t, disc)
	require.Len(t, unres, 1)
	assert.Equal(t, "non-literal repo_id", unres[0].Reason)
}

func TestParsePythonSource_AmbiguousLocalOutputPath(t *testing.T) {
	// "output/gpt2-finetuned" has one slash and no leading marker — same shape as a
	// syntactically valid Hub id — and starts with a known local-output prefix. With
	// no scan root (no filesystem evidence either way), it must be reported as
	// ambiguous rather than silently treated as local or as a Hub id.
	cases := []string{
		`"output/gpt2-finetuned"`,
		`"outputs/run-1"`,
		`"runs/exp-42"`,
		`"checkpoints/step-1000"`,
		`"checkpoint/best"`,
		`"saved_models/bert-ft"`,
		`"artifacts/model"`,
		`"results/final"`,
		`"finetuned/llama-lora"`,
		`"trained/my-model"`,
	}
	for _, arg := range cases {
		t.Run(arg, func(t *testing.T) {
			src := "model = AutoModel.from_pretrained(" + arg + ")"
			disc, unres := ParsePythonSource(src, "test.py", nil)
			assert.Empty(t, disc, "ambiguous local-output-shaped literal must not be audited as a Hub id")
			require.Len(t, unres, 1)
			assert.Equal(t, "ambiguous local path or Hub repo id", unres[0].Reason)
		})
	}
}

func TestParsePythonSource_LocalOutputPathConfirmedByFilesystem(t *testing.T) {
	// When a scan root is available and "output/gpt2-finetuned" exists on disk as a
	// real directory relative to it, filesystem evidence confirms it's local.
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "output", "gpt2-finetuned"), 0o755))

	src := `model = AutoModel.from_pretrained("output/gpt2-finetuned")`
	disc, unres := ParsePythonSource(src, "test.py", nil, root)
	assert.Empty(t, disc, "filesystem-confirmed local dir must not be audited as a Hub id")
	require.Len(t, unres, 1)
	assert.Equal(t, "local filesystem path", unres[0].Reason)
}

func TestParsePythonSource_LocalOutputPathAmbiguousWhenDirMissing(t *testing.T) {
	// Same name-shaped literal, but the directory does NOT exist under root — still
	// ambiguous, since the absence doesn't prove it's a real Hub id either (the
	// script may just not have run yet, e.g. this is a training script being audited
	// before its first run).
	root := t.TempDir()

	src := `model = AutoModel.from_pretrained("output/gpt2-finetuned")`
	disc, unres := ParsePythonSource(src, "test.py", nil, root)
	assert.Empty(t, disc)
	require.Len(t, unres, 1)
	assert.Equal(t, "ambiguous local path or Hub repo id", unres[0].Reason)
}

// TestParsePythonSource_ExistingUnlistedLocalPath: filesystem disambiguation must
// run even when the literal doesn't match localOutputPrefixes (e.g. "models/gpt2").
func TestParsePythonSource_ExistingUnlistedLocalPath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "models", "gpt2"), 0o755))

	discovered, unresolved := ParsePythonSource(
		`from_pretrained("models/gpt2")`, "app.py", nil, root)
	assert.Empty(t, discovered)
	require.Len(t, unresolved, 1)
	assert.Equal(t, "local filesystem path", unresolved[0].Reason)
}

func TestParsePythonSource_LocalOutputPrefixFalsePositiveGuard(t *testing.T) {
	// Legitimate Hub ids that superficially resemble output paths must not be flagged.
	legitimate := []string{
		`"microsoft/phi-3"`,
		`"google-bert/bert-base-uncased"`,
		`"meta-llama/Llama-3.1-8B"`,
		`"openai-community/gpt2"`,
	}
	for _, arg := range legitimate {
		t.Run(arg, func(t *testing.T) {
			src := "model = AutoModel.from_pretrained(" + arg + ")"
			disc, unres := ParsePythonSource(src, "test.py", nil)
			require.Len(t, disc, 1, "legitimate Hub id must be audited")
			assert.Empty(t, unres)
		})
	}
}

func TestParsePythonSource_NestedParenHandled(t *testing.T) {
	// The outer call's first positional arg is a function call result (non-literal),
	// so it goes to unresolved. The inner AutoConfig.from_pretrained("base-model") is
	// itself a valid HF call and is discovered independently.
	src := `model = AutoModel.from_pretrained(AutoConfig.from_pretrained("base-model"), revision="v1")
`
	discovered, unresolved := ParsePythonSource(src, "test.py", nil)
	// Inner call discovered correctly.
	require.Len(t, discovered, 1, "inner from_pretrained(\"base-model\") should be discovered")
	assert.Equal(t, "base-model", discovered[0].RepoID)
	// Outer call goes to unresolved (non-literal first arg).
	require.Len(t, unresolved, 1, "outer call with non-literal repo_id should be in UnresolvedSites")
}
