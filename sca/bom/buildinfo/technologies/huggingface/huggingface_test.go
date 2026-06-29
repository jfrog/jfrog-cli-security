package huggingface

import (
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseModelReference(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantRepoId   string
		wantRevision string
		wantErr      string
	}{
		{
			name:         "model id with sha revision",
			input:        "mcpotato/42-eicar-street:8fb61c4d511e9aaff0ea55396a124aa292830efc",
			wantRepoId:   "mcpotato/42-eicar-street",
			wantRevision: "8fb61c4d511e9aaff0ea55396a124aa292830efc",
		},
		{
			name:         "model id with branch revision",
			input:        "mcpotato/42-eicar-street:main",
			wantRepoId:   "mcpotato/42-eicar-street",
			wantRevision: "main",
		},
		{
			name:         "no revision defaults to main",
			input:        "org/model",
			wantRepoId:   "org/model",
			wantRevision: DefaultRevision,
		},
		{
			name:         "single-segment model id with revision",
			input:        "bert-base-uncased:v1.0",
			wantRepoId:   "bert-base-uncased",
			wantRevision: "v1.0",
		},
		{
			name:         "huggingfaceml:// prefix stripped",
			input:        HuggingFacePackagePrefix + "org/model:v2",
			wantRepoId:   "org/model",
			wantRevision: "v2",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "hugging face model reference is empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseModelReference(tt.input)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantRepoId, info.RepoId, "RepoId mismatch")
			assert.Equal(t, tt.wantRevision, info.Revision, "Revision mismatch")
		})
	}
}

func TestParseModelReferences(t *testing.T) {
	t.Run("comma-separated with whitespace and trailing comma", func(t *testing.T) {
		infos, err := ParseModelReferences(" org/a:main , org/b:v2 ,")
		require.NoError(t, err)
		require.Len(t, infos, 2)
		assert.Equal(t, "org/a", infos[0].RepoId)
		assert.Equal(t, "main", infos[0].Revision)
		assert.Equal(t, "org/b", infos[1].RepoId)
		assert.Equal(t, "v2", infos[1].Revision)
	})
	t.Run("single value", func(t *testing.T) {
		infos, err := ParseModelReferences("org/only")
		require.NoError(t, err)
		require.Len(t, infos, 1)
		assert.Equal(t, "org/only", infos[0].RepoId)
		assert.Equal(t, DefaultRevision, infos[0].Revision)
	})
	t.Run("all empty entries error", func(t *testing.T) {
		_, err := ParseModelReferences("  , , ")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})
}

func TestRepoFromHFEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantRepo string
		wantErr  string
	}{
		{
			name:     "standard endpoint",
			endpoint: "https://z0gytst.jfrogdev.org/artifactory/api/huggingfaceml/my-hugging-face-repo",
			wantRepo: "my-hugging-face-repo",
		},
		{
			name:     "endpoint with trailing slash",
			endpoint: "https://my.jfrog.io/artifactory/api/huggingfaceml/hf-repo/",
			wantRepo: "hf-repo",
		},
		{
			name:     "endpoint with extra path after repo",
			endpoint: "https://my.jfrog.io/artifactory/api/huggingfaceml/hf-repo/api/models",
			wantRepo: "hf-repo",
		},
		{
			name:     "not set",
			endpoint: "",
			wantErr:  "HF_ENDPOINT is not set",
		},
		{
			name:     "missing marker",
			endpoint: "https://my.jfrog.io/artifactory/api/npm/npm-repo",
			wantErr:  "does not contain",
		},
		{
			name:     "no repo segment after marker",
			endpoint: "https://my.jfrog.io/artifactory/api/huggingfaceml/",
			wantErr:  "no repository segment",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(hfEndpointEnv, tt.endpoint)
			repo, err := repoFromHFEndpoint()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantRepo, repo)
		})
	}
}

func TestBuildDependencyTree(t *testing.T) {
	tests := []struct {
		name          string
		modelRef      string
		wantLeafId    string
		wantUniqueDep string
	}{
		{
			name:          "blocked malicious model with sha",
			modelRef:      "mcpotato/42-eicar-street:8fb61c4d511e9aaff0ea55396a124aa292830efc",
			wantLeafId:    HuggingFacePackagePrefix + "mcpotato/42-eicar-street:8fb61c4d511e9aaff0ea55396a124aa292830efc",
			wantUniqueDep: HuggingFacePackagePrefix + "mcpotato/42-eicar-street:8fb61c4d511e9aaff0ea55396a124aa292830efc",
		},
		{
			name:          "model with branch revision",
			modelRef:      "bert-base-uncased:main",
			wantLeafId:    HuggingFacePackagePrefix + "bert-base-uncased:main",
			wantUniqueDep: HuggingFacePackagePrefix + "bert-base-uncased:main",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Empty working dir so only the flag contributes (no stray discovery).
			params := technologies.BuildInfoBomGeneratorParams{HuggingFaceModel: tt.modelRef, WorkingDirectory: t.TempDir()}
			trees, uniqueDeps, warnings, err := BuildDependencyTree(params)
			require.NoError(t, err)
			require.Len(t, trees, 1, "expected exactly one dependency tree")
			assert.Equal(t, "huggingface-project", trees[0].Id, "root node id mismatch")
			require.Len(t, trees[0].Nodes, 1, "expected exactly one child node")
			assert.Equal(t, tt.wantLeafId, trees[0].Nodes[0].Id, "leaf node id mismatch")
			require.Len(t, uniqueDeps, 1, "expected exactly one unique dep")
			assert.Equal(t, tt.wantUniqueDep, uniqueDeps[0], "unique dep mismatch")
			assert.Empty(t, warnings, "flag-only mode should not produce warnings")
		})
	}
}

// TestBuildDependencyTree_MultiValueAndAdditive verifies that the flag accepts a
// comma-separated list and that flag mode audits exactly the named models — no more,
// no less (source scan is skipped in flag mode).
func TestBuildDependencyTree_MultiValueAndAdditive(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		dir+"/app.py", []byte(`from_pretrained("org/discovered-model", revision="v1")`), 0644))

	params := technologies.BuildInfoBomGeneratorParams{
		// Two explicit flag models; source file has a third model that must NOT appear.
		HuggingFaceModel: "org/flag-model-a:main, org/flag-model-b:v2",
		WorkingDirectory: dir,
	}
	trees, uniqueDeps, warnings, err := BuildDependencyTree(params)
	require.NoError(t, err)
	require.Len(t, trees, 1)
	// Only the two flag models — discovered-model from source must be absent.
	assert.Len(t, uniqueDeps, 2)
	assert.Contains(t, uniqueDeps, HuggingFacePackagePrefix+"org/flag-model-a:main")
	assert.Contains(t, uniqueDeps, HuggingFacePackagePrefix+"org/flag-model-b:v2")
	assert.NotContains(t, uniqueDeps, HuggingFacePackagePrefix+"org/discovered-model:v1")
	assert.Empty(t, warnings, "flag mode skips source scan so no warnings expected")
}

// TestBuildDependencyTree_AutoDiscovery verifies that an empty HuggingFaceModel flag
// triggers source scanning on the working directory instead of returning an error.
func TestBuildDependencyTree_AutoDiscovery(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		dir+"/app.py", []byte(`from_pretrained("org/discovered-model", revision="v1")`), 0644))

	params := technologies.BuildInfoBomGeneratorParams{
		HuggingFaceModel: "",
		WorkingDirectory: dir,
	}
	trees, uniqueDeps, _, err := BuildDependencyTree(params)
	require.NoError(t, err)
	require.Len(t, trees, 1)
	require.Len(t, uniqueDeps, 1)
	assert.Contains(t, uniqueDeps[0], "org/discovered-model")
}

// TestBuildDependencyTree_UnresolvedWarnings verifies that dynamic references are
// returned as warnings (for the caller to surface after the curation table) rather
// than being logged during the BOM-build phase.
func TestBuildDependencyTree_UnresolvedWarnings(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(dir+"/dyn.py", []byte(
		"runtime = AutoModel.from_pretrained(args.model_name)\n"), 0644))

	params := technologies.BuildInfoBomGeneratorParams{WorkingDirectory: dir}
	trees, uniqueDeps, warnings, err := BuildDependencyTree(params)
	require.NoError(t, err)
	assert.Empty(t, trees, "no statically-resolvable models expected")
	assert.Empty(t, uniqueDeps)
	require.Len(t, warnings, 1, "expected one consolidated unresolved-references warning")
	assert.Contains(t, warnings[0], "could not be statically resolved")
	assert.Contains(t, warnings[0], "non-literal repo_id")
}
