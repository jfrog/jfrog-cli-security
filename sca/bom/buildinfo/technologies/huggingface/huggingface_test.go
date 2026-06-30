package huggingface

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseModelReference(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantRepoID   string
		wantRevision string
		wantErr      string
	}{
		{
			name:         "model id with sha revision",
			input:        "mcpotato/42-eicar-street:8fb61c4d511e9aaff0ea55396a124aa292830efc",
			wantRepoID:   "mcpotato/42-eicar-street",
			wantRevision: "8fb61c4d511e9aaff0ea55396a124aa292830efc",
		},
		{
			name:         "model id with branch revision",
			input:        "mcpotato/42-eicar-street:main",
			wantRepoID:   "mcpotato/42-eicar-street",
			wantRevision: "main",
		},
		{
			name:         "no revision defaults to main",
			input:        "org/model",
			wantRepoID:   "org/model",
			wantRevision: DefaultRevision,
		},
		{
			name:         "single-segment model id with revision",
			input:        "bert-base-uncased:v1.0",
			wantRepoID:   "bert-base-uncased",
			wantRevision: "v1.0",
		},
		{
			name:         "huggingfaceml:// prefix stripped",
			input:        HuggingFacePackagePrefix + "org/model:v2",
			wantRepoID:   "org/model",
			wantRevision: "v2",
		},
		{
			name:         "trailing colon treated as no revision — defaults to main",
			input:        "org/model:",
			wantRepoID:   "org/model",
			wantRevision: DefaultRevision,
		},
		{
			// refs/pr/<n> is a valid Hugging Face revision (a PR ref) and contains '/'.
			// It must still be split off as the revision, not glued onto RepoID.
			name:         "PR ref revision containing slashes",
			input:        "org/model:refs/pr/3",
			wantRepoID:   "org/model",
			wantRevision: "refs/pr/3",
		},
		{
			name:         "refs/convert/parquet revision containing slashes",
			input:        "bert-base-uncased:refs/convert/parquet",
			wantRepoID:   "bert-base-uncased",
			wantRevision: "refs/convert/parquet",
		},
		{
			name:    "leading colon only revision — missing repo id",
			input:   ":main",
			wantErr: "missing repo id",
		},
		{
			name:    "bare colon — missing repo id",
			input:   ":",
			wantErr: "missing repo id",
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
			assert.Equal(t, tt.wantRepoID, info.RepoID, "RepoID mismatch")
			assert.Equal(t, tt.wantRevision, info.Revision, "Revision mismatch")
		})
	}
}

func TestParseModelReferences(t *testing.T) {
	t.Run("comma-separated with whitespace and trailing comma", func(t *testing.T) {
		infos, err := ParseModelReferences(" org/a:main , org/b:v2 ,")
		require.NoError(t, err)
		require.Len(t, infos, 2)
		assert.Equal(t, "org/a", infos[0].RepoID)
		assert.Equal(t, "main", infos[0].Revision)
		assert.Equal(t, "org/b", infos[1].RepoID)
		assert.Equal(t, "v2", infos[1].Revision)
	})
	t.Run("single value", func(t *testing.T) {
		infos, err := ParseModelReferences("org/only")
		require.NoError(t, err)
		require.Len(t, infos, 1)
		assert.Equal(t, "org/only", infos[0].RepoID)
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
			workDir := t.TempDir()
			params := technologies.BuildInfoBomGeneratorParams{HuggingFaceModel: tt.modelRef, WorkingDirectory: workDir}
			trees, uniqueDeps, warnings, err := BuildDependencyTree(params)
			require.NoError(t, err)
			require.Len(t, trees, 1, "expected exactly one dependency tree")
			// Root node name is the working directory basename (not the old hardcoded constant).
			assert.Equal(t, filepath.Base(workDir), trees[0].Id, "root node id mismatch")
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

// TestBuildDependencyTree_DatasetsReportedNotAudited verifies that dataset
// references are surfaced as an advisory warning and never handed to the curation
// walker (Catalog does not score datasets).
func TestBuildDependencyTree_DatasetsReportedNotAudited(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(dir+"/data.py", []byte(
		"from datasets import load_dataset\n"+
			"ds = load_dataset(\"squad\", revision=\"1.0.0\")\n"), 0644))

	params := technologies.BuildInfoBomGeneratorParams{WorkingDirectory: dir}
	trees, uniqueDeps, warnings, err := BuildDependencyTree(params)
	require.NoError(t, err)
	assert.Empty(t, trees, "datasets must not be audited")
	assert.Empty(t, uniqueDeps)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "dataset reference(s) found but NOT audited")
	assert.Contains(t, warnings[0], "squad")
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

// TestBuildDependencyTree_SkippedFileWarning verifies that a file the scanner
// could not parse produces a user-visible "PARTIAL" warning, rather than being
// silently swallowed at debug level, while the rest of the scan still proceeds.
func TestBuildDependencyTree_SkippedFileWarning(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		dir+"/good.py", []byte(`from_pretrained("org/discovered-model", revision="v1")`), 0644))
	require.NoError(t, os.WriteFile(dir+"/bad.ipynb", []byte(`{not valid json`), 0644))

	params := technologies.BuildInfoBomGeneratorParams{WorkingDirectory: dir}
	trees, uniqueDeps, warnings, err := BuildDependencyTree(params)
	require.NoError(t, err)
	require.Len(t, trees, 1, "the unparsable notebook must not block discovery of the good file")
	require.Len(t, uniqueDeps, 1)
	assert.Contains(t, uniqueDeps[0], "org/discovered-model")

	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "could not be scanned")
	assert.Contains(t, warnings[0], "PARTIAL")
	assert.Contains(t, warnings[0], "bad.ipynb")
}

// TestDisambiguateRootNodeNames verifies that working dirs sharing a basename get
// distinct names, while unrelated dirs keep the plain basename.
func TestDisambiguateRootNodeNames(t *testing.T) {
	tmp := t.TempDir()
	unique := filepath.Join(tmp, "unique-project")
	servicesA := filepath.Join(tmp, "services", "a", "model")
	servicesB := filepath.Join(tmp, "services", "b", "model")
	// deepA/deepB also collide on basename "model" but, unlike servicesA/servicesB,
	// share the same parent name too ("dup"), so tier 2 can't disambiguate them either.
	deepA := filepath.Join(tmp, "p", "dup", "model")
	deepB := filepath.Join(tmp, "q", "dup", "model")

	names := DisambiguateRootNodeNames([]string{unique, servicesA, servicesB, deepA, deepB, servicesA})

	assert.Equal(t, "unique-project", names[unique])
	assert.Equal(t, "a/model", names[servicesA])
	assert.Equal(t, "b/model", names[servicesB])
	assert.Equal(t, deepA, names[deepA])
	assert.Equal(t, deepB, names[deepB])

	seen := map[string]bool{}
	for _, n := range names {
		require.False(t, seen[n], "name %q assigned to more than one distinct directory", n)
		seen[n] = true
	}
}

func TestHostOf(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{name: "https with no explicit port", rawURL: "https://example.com/artifactory", want: "example.com"},
		{name: "https with explicit default port 443", rawURL: "https://example.com:443/artifactory", want: "example.com"},
		{name: "http with explicit default port 80", rawURL: "http://example.com:80/artifactory", want: "example.com"},
		{name: "https with non-default port kept", rawURL: "https://example.com:8443/artifactory", want: "example.com:8443"},
		{name: "http with non-default port kept", rawURL: "http://example.com:8081/artifactory", want: "example.com:8081"},
		{name: "no host", rawURL: "/just/a/path", wantErr: true},
		{name: "invalid URL", rawURL: "://bad-url", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hostOf(tt.rawURL)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestHostOf_MissingSchemeGetsActionableError verifies that a schemeless
// HF_ENDPOINT/Artifactory URL (a common copy-paste mistake) produces a message
// pointing at the missing scheme, not a bare "no host in URL".
func TestHostOf_MissingSchemeGetsActionableError(t *testing.T) {
	_, err := hostOf("my.jfrog.io/artifactory/api/huggingfaceml/hf-repo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing a scheme")
}

func TestValidateHFEndpointHost(t *testing.T) {
	tests := []struct {
		name           string
		hfEndpoint     string
		artifactoryUrl string
		wantErr        bool
	}{
		{
			name:           "same host, both without explicit port",
			hfEndpoint:     "https://my.jfrog.io/artifactory/api/huggingfaceml/hf-repo",
			artifactoryUrl: "https://my.jfrog.io/artifactory",
			wantErr:        false,
		},
		{
			name:           "same host, HF_ENDPOINT has explicit default https port, server does not",
			hfEndpoint:     "https://my.jfrog.io:443/artifactory/api/huggingfaceml/hf-repo",
			artifactoryUrl: "https://my.jfrog.io/artifactory",
			wantErr:        false,
		},
		{
			name:           "same host, server has explicit default https port, HF_ENDPOINT does not",
			hfEndpoint:     "https://my.jfrog.io/artifactory/api/huggingfaceml/hf-repo",
			artifactoryUrl: "https://my.jfrog.io:443/artifactory",
			wantErr:        false,
		},
		{
			name:           "different hosts",
			hfEndpoint:     "https://other.jfrog.io/artifactory/api/huggingfaceml/hf-repo",
			artifactoryUrl: "https://my.jfrog.io/artifactory",
			wantErr:        true,
		},
		{
			name:           "same host, genuinely different non-default ports",
			hfEndpoint:     "https://my.jfrog.io:8443/artifactory/api/huggingfaceml/hf-repo",
			artifactoryUrl: "https://my.jfrog.io/artifactory",
			wantErr:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(hfEndpointEnv, tt.hfEndpoint)
			serverDetails := &config.ServerDetails{ArtifactoryUrl: tt.artifactoryUrl}
			err := validateHFEndpointHost(serverDetails)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
