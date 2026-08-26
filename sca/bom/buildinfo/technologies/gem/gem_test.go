package gem

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils"
)

var expectedUniqueDeps = []string{"rubygems://puma:5.6.9", "rubygems://nio4r:2.7.5"}

var expectedResult = &xrayUtils.GraphNode{
	Id: "root",
	Nodes: []*xrayUtils.GraphNode{
		{
			Id: "rubygems://puma:5.6.9",
			Nodes: []*xrayUtils.GraphNode{
				{
					Id:    "rubygems://nio4r:2.7.5",
					Nodes: []*xrayUtils.GraphNode{},
				},
			},
		},
	},
}

func TestBuildDependencyTree(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "gem"))
	defer cleanUp()
	params := technologies.BuildInfoBomGeneratorParams{SkipAutoInstall: true}
	actualTopLevelTrees, uniqueDeps, err := BuildDependencyTree(params)
	assert.NoError(t, err, "BuildDependencyTree should not return an error")
	expectedTopLevelTrees := expectedResult.Nodes
	if !reflect.DeepEqual(expectedTopLevelTrees, actualTopLevelTrees) {
		expectedJSON, err := utils.GetAsJsonString(expectedTopLevelTrees, true, false)
		if err != nil {
			t.Fatalf("Failed to marshal expected dependency tree to JSON for error reporting: %v", err)
		}

		actualJSON, err := utils.GetAsJsonString(actualTopLevelTrees, true, false)
		if err != nil {
			t.Fatalf("Failed to marshal actual dependency tree to JSON for error reporting: %v", err)
		}
		t.Errorf("Dependency tree mismatch.\nExpected (JSON):\n%s\nGot (JSON):\n%s", expectedJSON, actualJSON)
	}
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "Unique dependencies mismatch. First is actual, Second is Expected")
}

// expectedUniqueDeps should be defined
// expectedUniqueDeps := []string{"rubygems://puma:5.6.9", "rubygems://nio4r:2.7.5"}
func TestCalculateUniqueDeps(t *testing.T) {
	var input = &xrayUtils.GraphNode{
		Nodes: []*xrayUtils.GraphNode{
			{
				Id: "rubygems://puma:5.6.9",
				Nodes: []*xrayUtils.GraphNode{
					{
						Id:    "rubygems://nio4r:2.7.5",
						Nodes: []*xrayUtils.GraphNode{},
					},
				},
			},
		},
	}
	uniqueDeps := calculateUniqueDependencies(input.Nodes)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
}

func TestParseArtifactoryGemSourceUrl(t *testing.T) {
	testCases := []struct {
		name          string
		sourceUrl     string
		expectMatch   bool
		expectedRtUrl string
		expectedRepo  string
		expectedUser  string
		expectedToken string
	}{
		{
			name:          "artifactory gems source with embedded credentials",
			sourceUrl:     "https://admin:FAKE-TEST-TOKEN-NOT-A-REAL-SECRET@myrt.jfrogdev.org/artifactory/api/gems/rubygems-repo-test/", // #nosec G101 -- fake placeholder value in a test fixture, not a real credential
			expectMatch:   true,
			expectedRtUrl: "https://myrt.jfrogdev.org/artifactory/",
			expectedRepo:  "rubygems-repo-test",
			expectedUser:  "admin",
			expectedToken: "FAKE-TEST-TOKEN-NOT-A-REAL-SECRET",
		},
		{
			name:          "artifactory gems source without credentials (anonymous access)",
			sourceUrl:     "https://myrt.jfrogdev.org/artifactory/api/gems/rubygems-repo-test/",
			expectMatch:   true,
			expectedRtUrl: "https://myrt.jfrogdev.org/artifactory/",
			expectedRepo:  "rubygems-repo-test",
		},
		{
			name:          "reverse-proxy source without /artifactory context root",
			sourceUrl:     "https://gems.company.com/api/gems/my-repo/",
			expectMatch:   true,
			expectedRtUrl: "https://gems.company.com/",
			expectedRepo:  "my-repo",
		},
		{
			name:          "source without trailing slash",
			sourceUrl:     "https://myrt.jfrogdev.org/artifactory/api/gems/rubygems-repo-test",
			expectMatch:   true,
			expectedRtUrl: "https://myrt.jfrogdev.org/artifactory/",
			expectedRepo:  "rubygems-repo-test",
		},
		{
			name:        "public rubygems.org source is not Artifactory-shaped",
			sourceUrl:   "https://rubygems.org/",
			expectMatch: false,
		},
		{
			name:        "empty repository segment",
			sourceUrl:   "https://myrt.jfrogdev.org/artifactory/api/gems/",
			expectMatch: false,
		},
		{
			name:        "malformed url",
			sourceUrl:   "not-a-url",
			expectMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, ok := parseArtifactoryGemSourceUrl(tc.sourceUrl)
			require.Equal(t, tc.expectMatch, ok)
			if !tc.expectMatch {
				return
			}
			assert.Equal(t, tc.expectedRtUrl, cfg.ArtifactoryUrl)
			assert.Equal(t, tc.expectedRepo, cfg.RepoName)
			assert.Equal(t, tc.expectedUser, cfg.AuthUser)
			assert.Equal(t, tc.expectedToken, cfg.AuthToken)
		})
	}
}

func TestExtractGemSourcesList(t *testing.T) {
	testCases := []struct {
		name        string
		raw         map[string]any
		expectFound bool
		expected    []string
	}{
		{
			name:        "leading-colon key (gem sources -a on-disk format)",
			raw:         map[string]any{":sources": []any{"https://rubygems.org/", "https://example.com/"}},
			expectFound: true,
			expected:    []string{"https://rubygems.org/", "https://example.com/"},
		},
		{
			name:        "plain key without leading colon",
			raw:         map[string]any{"sources": []any{"https://rubygems.org/"}},
			expectFound: true,
			expected:    []string{"https://rubygems.org/"},
		},
		{
			name:        "no sources key",
			raw:         map[string]any{":verbose": true},
			expectFound: false,
		},
		{
			name:        "sources is not a list",
			raw:         map[string]any{":sources": "https://rubygems.org/"},
			expectFound: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			list, ok := extractGemSourcesList(tc.raw)
			require.Equal(t, tc.expectFound, ok)
			if tc.expectFound {
				assert.Equal(t, tc.expected, list)
			}
		})
	}
}

func TestGetNativeGemRegistryConfig(t *testing.T) {
	t.Run("no gemrc files at all returns a clear error", func(t *testing.T) {
		tempHome := t.TempDir()
		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", "")
		t.Setenv("XDG_CONFIG_HOME", "")

		_, err := GetNativeGemRegistryConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gem sources --add")
	})

	t.Run("GEMRC-listed file overrides ~/.gemrc sources", func(t *testing.T) {
		tempHome := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tempHome, ".gemrc"),
			[]byte(":sources:\n- https://rubygems.org/\n"), 0600))

		gemrcOverride := filepath.Join(t.TempDir(), "gemrc-override")
		require.NoError(t, os.WriteFile(gemrcOverride,
			[]byte(":sources:\n- https://myrt.jfrogdev.org/artifactory/api/gems/rubygems-repo-test/\n"), 0600))

		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", gemrcOverride)

		cfg, err := GetNativeGemRegistryConfig()
		require.NoError(t, err)
		assert.Equal(t, "https://myrt.jfrogdev.org/artifactory/", cfg.ArtifactoryUrl)
		assert.Equal(t, "rubygems-repo-test", cfg.RepoName)
	})

	t.Run("sources with no Artifactory-shaped entry returns a clear error", func(t *testing.T) {
		tempHome := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tempHome, ".gemrc"),
			[]byte(":sources:\n- https://rubygems.org/\n"), 0600))
		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", "")

		_, err := GetNativeGemRegistryConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "point at an Artifactory Gems repository")
	})

	t.Run("first Artifactory-shaped source wins when multiple sources are configured", func(t *testing.T) {
		tempHome := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tempHome, ".gemrc"),
			[]byte(":sources:\n"+
				"- https://myrt.jfrogdev.org/artifactory/api/gems/rubygems-repo-test/\n"+
				"- https://rubygems.org/\n"), 0600))
		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", "")

		cfg, err := GetNativeGemRegistryConfig()
		require.NoError(t, err)
		assert.Equal(t, "rubygems-repo-test", cfg.RepoName)
	})

	t.Run("the Artifactory-shaped source is found regardless of its position in the list", func(t *testing.T) {
		tempHome := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tempHome, ".gemrc"),
			[]byte(":sources:\n"+
				"- https://rubygems.org/\n"+
				"- https://myrt.jfrogdev.org/artifactory/api/gems/rubygems-repo-test/\n"), 0600))
		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", "")

		cfg, err := GetNativeGemRegistryConfig()
		require.NoError(t, err)
		assert.Equal(t, "rubygems-repo-test", cfg.RepoName)
	})

	t.Run("GEMRC fully replaces ~/.gemrc's sources instead of merging with them", func(t *testing.T) {
		tempHome := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tempHome, ".gemrc"),
			[]byte(":sources:\n- https://myrt.jfrogdev.org/artifactory/api/gems/rubygems-repo-test/\n"), 0600))

		gemrcOverride := filepath.Join(t.TempDir(), "gemrc-override")
		require.NoError(t, os.WriteFile(gemrcOverride, []byte(":sources:\n- https://rubygems.org/\n"), 0600))

		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", gemrcOverride)

		// GEMRC's file has no Artifactory source; if it merged with ~/.gemrc this would
		// succeed using ~/.gemrc's source instead of failing.
		_, err := GetNativeGemRegistryConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "point at an Artifactory Gems repository")
	})

	t.Run("empty gemrc file returns the same clear error as a missing one", func(t *testing.T) {
		tempHome := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tempHome, ".gemrc"), []byte(""), 0600))
		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", "")

		_, err := GetNativeGemRegistryConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gem sources --add")
	})

	t.Run("an empty ':sources:' list returns the same clear error as no sources", func(t *testing.T) {
		tempHome := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tempHome, ".gemrc"), []byte(":sources: []\n"), 0600))
		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", "")

		_, err := GetNativeGemRegistryConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gem sources --add")
	})

	t.Run("falls back to $XDG_CONFIG_HOME/gem/gemrc when ~/.gemrc doesn't exist", func(t *testing.T) {
		tempHome := t.TempDir()
		xdgConfigHome := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(xdgConfigHome, "gem"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(xdgConfigHome, "gem", "gemrc"),
			[]byte(":sources:\n- https://myrt.jfrogdev.org/artifactory/api/gems/rubygems-repo-test/\n"), 0600))

		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", "")
		t.Setenv("XDG_CONFIG_HOME", xdgConfigHome)

		cfg, err := GetNativeGemRegistryConfig()
		require.NoError(t, err)
		assert.Equal(t, "rubygems-repo-test", cfg.RepoName)
	})

	t.Run("a source with the wrong API path is not mistaken for an Artifactory Gems repository", func(t *testing.T) {
		tempHome := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tempHome, ".gemrc"),
			[]byte(":sources:\n- https://myrt.jfrogdev.org/artifactory/api/rubygems/rubygems-repo-test/\n"), 0600))
		t.Setenv("HOME", tempHome)
		t.Setenv("USERPROFILE", tempHome)
		t.Setenv("GEMRC", "")

		_, err := GetNativeGemRegistryConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "point at an Artifactory Gems repository")
	})
}
