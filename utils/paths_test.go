package utils

import (
	"bytes"
	"path/filepath"
	"testing"

	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	downloadPath = "xray-scan-lib/xray-scan-lib-1.6.0-linux-amd64.tar.gz"
	envServerId  = "envServer"
)

func TestIsPathExcludedFromRoot(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "ci", "proj")
	ancestorRoot := filepath.Join(string(filepath.Separator), "ci", "attestation", "main")
	tests := []struct {
		name       string
		root       string
		path       string
		exclusions []string
		expected   bool
	}{
		{
			name:       "Project folder name does not exclude it",
			root:       filepath.Join(string(filepath.Separator), "ci", "my-test-project"),
			path:       filepath.Join(string(filepath.Separator), "ci", "my-test-project"),
			exclusions: []string{"*test*"},
			expected:   false,
		},
		{
			name:       "Subfolder inside the project matches",
			root:       root,
			path:       filepath.Join(root, "src", "test", "app.go"),
			exclusions: []string{"*test*"},
			expected:   true,
		},
		{
			name:       "Subfolder does not match",
			root:       root,
			path:       filepath.Join(root, "src", "app.go"),
			exclusions: []string{"*node_modules*"},
			expected:   false,
		},
		{
			name:       "Include kept when only a parent folder matches",
			root:       root,
			path:       filepath.Join(string(filepath.Separator), "ci", "attestation", "sibling"),
			exclusions: []string{"*test*"},
			expected:   false,
		},
		{
			name:       "Path outside the project is kept when its own name matches",
			root:       root,
			path:       filepath.Join(string(filepath.Separator), "ci", "my-test-sibling"),
			exclusions: []string{"*test*"},
			expected:   false,
		},
		{
			name:       "Ancestor of the project does not exclude it",
			root:       ancestorRoot,
			path:       ancestorRoot,
			exclusions: []string{"*test*"},
			expected:   false,
		},
		{
			name:       "File inside the project is not excluded by an ancestor",
			root:       ancestorRoot,
			path:       filepath.Join(ancestorRoot, "src", "app.go"),
			exclusions: []string{"*test*"},
			expected:   false,
		},
		{
			name:       "Empty exclusions",
			root:       filepath.Join(string(filepath.Separator), "ci", "attestation", "main"),
			path:       filepath.Join(string(filepath.Separator), "ci", "attestation", "main"),
			exclusions: nil,
			expected:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsPathExcludedFromRoot(tt.root, tt.path, tt.exclusions))
		})
	}
}

func TestIsPathExcludedFromRootWarnsWhenPathCannotBeCompared(t *testing.T) {
	buf := &bytes.Buffer{}
	original := log.Logger
	log.SetLogger(log.NewLogger(log.WARN, buf))
	t.Cleanup(func() { log.SetLogger(original) })

	root := filepath.Join(string(filepath.Separator), "ci", "proj")
	assert.False(t, IsPathExcludedFromRoot(root, "src", []string{"*test*"}))
	assert.Contains(t, buf.String(), "Failed to compare path for exclusions")
}

func TestIsPathExcluded(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		exclusions []string
		expected   bool
	}{
		{
			name:       "Matching exclusion pattern",
			path:       "/project/node_modules/pkg",
			exclusions: []string{"*node_modules*"},
			expected:   true,
		},
		{
			name:       "Non-matching exclusion pattern",
			path:       "/project/src/main.go",
			exclusions: []string{"*node_modules*"},
			expected:   false,
		},
		{
			name:       "Empty exclusions - path is not excluded",
			path:       "/project/src/main.go",
			exclusions: []string{},
			expected:   false,
		},
		{
			name:       "Multiple patterns - one matches",
			path:       "/project/test/unit_test.go",
			exclusions: []string{"*node_modules*", "*test*"},
			expected:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsPathExcluded(tt.path, tt.exclusions))
		})
	}
}

func TestGetFullPathsWorkingDirs(t *testing.T) {
	tests := []struct {
		name        string
		workingDirs []string
		expectErr   bool
	}{
		{
			name:        "Empty input",
			workingDirs: []string{},
			expectErr:   false,
		},
		{
			name:        "Already absolute paths",
			workingDirs: []string{"/absolute/path/one", "/absolute/path/two"},
			expectErr:   false,
		},
		{
			name:        "Relative paths get resolved",
			workingDirs: []string{"relative/path"},
			expectErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetFullPathsWorkingDirs(tt.workingDirs)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Len(t, result, len(tt.workingDirs))
			for _, p := range result {
				assert.True(t, filepath.IsAbs(p), "expected absolute path, got: %s", p)
			}
		})
	}
}

func TestGetReleasesRemoteDetails(t *testing.T) {
	profileServer := &config.ServerDetails{ArtifactoryUrl: "https://profile.example.com/artifactory/"}
	envServer := &config.ServerDetails{ServerId: envServerId, Url: "https://env.example.com/", ArtifactoryUrl: "https://env.example.com/artifactory/"}
	t.Setenv(coreutils.HomeDir, t.TempDir())
	require.NoError(t, commonCommands.NewConfigCommand(commonCommands.AddOrEdit, envServerId).SetDetails(envServer).SetInteractive(false).SetEncPassword(false).Run())
	testCases := []struct {
		name                       string
		remoteRepo                 string
		remoteServer               *config.ServerDetails
		envValue                   string
		expectedServerUrl          string
		expectedRemotePath         string
		expectedFallbackRemotePath string
	}{
		{
			name:                       "Config profile remote repository",
			remoteRepo:                 "releases-remote",
			remoteServer:               profileServer,
			expectedServerUrl:          profileServer.ArtifactoryUrl,
			expectedRemotePath:         "releases-remote/artifactory/" + downloadPath,
			expectedFallbackRemotePath: "releases-remote/" + downloadPath,
		},
		{
			name:                       "Env var remote repository",
			envValue:                   envServerId + "/releases-remote",
			expectedServerUrl:          envServer.ArtifactoryUrl,
			expectedRemotePath:         "releases-remote/artifactory/" + downloadPath,
			expectedFallbackRemotePath: "releases-remote/" + downloadPath,
		},
		{
			name:               "Not configured, download from releases.jfrog.io",
			expectedServerUrl:  coreutils.JfrogReleasesUrl,
			expectedRemotePath: downloadPath,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(coreutils.ReleasesRemoteEnv, testCase.envValue)
			server, remotePath, fallbackRemotePath, err := GetReleasesRemoteDetails("Resource", downloadPath, testCase.remoteRepo, testCase.remoteServer)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedServerUrl, server.ArtifactoryUrl)
			assert.Equal(t, testCase.expectedRemotePath, remotePath)
			assert.Equal(t, testCase.expectedFallbackRemotePath, fallbackRemotePath)
		})
	}
}
