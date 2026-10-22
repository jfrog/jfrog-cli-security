package utils

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
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
			name:       "Project folder name matches",
			root:       filepath.Join(string(filepath.Separator), "ci", "my-test-project"),
			path:       filepath.Join(string(filepath.Separator), "ci", "my-test-project"),
			exclusions: []string{"*test*"},
			expected:   true,
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
