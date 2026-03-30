package utils

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
			name:       "Empty exclusions - matches all (PrepareExcludePathPattern behavior)",
			path:       "/project/src/main.go",
			exclusions: []string{},
			expected:   true,
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
