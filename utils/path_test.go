package utils

import (
	"path/filepath"
	"testing"
)

func TestGetRelativePath(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		target   string
		expected string
	}{
		{
			name:     "relative path",
			basePath: filepath.Join("dir1", "dir2"),
			target:   filepath.Join("dir1", "dir2", "dir3"),
			expected: "dir3",
		},
		{
			name:     "absolute path",
			basePath: filepath.Join("home", "user", "dir1", "dir2"),
			target:   filepath.Join("home", "user", "dir1", "dir2", "dir3"),
			expected: "dir3",
		},
		{
			name:     "no common base path",
			basePath: filepath.Join("dir1", "dir2"),
			target:   filepath.Join("dir3", "dir4"),
			expected: filepath.Join("..", "..", "dir3", "dir4"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetRelativePath(test.target, test.basePath)
			if result != test.expected {
				t.Errorf("expected '%s', got '%s'", filepath.ToSlash(test.expected), result)
			}
		})
	}
}

func TestGetCommonParentDir(t *testing.T) {
	tests := []struct {
		name     string
		dirs     []string
		expected string
	}{
		{
			name:     "common parent dir",
			dirs:     []string{filepath.Join("dir1", "dir2", "dir3"), filepath.Join("dir1", "dir2", "dir4")},
			expected: filepath.Join("dir1", "dir2"),
		},
		{
			name:     "multi sub common parent dir",
			dirs:     []string{filepath.Join("dir1", "dir2", "dir3"), filepath.Join("dir1", "dir2", "dir4"), filepath.Join("dir1", "dir5")},
			expected: "dir1",
		},
		{
			name:     "no common parent dir",
			dirs:     []string{filepath.Join("dir1", "dir2", "dir3"), filepath.Join("dir1", "dir2", "dir4"), filepath.Join("dir4", "dir5")},
			expected: ".",
		},
		{
			name:     "empty dirs",
			dirs:     []string{},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetCommonParentDir(test.dirs...)
			if result != test.expected {
				t.Errorf("expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}
