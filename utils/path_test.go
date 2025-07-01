package utils

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
			assert.Equal(t, result, filepath.ToSlash(test.expected), "expected '%s', got '%s'", filepath.ToSlash(test.expected), result)
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

func TestGetRepositoriesScansListUrlForArtifact(t *testing.T) {
	tests := []struct {
		name         string
		baseUrl      string
		repoPath     string
		targetPath   string
		artifactName string
		packageId    string
		expected     string
	}{
		{
			name:         "basic case",
			baseUrl:      "http://localhost:8081/",
			repoPath:     "my-repo",
			targetPath:   "artifact.zip",
			artifactName: "artifact.zip",
			packageId:    "abc123",
			expected:     "http://localhost:8081/ui/scans-list/repositories/my-repo/scan-descendants/artifact.zip?package_id=abc123&page_type=overview&path=my-repo%2Fartifact.zip",
		},
		{
			name:         "with subdirectory",
			baseUrl:      "http://localhost:8081/",
			repoPath:     "my-repo",
			targetPath:   "path/to/artifact.zip",
			artifactName: "artifact.zip",
			packageId:    "abc123",
			expected:     "http://localhost:8081/ui/scans-list/repositories/my-repo/scan-descendants/artifact.zip?package_id=abc123&page_type=overview&path=my-repo%2Fpath%2Fto%2Fartifact.zip",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetRepositoriesScansListUrlForArtifact(test.baseUrl, test.repoPath, test.targetPath, test.artifactName, test.packageId)
			assert.Equal(t, test.expected, result, "expected '%s', got '%s'", test.expected, result)
		})
	}
}
