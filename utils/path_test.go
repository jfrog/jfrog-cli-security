package utils

import (
	"fmt"
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
			expected: filepath.Join("dir3", "dir4"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetRelativePath(test.target, test.basePath)
			assert.Equal(t, result, filepath.ToSlash(test.expected), "expected '%s', got '%s'", filepath.ToSlash(test.expected), result)
		})
	}
}
func TestExtractRelativePath(t *testing.T) {
	tests := []struct {
		name           string
		fullPath       string
		projectPath    string
		expectedResult string
	}{
		{
			name:           "empty path",
			fullPath:       "",
			projectPath:    filepath.Join("Users", "user", "Desktop", "secrets_scanner"),
			expectedResult: "",
		},
		{
			name:           "invalid path",
			fullPath:       "invalidFullPath",
			projectPath:    filepath.Join("Users", "user", "Desktop", "secrets_scanner"),
			expectedResult: "invalidFullPath",
		},
		{
			name:           "valid full path",
			fullPath:       fmt.Sprintf("file://%s", filepath.Join("Users", "user", "Desktop", "secrets_scanner", "tests", "req.nodejs", "file.js")),
			projectPath:    fmt.Sprintf("file://%s", filepath.Join("Users", "user", "Desktop", "secrets_scanner")),
			expectedResult: "tests/req.nodejs/file.js",
		},
		{
			name:           "invalid project path",
			fullPath:       fmt.Sprintf("file://%s", filepath.Join("Users", "user", "Desktop", "secrets_scanner", "tests", "req.nodejs", "file.js")),
			projectPath:    "invalidProjectPath",
			expectedResult: fmt.Sprintf("file://%s", filepath.Join("Users", "user", "Desktop", "secrets_scanner", "tests", "req.nodejs", "file.js")),
		},
		{
			name:           "valid full path with private",
			fullPath:       "file:///private/Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js",
			projectPath:    "file:///Users/user/Desktop/secrets_scanner/",
			expectedResult: "tests/req.nodejs/file.js",
		},
		{
			name:           "invalid project path and path with private",
			fullPath:       "file:///private/Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js",
			projectPath:    "invalidProjectPath",
			expectedResult: "file:///Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedResult, GetRelativePath(test.fullPath, test.projectPath))
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
