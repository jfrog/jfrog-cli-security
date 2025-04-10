package utils

import "testing"

func TestGetRelativePath(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		target   string
		expected string
	}{
		{
			name:     "relative path",
			basePath: "dir1/dir2",
			target:   "dir1/dir2/dir3",
			expected: "dir3",
		},
		{
			name:     "absolute path",
			basePath: "/home/user/dir1/dir2",
			target:   "/home/user/dir1/dir2/dir3",
			expected: "dir3",
		},
		{
			name:     "no common base path",
			basePath: "dir1/dir2",
			target:   "dir3/dir4",
			expected: "dir3/dir4",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetRelativePath(test.target, test.basePath)
			if result != test.expected {
				t.Errorf("expected '%s', got '%s'", test.expected, result)
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
			dirs:     []string{"dir1/dir2/dir3", "dir1/dir2/dir4"},
			expected: "dir1/dir2",
		},
		{
			name:     "multi sub common parent dir",
			dirs:     []string{"dir1/dir2/dir3", "dir1/dir2/dir4", "dir1/dir5"},
			expected: "dir1",
		},
		{
			name:     "no common parent dir",
			dirs:     []string{"dir1/dir2/dir3", "dir4/dir5"},
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
