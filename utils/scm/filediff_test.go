package scm

import (

	// "path/filepath"
	"testing"

	// goGit "github.com/go-git/go-git/v5"

	"github.com/stretchr/testify/assert"
)

func TestRangeContains(t *testing.T) {
	rangeToTest := Range{StartRow: 1, StartCol: 1, EndRow: 10, EndCol: 10}

	testCases := []struct {
		name       string
		inputRange Range
		expected   bool
	}{
		{
			name:       "Same range",
			inputRange: Range{StartRow: 1, StartCol: 1, EndRow: 10, EndCol: 10},
			expected:   true,
		},
		{
			name:       "Range contains input range",
			inputRange: Range{StartRow: 2, StartCol: 2, EndRow: 9, EndCol: 9},
			expected:   true,
		},
		{
			name:       "Range overlapping input range (to the right)",
			inputRange: Range{StartRow: 5, StartCol: 5, EndRow: 15, EndCol: 15},
			expected:   false,
		},
		{
			name:       "Range overlapping input range (to the left)",
			inputRange: Range{StartRow: 0, StartCol: 0, EndRow: 5, EndCol: 5},
			expected:   false,
		},
		{
			name:       "Range overlapping input range (input range contains range)",
			inputRange: Range{StartRow: 0, StartCol: 0, EndRow: 11, EndCol: 11},
			expected:   false,
		},
		{
			name:       "Range outside input range",
			inputRange: Range{StartRow: 11, StartCol: 11, EndRow: 20, EndCol: 20},
			expected:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rangeToTest.Contains(tt.inputRange.StartRow, tt.inputRange.StartCol, tt.inputRange.EndRow, tt.inputRange.EndCol))
		})
	}
}

func TestRangeOverlaps(t *testing.T) {
	rangeToTest := Range{StartRow: 1, StartCol: 1, EndRow: 10, EndCol: 10}

	testCases := []struct {
		name       string
		inputRange Range
		expected   bool
	}{
		{
			name:       "Same range",
			inputRange: Range{StartRow: 1, StartCol: 1, EndRow: 10, EndCol: 10},
			expected:   true,
		},
		{
			name:       "Range contains input range",
			inputRange: Range{StartRow: 2, StartCol: 2, EndRow: 9, EndCol: 9},
			expected:   true,
		},
		{
			name:       "Range overlapping input range (to the right)",
			inputRange: Range{StartRow: 5, StartCol: 5, EndRow: 15, EndCol: 15},
			expected:   true,
		},
		{
			name:       "Range overlapping input range (to the left)",
			inputRange: Range{StartRow: 0, StartCol: 0, EndRow: 5, EndCol: 5},
			expected:   true,
		},
		{
			name:       "Range overlapping input range (input range contains range)",
			inputRange: Range{StartRow: 0, StartCol: 0, EndRow: 11, EndCol: 11},
			expected:   true,
		},
		{
			name:       "Range outside input range",
			inputRange: Range{StartRow: 11, StartCol: 11, EndRow: 20, EndCol: 20},
			expected:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, rangeToTest.Overlaps(tt.inputRange.StartRow, tt.inputRange.StartCol, tt.inputRange.EndRow, tt.inputRange.EndCol))
		})
	}
}

func TestFileChangesContains(t *testing.T) {
	fileChangesToTest := FileChanges{
		Path: "file1",
		Ranges: []Range{
			{StartRow: 1, StartCol: 1, EndRow: 10, EndCol: 10},
			{StartRow: 20, StartCol: 20, EndRow: 30, EndCol: 30},
		},
	}

	testCases := []struct {
		name       string
		inputRange Range
		expected   bool
	}{
		{
			name:       "input range in file changes",
			inputRange: Range{StartRow: 2, StartCol: 2, EndRow: 9, EndCol: 9},
			expected:   true,
		},
		{
			name:       "input range overlaps file changes",
			inputRange: Range{StartRow: 9, StartCol: 9, EndRow: 25, EndCol: 25},
			expected:   false,
		},
		{
			name:       "input range outside file changes",
			inputRange: Range{StartRow: 31, StartCol: 31, EndRow: 40, EndCol: 40},
			expected:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, fileChangesToTest.Contains(tt.inputRange.StartRow, tt.inputRange.StartCol, tt.inputRange.EndRow, tt.inputRange.EndCol))
		})
	}
}

func TestFileChangesOverlaps(t *testing.T) {
	fileChangesToTest := FileChanges{
		Path: "file1",
		Ranges: []Range{
			{StartRow: 1, StartCol: 1, EndRow: 10, EndCol: 10},
			{StartRow: 20, StartCol: 20, EndRow: 30, EndCol: 30},
		},
	}

	testCases := []struct {
		name       string
		inputRange Range
		expected   bool
	}{
		{
			name:       "input range in file changes",
			inputRange: Range{StartRow: 2, StartCol: 2, EndRow: 9, EndCol: 9},
			expected:   true,
		},
		{
			name:       "input range overlaps file changes",
			inputRange: Range{StartRow: 9, StartCol: 9, EndRow: 25, EndCol: 25},
			expected:   true,
		},
		{
			name:       "input range outside file changes",
			inputRange: Range{StartRow: 31, StartCol: 31, EndRow: 40, EndCol: 40},
			expected:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, fileChangesToTest.Overlaps(tt.inputRange.StartRow, tt.inputRange.StartCol, tt.inputRange.EndRow, tt.inputRange.EndCol))
		})
	}
}
