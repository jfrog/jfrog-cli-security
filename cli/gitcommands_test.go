package cli

import (
	"reflect"
	"testing"
)

func TestGetRepositoriesList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "No spaces",
			input:    "repo1;repo2;repo3",
			expected: []string{"repo1", "repo2", "repo3"},
		},
		{
			name:     "With spaces",
			input:    "repo1; repo2 ; repo3",
			expected: []string{"repo1", "repo2", "repo3"},
		},
		{
			name:     "Trailing and leading spaces",
			input:    " repo1 ; repo2 ; repo3 ",
			expected: []string{"repo1", "repo2", "repo3"},
		},
		{
			name:     "Empty input",
			input:    "",
			expected: []string{},
		},
		{
			name:     "One coma",
			input:    ";",
			expected: []string{},
		},
		{
			name:     "Multiple commas",
			input:    "repo1;;repo2;;;repo3",
			expected: []string{"repo1", "repo2", "repo3"},
		},
		{
			name:     "One repo with coma",
			input:    "repo1;",
			expected: []string{"repo1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRepositoriesList(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}
