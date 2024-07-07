package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToCommandEnvVars(t *testing.T) {
	testCases := []struct {
		name       string
		envVarsMap map[string]string
		expected   []string
	}{
		{
			name:       "Empty",
			envVarsMap: map[string]string{},
			expected:   []string{},
		},
		{
			name:       "One key-value pair",
			envVarsMap: map[string]string{"key1": "value1"},
			expected:   []string{"key1=value1"},
		},
		{
			name:       "Two key-value pairs",
			envVarsMap: map[string]string{"key1": "value1", "key2": "value2"},
			expected:   []string{"key1=value1", "key2=value2"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ToCommandEnvVars(tc.envVarsMap))
		})
	}
}

func TestToEnvVarsMap(t *testing.T) {
	testCases := []struct {
		name     string
		envVars  []string
		expected map[string]string
	}{
		{
			name:     "Empty",
			envVars:  []string{},
			expected: map[string]string{},
		},
		{
			name:     "One key-value pair",
			envVars:  []string{"key1=value1"},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "Two key-value pairs",
			envVars:  []string{"key1=value1", "key2=value2"},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ToEnvVarsMap(tc.envVars))
		})
	}
}

func TestMergeMaps(t *testing.T) {
	testCases := []struct {
		name     string
		maps     []map[string]string
		expected map[string]string
	}{
		{
			name:     "Empty",
			maps:     []map[string]string{},
			expected: map[string]string{},
		},
		{
			name:     "One map",
			maps:     []map[string]string{{"key1": "value1"}},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "Two maps",
			maps:     []map[string]string{{"key1": "value1"}, {"key2": "value2"}},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "Two maps with same key",
			maps:     []map[string]string{{"key1": "value1"}, {"key1": "value2"}},
			expected: map[string]string{"key1": "value2"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, MergeMaps(tc.maps...))
		})
	}
}
