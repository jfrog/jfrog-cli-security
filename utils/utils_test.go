package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUniqueIntersection(t *testing.T) {
	testCases := []struct {
		name     string
		slice1   []string
		slice2   []string
		expected []string
	}{
		{
			name:     "Empty",
			slice1:   []string{},
			slice2:   []string{},
			expected: []string{},
		},
		{
			name:     "One element",
			slice1:   []string{"element1"},
			slice2:   []string{"element1"},
			expected: []string{"element1"},
		},
		{
			name:     "Two elements",
			slice1:   []string{"element1", "element2"},
			slice2:   []string{"element2", "element3"},
			expected: []string{"element2"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expected, UniqueIntersection(tc.slice1, tc.slice2...))
		})
	}
}

func TestUniqueUnion(t *testing.T) {
	testCases := []struct {
		name     string
		slice    []string
		elements []string
		expected []string
	}{
		{
			name:     "Empty",
			slice:    []string{},
			elements: []string{},
			expected: []string{},
		},
		{
			name:     "One element",
			slice:    []string{"element1"},
			elements: []string{"element1"},
			expected: []string{"element1"},
		},
		{
			name:     "Two elements",
			slice:    []string{"element1", "element2"},
			elements: []string{"element2", "element3"},
			expected: []string{"element1", "element2", "element3"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expected, UniqueUnion(tc.slice, tc.elements...))
		})
	}
}

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
			assert.ElementsMatch(t, tc.expected, ToCommandEnvVars(tc.envVarsMap))
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
