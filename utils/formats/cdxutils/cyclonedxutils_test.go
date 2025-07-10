package cdxutils

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestAppendProperties(t *testing.T) {
	tests := []struct {
		name          string
		properties    *[]cyclonedx.Property
		newProperties []cyclonedx.Property
		expected      *[]cyclonedx.Property
	}{
		{
			name:          "Append new properties",
			properties:    &[]cyclonedx.Property{{Name: "key1", Value: "value1"}},
			newProperties: []cyclonedx.Property{{Name: "key2", Value: "value2"}},
			expected:      &[]cyclonedx.Property{{Name: "key1", Value: "value1"}, {Name: "key2", Value: "value2"}},
		},
		{
			name:          "Do not append existing property",
			properties:    &[]cyclonedx.Property{{Name: "key1", Value: "value1"}},
			newProperties: []cyclonedx.Property{{Name: "key1", Value: "newValue"}},
			expected:      &[]cyclonedx.Property{{Name: "key1", Value: "value1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AppendProperties(tt.properties, tt.newProperties...)
			assert.Equal(t, tt.expected, result, "Expected properties do not match")
		})
	}
}

func TestSearchDependencyEntry(t *testing.T) {
	tests := []struct {
		name         string
		dependencies *[]cyclonedx.Dependency
		ref          string
		expected     *cyclonedx.Dependency
	}{
		{
			name:         "Find existing dependency",
			dependencies: &[]cyclonedx.Dependency{{Ref: "dep1"}, {Ref: "dep2"}},
			ref:          "dep1",
			expected:     &cyclonedx.Dependency{Ref: "dep1"},
		},
		{
			name:         "Dependency not found",
			dependencies: &[]cyclonedx.Dependency{{Ref: "dep1"}, {Ref: "dep2"}},
			ref:          "dep3",
			expected:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SearchDependencyEntry(tt.dependencies, tt.ref)
			assert.Equal(t, tt.expected, result, "Expected dependency entry does not match")
		})
	}
}

func TestIsDirectDependency(t *testing.T) {
	oneRootDependencies := &[]cyclonedx.Dependency{
		{Ref: "comp1", Dependencies: &[]string{"comp2", "comp3"}},
		{Ref: "comp2", Dependencies: &[]string{"comp3", "comp4"}},
	}
	twoRootDependencies := &[]cyclonedx.Dependency{
		{Ref: "comp1", Dependencies: &[]string{"comp2"}},
		{Ref: "comp3", Dependencies: &[]string{"comp4"}},
		{Ref: "comp4", Dependencies: &[]string{"comp5"}},
	}
	tests := []struct {
		name         string
		dependencies *[]cyclonedx.Dependency
		ref          string
		expected     bool
	}{
		{
			name:         "Root component",
			dependencies: oneRootDependencies,
			ref:          "comp1",
			expected:     false,
		},
		{
			name:         "Direct dependency",
			dependencies: oneRootDependencies,
			ref:          "comp2",
			expected:     true,
		},
		{
			name:         "Direct dependency (also indirect)",
			dependencies: oneRootDependencies,
			ref:          "comp3",
			expected:     true,
		},
		{
			name:         "Indirect dependency",
			dependencies: oneRootDependencies,
			ref:          "comp4",
			expected:     false,
		},
		{
			name:         "Non-existent dependency",
			dependencies: oneRootDependencies,
			ref:          "comp5",
			expected:     false,
		},
		{
			name:         "Two root components, direct dependency",
			dependencies: twoRootDependencies,
			ref:          "comp4",
			expected:     true,
		},
		{
			name:         "Two root components, indirect dependency",
			dependencies: twoRootDependencies,
			ref:          "comp5",
			expected:     false,
		},
		{
			name:         "Two root components, root component",
			dependencies: twoRootDependencies,
			ref:          "comp1",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsDirectDependency(tt.dependencies, tt.ref), "Expected direct dependency check result does not match")
		})
	}
}
