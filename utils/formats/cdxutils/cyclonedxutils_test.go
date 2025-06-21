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

func TestGetComponentRelation(t *testing.T) {
	tests := []struct {
		name         string
		bom          *cyclonedx.BOM
		componentRef string
		expected     ComponentRelation
	}{
		{
			name: "Root component",
			bom: &cyclonedx.BOM{
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
				},
			},
			componentRef: "root",
			expected:     RootRelation,
		},
		{
			name: "Root component with no dependencies",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: "library", Name: "Root Component"},
					{BOMRef: "comp1", Type: "library", Name: "Component 1"},
				},
			},
			componentRef: "root",
			expected:     RootRelation,
		},
		{
			name: "Direct dependency",
			bom: &cyclonedx.BOM{
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
					{Ref: "comp1", Dependencies: &[]string{"comp2"}},
				},
			},
			componentRef: "comp1",
			expected:     DirectRelation,
		},
		{
			name: "Transitive dependency",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "comp2", Name: "Component 2"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
					{Ref: "comp1", Dependencies: &[]string{"comp2"}},
				},
			},
			componentRef: "comp2",
			expected:     TransitiveRelation,
		},
		{
			name: "Unknown relation",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Name: "Root Component"},
					{BOMRef: "comp1", Name: "Component 1"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
				},
			},
			componentRef: "comp2",
			expected:     UnknownRelation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetComponentRelation(tt.bom, tt.componentRef)
			assert.Equal(t, tt.expected, result, "Expected component relation does not match")
		})
	}
}

func TestCreateFileOrDirComponent(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected cyclonedx.Component
	}{
		{
			name: "File component",
			path: "/path/to/file.txt",
			expected: cyclonedx.Component{
				BOMRef: "f5aa4f4f1380b71acc56750e9f8ff825",
				Type:   cyclonedx.ComponentTypeFile,
				Name:   "/path/to/file.txt",
			},
		},
		{
			name: "Directory component",
			path: "/path/to/directory/",
			expected: cyclonedx.Component{
				BOMRef: "0b02f93c6b83cab52b1024d1aebad31c",
				Type:   cyclonedx.ComponentTypeFile,
				Name:   "/path/to/directory/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CreateFileOrDirComponent(tt.path)
			assert.Equal(t, tt.expected, result, "Expected component does not match")
		})
	}
}

func TestSearchComponentByRef(t *testing.T) {
	tests := []struct {
		name       string
		components *[]cyclonedx.Component
		ref        string
		expected   *cyclonedx.Component
	}{
		{
			name:       "Find existing component",
			components: &[]cyclonedx.Component{{BOMRef: "comp1"}, {BOMRef: "comp2"}},
			ref:        "comp1",
			expected:   &cyclonedx.Component{BOMRef: "comp1"},
		},
		{
			name:       "Component not found",
			components: &[]cyclonedx.Component{{BOMRef: "comp1"}, {BOMRef: "comp2"}},
			ref:        "comp3",
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SearchComponentByRef(tt.components, tt.ref)
			assert.Equal(t, tt.expected, result, "Expected component does not match")
		})
	}
}

func TestGetDirectDependencies(t *testing.T) {
	dependencies := &[]cyclonedx.Dependency{
		{Ref: "comp1", Dependencies: &[]string{"comp2", "comp3"}},
		{Ref: "comp2", Dependencies: &[]string{"comp3"}},
		{Ref: "comp3", Dependencies: &[]string{}},
	}
	tests := []struct {
		name     string
		ref      string
		expected []string
	}{
		{
			name:     "Direct dependencies of comp1",
			ref:      "comp1",
			expected: []string{"comp2", "comp3"},
		},
		{
			name:     "Direct dependencies of comp2",
			ref:      "comp2",
			expected: []string{"comp3"},
		},
		{
			name:     "Direct dependencies of comp3",
			ref:      "comp3",
			expected: []string{},
		},
		{
			name:     "Non-existent component",
			ref:      "comp4",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDirectDependencies(dependencies, tt.ref)
			assert.Equal(t, tt.expected, result, "Expected direct dependencies do not match")
		})
	}
}

func TestGetRootDependenciesEntries(t *testing.T) {
	tests := []struct {
		name     string
		bom      *cyclonedx.BOM
		expected []cyclonedx.Dependency
	}{
		{
			name:     "No dependencies",
			expected: []cyclonedx.Dependency{},
		},
		{
			name: "Single root dependency",
			bom: &cyclonedx.BOM{
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}},
					{Ref: "dep2", Dependencies: &[]string{"dep3", "dep4"}},
					{Ref: "dep4", Dependencies: &[]string{"dep5"}},
				},
			},
			expected: []cyclonedx.Dependency{{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}}},
		},
		{
			name: "Multiple root dependencies",
			bom: &cyclonedx.BOM{
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}},
					{Ref: "dep2", Dependencies: &[]string{"dep3", "dep4"}},
					{Ref: "root2", Dependencies: &[]string{"dep4", "dep5"}},
					{Ref: "dep4", Dependencies: &[]string{"dep5"}},
				},
			},
			expected: []cyclonedx.Dependency{{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}}, {Ref: "root2", Dependencies: &[]string{"dep4", "dep5"}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRootDependenciesEntries(tt.bom)
			assert.ElementsMatch(t, tt.expected, result, "Expected root dependencies do not match")
		})
	}
}
