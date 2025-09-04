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
			name:         "Unknown - Nil BOM",
			bom:          nil,
			componentRef: "comp1",
			expected:     UnknownRelation,
		},
		{
			name: "Unknown - BOM with nil components",
			bom: &cyclonedx.BOM{
				Components: nil,
			},
			componentRef: "comp1",
			expected:     UnknownRelation,
		},
		{
			name: "Unknown - Component not found in BOM",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
				},
			},
			componentRef: "comp1",
			expected:     UnknownRelation,
		},
		{
			name: "Unknown - Component found but not library type",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeFile, Name: "File Component"},
				},
			},
			componentRef: "comp1",
			expected:     UnknownRelation,
		},
		{
			name: "Root - identified as root dependency",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
				},
			},
			componentRef: "root",
			expected:     RootRelation,
		},
		{
			name: "Root - identified when no dependencies exist",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
				},
			},
			componentRef: "root",
			expected:     RootRelation,
		},
		{
			name: "Root - Multiple root dependencies",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root1", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component 1"},
					{BOMRef: "root2", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component 2"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 2"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root1", Dependencies: &[]string{"comp1"}},
					{Ref: "root2", Dependencies: &[]string{"comp2"}},
				},
			},
			componentRef: "root2",
			expected:     RootRelation,
		},
		{
			name: "Root - child of metadata component",
			bom: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "project-path-sha",
						Type:   cyclonedx.ComponentTypeFile,
						Name:   "Project Source",
					},
				},
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Actual Root"},
					{BOMRef: "lib1", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 1"},
					{BOMRef: "lib2", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 2"},
					{BOMRef: "lib3", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 3"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "project-path-sha", Dependencies: &[]string{"root"}},
					{Ref: "root", Dependencies: &[]string{"lib1", "lib2"}},
					{Ref: "lib1", Dependencies: &[]string{"lib3"}},
				},
			},
			componentRef: "root",
			expected:     RootRelation,
		},
		{
			name: "Root - stand alone from metadata component",
			bom: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "project-path-sha",
						Type:   cyclonedx.ComponentTypeFile,
						Name:   "Empty Metadata",
					},
				},
				Components: &[]cyclonedx.Component{
					{BOMRef: "project-path-sha", Type: cyclonedx.ComponentTypeFile, Name: "Empty Metadata"},
					{BOMRef: "standalone", Type: cyclonedx.ComponentTypeLibrary, Name: "Standalone"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "project-path-sha", Dependencies: &[]string{"comp1"}},
				},
			},
			componentRef: "standalone",
			expected:     RootRelation,
		},
		{
			name: "Direct - child of root",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
				},
			},
			componentRef: "comp1",
			expected:     DirectRelation,
		},
		{
			name: "Direct - Component both direct and transitive",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 2"},
					{BOMRef: "shared", Type: cyclonedx.ComponentTypeLibrary, Name: "Shared Component"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1", "shared"}},
					{Ref: "comp1", Dependencies: &[]string{"comp2"}},
					{Ref: "comp2", Dependencies: &[]string{"shared"}},
				},
			},
			componentRef: "shared",
			expected:     DirectRelation,
		},
		{
			name: "Direct - identified with metadata component connection",
			bom: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "project-path-sha",
						Type:   cyclonedx.ComponentTypeFile,
						Name:   "Project Source",
					},
				},
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Actual Root"},
					{BOMRef: "lib1", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 1"},
					{BOMRef: "lib2", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 2"},
					{BOMRef: "lib3", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 3"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "project-path-sha", Dependencies: &[]string{"root"}},
					{Ref: "root", Dependencies: &[]string{"lib1", "lib2"}},
					{Ref: "lib1", Dependencies: &[]string{"lib3"}},
				},
			},
			componentRef: "lib2",
			expected:     DirectRelation,
		},
		{
			name: "Transitive - identified with metadata component connection",
			bom: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "project-path-sha",
						Type:   cyclonedx.ComponentTypeFile,
						Name:   "Project Source",
					},
				},
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Actual Root"},
					{BOMRef: "lib1", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 1"},
					{BOMRef: "lib2", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 2"},
					{BOMRef: "lib3", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 3"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "project-path-sha", Dependencies: &[]string{"root"}},
					{Ref: "root", Dependencies: &[]string{"lib1", "lib2"}},
					{Ref: "lib1", Dependencies: &[]string{"lib3"}},
				},
			},
			componentRef: "lib3",
			expected:     TransitiveRelation,
		},
		{
			name: "Transitive - child of direct dependency",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 2"},
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
			name: "Transitive - descendant of a direct dependency",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 2"},
					{BOMRef: "comp3", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 3"},
					{BOMRef: "comp4", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 4"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1", "comp2"}},
					{Ref: "comp1", Dependencies: &[]string{"comp3"}},
					{Ref: "comp2", Dependencies: &[]string{"comp3", "comp4"}},
				},
			},
			componentRef: "comp3",
			expected:     TransitiveRelation,
		},
		{
			name: "Transitive - Diamond dependency pattern",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 2"},
					{BOMRef: "comp3", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 3"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1", "comp2"}},
					{Ref: "comp1", Dependencies: &[]string{"comp3"}},
					{Ref: "comp2", Dependencies: &[]string{"comp3"}},
				},
			},
			componentRef: "comp3",
			expected:     TransitiveRelation,
		},
		{
			name: "Transitive - Circular dependency handling",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 2"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
					{Ref: "comp1", Dependencies: &[]string{"comp2"}},
					{Ref: "comp2", Dependencies: &[]string{"comp1"}}, // Circular reference
				},
			},
			componentRef: "comp2",
			expected:     TransitiveRelation,
		},
		{
			name: "Root - skip generic root, actual roots are dependencies",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "generic:root", Type: cyclonedx.ComponentTypeLibrary, Name: "Generic Root"},
					{BOMRef: "actual-root1", Type: cyclonedx.ComponentTypeLibrary, Name: "Actual Root 1"},
					{BOMRef: "actual-root2", Type: cyclonedx.ComponentTypeLibrary, Name: "Actual Root 2"},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "generic:root", Dependencies: &[]string{"actual-root1", "actual-root2"}},
					{Ref: "actual-root1", Dependencies: &[]string{"comp1"}},
					{Ref: "actual-root2", Dependencies: &[]string{}},
				},
			},
			componentRef: "actual-root1",
			expected:     RootRelation,
		},
		{
			name: "Direct - both direct and transitive in diff roots",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root1", Type: cyclonedx.ComponentTypeLibrary, Name: "Root 1"},
					{BOMRef: "root2", Type: cyclonedx.ComponentTypeLibrary, Name: "Root 2"},
					{BOMRef: "intermediate1", Type: cyclonedx.ComponentTypeLibrary, Name: "Intermediate 1"},
					{BOMRef: "intermediate2", Type: cyclonedx.ComponentTypeLibrary, Name: "Intermediate 2"},
					{BOMRef: "target", Type: cyclonedx.ComponentTypeLibrary, Name: "Target Component"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root1", Dependencies: &[]string{"intermediate1"}},
					{Ref: "root2", Dependencies: &[]string{"target"}},
					{Ref: "intermediate1", Dependencies: &[]string{"intermediate2"}},
					{Ref: "intermediate2", Dependencies: &[]string{"target"}},
				},
			},
			componentRef: "target",
			expected:     DirectRelation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetComponentRelation(tt.bom, tt.componentRef, true)
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
		{
			name: "file with special characters and spaces",
			path: "/path/to/file with spaces.txt",
			expected: cyclonedx.Component{
				BOMRef: "b24231d78bc53506b3a74b40cf0e1e99",
				Type:   cyclonedx.ComponentTypeFile,
				Name:   "/path/to/file with spaces.txt",
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

func TestSearchParents(t *testing.T) {
	tests := []struct {
		name         string
		ref          string
		dependencies []cyclonedx.Dependency
		components   []cyclonedx.Component
		expected     []cyclonedx.Component
	}{
		{
			name: "Search No parent match",
			ref:  "compX",
			components: []cyclonedx.Component{
				{BOMRef: "root"}, {BOMRef: "comp1"}, {BOMRef: "comp2"}, {BOMRef: "comp3"},
			},
			dependencies: []cyclonedx.Dependency{
				{Ref: "root", Dependencies: &[]string{"comp1", "comp2"}},
				{Ref: "comp1", Dependencies: &[]string{"comp3"}},
			},
			expected: []cyclonedx.Component{},
		},
		{
			name: "Search No dependencies",
			ref:  "comp2",
			components: []cyclonedx.Component{
				{BOMRef: "root"}, {BOMRef: "comp1"}, {BOMRef: "comp2"}, {BOMRef: "comp3"},
			},
			expected: []cyclonedx.Component{},
		},
		{
			name:       "Search Root no parent",
			ref:        "root",
			components: []cyclonedx.Component{{BOMRef: "root"}},
			dependencies: []cyclonedx.Dependency{
				{Ref: "root", Dependencies: &[]string{"comp1", "comp2"}},
			},
			expected: []cyclonedx.Component{},
		},
		{
			name: "Single parent match",
			ref:  "comp3",
			components: []cyclonedx.Component{
				{BOMRef: "root"}, {BOMRef: "comp1"}, {BOMRef: "comp2"}, {BOMRef: "comp3"},
			},
			dependencies: []cyclonedx.Dependency{
				{Ref: "root", Dependencies: &[]string{"comp1", "comp2"}},
				{Ref: "comp1", Dependencies: &[]string{"comp3"}},
			},
			expected: []cyclonedx.Component{{BOMRef: "comp1"}},
		},
		{
			name: "Multiple parent matches",
			ref:  "comp1",
			components: []cyclonedx.Component{
				{BOMRef: "root"}, {BOMRef: "comp1"}, {BOMRef: "comp2"}, {BOMRef: "comp3"},
			},
			dependencies: []cyclonedx.Dependency{
				{Ref: "root", Dependencies: &[]string{"comp1", "comp2", "comp3"}},
				{Ref: "comp1", Dependencies: &[]string{"comp3"}},
				{Ref: "comp2", Dependencies: &[]string{"comp1"}},
			},
			expected: []cyclonedx.Component{{BOMRef: "root"}, {BOMRef: "comp2"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SearchParents(tt.ref, tt.components, tt.dependencies...)
			assert.ElementsMatch(t, tt.expected, result, "Expected parent components do not match")
		})
	}
}

func TestGetRootDependenciesEntries(t *testing.T) {
	tests := []struct {
		name     string
		bom      *cyclonedx.BOM
		skipRoot bool
		expected []cyclonedx.Dependency
	}{
		{
			name: "Empty BOM",
			bom: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "file-root",
						Type:   cyclonedx.ComponentTypeFile,
					},
				},
			},
			expected: []cyclonedx.Dependency{},
		},
		{
			name: "No components",
			bom: &cyclonedx.BOM{
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"dep1"}},
				},
			},
			expected: []cyclonedx.Dependency{},
		},
		{
			name: "BuildInfo - Single root dependency",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "dep1", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 1"},
					{BOMRef: "dep2", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 2"},
					{BOMRef: "dep3", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 3"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}},
					{Ref: "dep2", Dependencies: &[]string{"dep3", "dep4"}},
					{Ref: "dep4", Dependencies: &[]string{"dep5"}},
				},
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}}},
		},
		{
			name: "XrayLib - Single root dependency",
			bom: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "file-root",
						Type:   cyclonedx.ComponentTypeFile,
					},
				},
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "dep1", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 1"},
					{BOMRef: "dep2", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 2"},
					{BOMRef: "dep3", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 3"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "file-root", Dependencies: &[]string{"root"}},
					{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}},
					{Ref: "dep2", Dependencies: &[]string{"dep3", "dep4"}},
					{Ref: "dep4", Dependencies: &[]string{"dep5"}},
				},
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}}},
		},
		{
			name: "BuildInfo - Multiple root dependencies",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component"},
					{BOMRef: "root2", Type: cyclonedx.ComponentTypeLibrary, Name: "Root Component 2"},
					{BOMRef: "dep1", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 1"},
					{BOMRef: "dep2", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 2"},
					{BOMRef: "dep3", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 3"},
					{BOMRef: "dep4", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 4"},
					{BOMRef: "dep5", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 5"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}},
					{Ref: "dep2", Dependencies: &[]string{"dep3", "dep4"}},
					{Ref: "root2", Dependencies: &[]string{"dep4", "dep5"}},
					{Ref: "dep4", Dependencies: &[]string{"dep5"}},
				},
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{
				{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}},
				{Ref: "root2", Dependencies: &[]string{"dep4", "dep5"}},
			},
		},
		{
			name: "BuildInfo - generic root with skipDefaultRoot=true",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "generic:root", Type: cyclonedx.ComponentTypeLibrary, Name: "Generic Root"},
					{BOMRef: "actual_root1", Type: cyclonedx.ComponentTypeLibrary, Name: "Actual Root 1"},
					{BOMRef: "actual_root2", Type: cyclonedx.ComponentTypeLibrary, Name: "Actual Root 2"},
					{BOMRef: "dep1", Type: cyclonedx.ComponentTypeLibrary, Name: "Dep 1"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "generic:root", Dependencies: &[]string{"actual_root1", "actual_root2"}},
					{Ref: "actual_root1", Dependencies: &[]string{"dep1"}},
				},
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{
				{Ref: "actual_root1", Dependencies: &[]string{"dep1"}},
				{Ref: "actual_root2"},
				{Ref: "generic:root", Dependencies: &[]string{"actual_root1", "actual_root2"}},
			},
		},
		{
			name: "BuildInfo - generic root with skipDefaultRoot=false",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "generic:root", Type: cyclonedx.ComponentTypeLibrary, Name: "Generic Root"},
					{BOMRef: "not_actual_root1", Type: cyclonedx.ComponentTypeLibrary, Name: "Not Actual Root 1"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "generic:root", Dependencies: &[]string{"not_actual_root1"}},
					{Ref: "not_actual_root1", Dependencies: &[]string{}},
				},
			},
			skipRoot: false,
			expected: []cyclonedx.Dependency{
				{Ref: "generic:root", Dependencies: &[]string{"not_actual_root1"}},
			},
		},
		{
			name: "XrayLib - Multiple root dependencies",
			bom: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "metadata:comp",
						Type:   cyclonedx.ComponentTypeFile,
						Name:   "Project Root",
					},
				},
				Components: &[]cyclonedx.Component{
					{BOMRef: "metadata:comp", Type: cyclonedx.ComponentTypeFile, Name: "Project Root"},
					{BOMRef: "lib1", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 1"},
					{BOMRef: "lib2", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 2"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "metadata:comp", Dependencies: &[]string{"lib1", "lib2"}},
				},
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{{Ref: "lib1"}, {Ref: "lib2"}},
		},
		{
			name: "No root found - fallback to library components",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "lib1", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 1"},
					{BOMRef: "lib2", Type: cyclonedx.ComponentTypeLibrary, Name: "Library 2"},
					{BOMRef: "file1", Type: cyclonedx.ComponentTypeFile, Name: "File 1"},
				},
				Dependencies: &[]cyclonedx.Dependency{},
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{
				{Ref: "lib1"},
				{Ref: "lib2"},
			},
		},
		{
			name: "XrayLib - Circular dependencies",
			bom: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "metadata:comp",
						Type:   cyclonedx.ComponentTypeFile,
						Name:   "Project Root",
					},
				},
				Components: &[]cyclonedx.Component{
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 2"},
					{BOMRef: "comp3", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 3"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "metadata:comp", Dependencies: &[]string{"comp2"}},
					{Ref: "comp1", Dependencies: &[]string{"comp2"}},
					{Ref: "comp2", Dependencies: &[]string{"comp3"}},
					{Ref: "comp3", Dependencies: &[]string{"comp1"}},
				},
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{{Ref: "comp2", Dependencies: &[]string{"comp3"}}},
		},
		{
			name: "BuildInfo - Circular dependencies - no clear root",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 1"},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 2"},
					{BOMRef: "comp3", Type: cyclonedx.ComponentTypeLibrary, Name: "Component 3"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "comp1", Dependencies: &[]string{"comp2"}},
					{Ref: "comp2", Dependencies: &[]string{"comp3"}},
					{Ref: "comp3", Dependencies: &[]string{"comp1"}},
				},
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{}, // All components are in dependedRefs, none becomes root
		},
		{
			name: "BuildInfo - fallback scenario - only standalone components",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "standalone1", Type: cyclonedx.ComponentTypeLibrary, Name: "Standalone Library 1"},
					{BOMRef: "standalone2", Type: cyclonedx.ComponentTypeLibrary, Name: "Standalone Library 2"},
					{BOMRef: "file1", Type: cyclonedx.ComponentTypeFile, Name: "File Component"},
				},
				Dependencies: &[]cyclonedx.Dependency{}, // No dependencies, so fallback applies
			},
			skipRoot: true,
			expected: []cyclonedx.Dependency{
				{Ref: "standalone1"},
				{Ref: "standalone2"},
				// file1 is not included because it's not a library type
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRootDependenciesEntries(tt.bom, tt.skipRoot)
			assert.ElementsMatch(t, tt.expected, result, "Expected root dependencies do not match")
		})
	}
}

func TestAttachLicenseToComponent(t *testing.T) {
	tests := []struct {
		name     string
		startLic []*cyclonedx.LicenseChoice
		license  cyclonedx.LicenseChoice
		expected []string
	}{
		{
			name:     "Add new license",
			startLic: nil,
			license:  cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: "MIT"}},
			expected: []string{"MIT"},
		},
		{
			name:     "Add duplicate license",
			startLic: []*cyclonedx.LicenseChoice{{License: &cyclonedx.License{ID: "MIT"}}},
			license:  cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: "MIT"}},
			expected: []string{"MIT"},
		},
		{
			name:     "Add second license",
			startLic: []*cyclonedx.LicenseChoice{{License: &cyclonedx.License{ID: "MIT"}}},
			license:  cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: "Apache-2.0"}},
			expected: []string{"MIT", "Apache-2.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := cyclonedx.Component{Name: "comp1"}
			if tt.startLic != nil {
				lics := cyclonedx.Licenses{}
				for _, l := range tt.startLic {
					lics = append(lics, *l)
				}
				comp.Licenses = &lics
			}
			AttachLicenseToComponent(&comp, tt.license)
			var got []string
			if comp.Licenses != nil {
				for _, l := range *comp.Licenses {
					got = append(got, l.License.ID)
				}
			}
			assert.ElementsMatch(t, tt.expected, got)
		})
	}
}

func TestAttachComponentAffectsAndHasImpactedAffects(t *testing.T) {
	tests := []struct {
		name      string
		startA    *[]cyclonedx.Affects
		comp      cyclonedx.Component
		expectedN int
		expectedB bool
	}{
		{
			name:      "Add new affect",
			startA:    nil,
			comp:      cyclonedx.Component{BOMRef: "comp1"},
			expectedN: 1,
			expectedB: true,
		},
		{
			name:      "Add duplicate affect",
			startA:    &[]cyclonedx.Affects{{Ref: "comp1"}},
			comp:      cyclonedx.Component{BOMRef: "comp1"},
			expectedN: 1,
			expectedB: true,
		},
		{
			name:      "Add second affect",
			startA:    &[]cyclonedx.Affects{{Ref: "comp1"}},
			comp:      cyclonedx.Component{BOMRef: "comp2"},
			expectedN: 2,
			expectedB: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := &cyclonedx.Vulnerability{ID: "VULN-1", Affects: tt.startA}
			AttachComponentAffects(vuln, tt.comp, func(c cyclonedx.Component) cyclonedx.Affects {
				return cyclonedx.Affects{Ref: c.BOMRef}
			})
			assert.Equal(t, tt.expectedN, len(*vuln.Affects))
			assert.Equal(t, tt.expectedB, HasImpactedAffects(*vuln, tt.comp))
		})
	}
}

func TestCreateScaImpactedAffects(t *testing.T) {
	tests := []struct {
		name          string
		comp          cyclonedx.Component
		fixed         []string
		expAffected   string
		expNotAffect1 string
		expNotAffect2 string
	}{
		{
			name:          "Maven with 2 fixed",
			comp:          cyclonedx.Component{BOMRef: "comp1", PackageURL: "pkg:maven/group/artifact@1.2.3"},
			fixed:         []string{"2.0.0", "3.0.0"},
			expAffected:   "1.2.3",
			expNotAffect1: "2.0.0",
			expNotAffect2: "3.0.0",
		},
		{
			name:        "No fixed",
			comp:        cyclonedx.Component{BOMRef: "comp2", PackageURL: "pkg:docker/library/nginx@1.0.0"},
			fixed:       nil,
			expAffected: "1.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			affect := CreateScaImpactedAffects(tt.comp, tt.fixed)
			assert.Equal(t, tt.comp.BOMRef, affect.Ref)
			assert.NotNil(t, affect.Range)
			assert.Equal(t, tt.expAffected, (*affect.Range)[0].Version)
			assert.Equal(t, cyclonedx.VulnerabilityStatusAffected, (*affect.Range)[0].Status)
			if len(tt.fixed) > 0 {
				assert.Equal(t, tt.expNotAffect1, (*affect.Range)[1].Version)
				assert.Equal(t, cyclonedx.VulnerabilityStatusNotAffected, (*affect.Range)[1].Status)
				assert.Equal(t, tt.expNotAffect2, (*affect.Range)[2].Version)
			}
		})
	}
}

func TestGetOrCreateScaIssue(t *testing.T) {
	tests := []struct {
		name   string
		params CdxVulnerabilityParams
		id     string
	}{
		{
			name:   "Create new issue",
			params: CdxVulnerabilityParams{Ref: "comp1", ID: "VULN-1", Details: "details", Description: "desc", Service: &cyclonedx.Service{Name: "svc"}, CWE: []string{"CWE-79"}, References: []string{"https://ref"}, Ratings: []cyclonedx.VulnerabilityRating{{Severity: cyclonedx.SeverityHigh}}},
			id:     "VULN-1",
		},
		{
			name:   "Create another issue",
			params: CdxVulnerabilityParams{Ref: "comp2", ID: "VULN-2", Details: "d2", Description: "desc2", Service: &cyclonedx.Service{Name: "svc2"}, CWE: []string{"CWE-89"}, References: []string{"https://ref2"}, Ratings: []cyclonedx.VulnerabilityRating{{Severity: cyclonedx.SeverityCritical}}},
			id:     "VULN-2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bom := cyclonedx.NewBOM()
			vuln := GetOrCreateScaIssue(bom, tt.params)
			assert.NotNil(t, vuln)
			assert.Equal(t, tt.id, vuln.ID)
			// Should return same vuln if called again
			vuln2 := GetOrCreateScaIssue(bom, tt.params)
			assert.Equal(t, vuln, vuln2)
		})
	}
}

func TestSearchVulnerabilityByRef(t *testing.T) {
	tests := []struct {
		name      string
		params    []CdxVulnerabilityParams
		searchRef string
		exists    bool
	}{
		{
			name: "Find existing vuln",
			params: []CdxVulnerabilityParams{
				{Ref: "VULN-1", ID: "VULN-1-ID"},
				{Ref: "VULN-2", ID: "VULN-2-ID"},
			},
			searchRef: "VULN-2",
			exists:    true,
		},
		{
			name: "Not found vuln",
			params: []CdxVulnerabilityParams{
				{Ref: "VULN-1", ID: "VULN-1-ID"},
			},
			searchRef: "VULN-3",
			exists:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bom := cyclonedx.NewBOM()
			for _, p := range tt.params {
				GetOrCreateScaIssue(bom, p)
			}
			found := SearchVulnerabilityByRef(bom, tt.searchRef)
			if tt.exists {
				if assert.NotNil(t, found) {
					assert.Equal(t, tt.searchRef, found.BOMRef)
				}
			} else {
				assert.Nil(t, found)
			}
		})
	}
}

func TestCreateBaseVulnerability(t *testing.T) {
	tests := []struct {
		name   string
		params CdxVulnerabilityParams
		expID  string
		expSvc string
		expCWE []int
		expSev cyclonedx.Severity
		expRef string
	}{
		{
			name:   "Critical vuln",
			params: CdxVulnerabilityParams{Ref: "comp1", ID: "VULN-2", Details: "details2", Description: "desc2", Service: &cyclonedx.Service{Name: "svc2"}, CWE: []string{"CWE-89"}, References: []string{"https://ref2"}, Ratings: []cyclonedx.VulnerabilityRating{{Severity: cyclonedx.SeverityCritical}}},
			expID:  "VULN-2",
			expSvc: "svc2",
			expCWE: []int{89},
			expSev: cyclonedx.SeverityCritical,
			expRef: "https://ref2",
		},
		{
			name:   "No CWE vuln",
			params: CdxVulnerabilityParams{Ref: "comp2", ID: "VULN-3", Details: "d3", Description: "desc3", Service: &cyclonedx.Service{Name: "svc3"}, References: []string{"https://ref3"}, Ratings: []cyclonedx.VulnerabilityRating{{Severity: cyclonedx.SeverityLow}}},
			expID:  "VULN-3",
			expSvc: "svc3",
			expSev: cyclonedx.SeverityLow,
			expRef: "https://ref3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := CreateBaseVulnerability(tt.params)
			assert.Equal(t, tt.expID, vuln.ID)
			if vuln.Source != nil {
				assert.Equal(t, tt.expSvc, vuln.Source.Name)
			}
			if len(tt.expCWE) > 0 {
				assert.NotNil(t, vuln.CWEs)
				assert.ElementsMatch(t, *vuln.CWEs, tt.expCWE)
			} else {
				assert.Nil(t, vuln.CWEs)
			}
			if vuln.Ratings != nil {
				assert.Equal(t, tt.expSev, (*vuln.Ratings)[0].Severity)
			}
			if vuln.References != nil {
				assert.Equal(t, tt.expRef, (*vuln.References)[0].Source.URL)
			}
		})
	}
}

func TestUpdateOrAppendVulnerabilitiesRatingsAndSearchRating(t *testing.T) {
	vulnerability := &cyclonedx.Vulnerability{
		Ratings: &[]cyclonedx.VulnerabilityRating{
			{Severity: cyclonedx.SeverityHigh, Method: cyclonedx.ScoringMethodCVSSv3},
			{Severity: cyclonedx.SeverityMedium, Method: cyclonedx.ScoringMethodCVSSv2},
		},
	}
	tests := []struct {
		name   string
		rating cyclonedx.VulnerabilityRating
		isNew  bool
	}{
		{
			name:   "Update existing",
			rating: cyclonedx.VulnerabilityRating{Severity: cyclonedx.SeverityLow, Method: cyclonedx.ScoringMethodCVSSv3},
		},
		{
			name:   "Add new rating",
			rating: cyclonedx.VulnerabilityRating{Severity: cyclonedx.SeverityCritical, Method: cyclonedx.ScoringMethodCVSSv4, Source: &cyclonedx.Source{Name: "New Source"}},
			isNew:  true,
		},
		{
			name:   "Add new source, same method",
			rating: cyclonedx.VulnerabilityRating{Severity: cyclonedx.SeverityCritical, Method: cyclonedx.ScoringMethodCVSSv3, Source: &cyclonedx.Source{Name: "New Source"}},
			isNew:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.isNew {
				assert.Nil(t, SearchRating(vulnerability.Ratings, tt.rating.Method, tt.rating.Source), "Rating should not be found before update")
			} else {
				existing := SearchRating(vulnerability.Ratings, tt.rating.Method, tt.rating.Source)
				assert.NotNil(t, existing, "Rating should be found before update")
				assert.NotEqual(t, tt.rating, existing, "Rating should not match before update")
			}
			updateOrAppendVulnerabilitiesRatings(vulnerability, tt.rating)
			actual := SearchRating(vulnerability.Ratings, tt.rating.Method, tt.rating.Source)
			assert.NotNil(t, actual, "Rating should not be found before update")
			assert.Equal(t, tt.rating, *actual, "Rating should match after update")
		})
	}
}

func TestExclude(t *testing.T) {
	bom := cyclonedx.NewBOM()
	bom.Components = &[]cyclonedx.Component{
		{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary},
		{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary},
		{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary},
		{BOMRef: "comp3", Type: cyclonedx.ComponentTypeLibrary},
	}
	bom.Dependencies = &[]cyclonedx.Dependency{
		{Ref: "root", Dependencies: &[]string{"comp1", "comp3"}},
		{Ref: "comp1", Dependencies: &[]string{"comp2", "comp3"}},
	}
	tests := []struct {
		name     string
		bom      cyclonedx.BOM
		exclude  []cyclonedx.Component
		expected *cyclonedx.BOM
	}{
		{
			name:    "Exclude from empty BOM",
			exclude: []cyclonedx.Component{{BOMRef: "exclude-me"}},
			bom: cyclonedx.BOM{
				Components: &[]cyclonedx.Component{},
			},
			expected: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{},
			},
		},
		{
			name:    "Do not exclude different string",
			exclude: []cyclonedx.Component{{BOMRef: "exclude-me"}},
			bom:     *bom,
			expected: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary},
					{BOMRef: "comp3", Type: cyclonedx.ComponentTypeLibrary},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1", "comp3"}},
					{Ref: "comp1", Dependencies: &[]string{"comp2", "comp3"}},
				},
			},
		},
		{
			name:    "Exclude single component with transitive dependencies",
			exclude: []cyclonedx.Component{{BOMRef: "comp1"}},
			bom:     *bom,
			expected: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary},
					{BOMRef: "comp3", Type: cyclonedx.ComponentTypeLibrary},
				},
				Dependencies: &[]cyclonedx.Dependency{{Ref: "root", Dependencies: &[]string{"comp3"}}},
			},
		},
		{
			name:    "Exclude single component existing both directly and transitively",
			exclude: []cyclonedx.Component{{BOMRef: "comp3"}},
			bom:     *bom,
			expected: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary},
					{BOMRef: "comp2", Type: cyclonedx.ComponentTypeLibrary},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
					{Ref: "comp1", Dependencies: &[]string{"comp2"}},
				},
			},
		},
		{
			name:    "Exclude multiple components",
			exclude: []cyclonedx.Component{{BOMRef: "comp2"}, {BOMRef: "comp3"}, {BOMRef: "exclude-me"}},
			bom:     *bom,
			expected: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{BOMRef: "root", Type: cyclonedx.ComponentTypeLibrary},
					{BOMRef: "comp1", Type: cyclonedx.ComponentTypeLibrary},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"comp1"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Exclude(tt.bom, tt.exclude...)
			if tt.expected.Components == nil {
				assert.Nil(t, result.Components, "Expected components to be nil after exclusion")
				assert.Nil(t, result.Dependencies, "Expected dependencies to be nil after exclusion")
				return
			} else if len(*tt.expected.Components) == 0 {
				assert.NotNil(t, result.Components, "Expected components to not be nil after exclusion")
				assert.Len(t, *result.Components, 0, "Expected components to be empty after exclusion")
				assert.Nil(t, result.Dependencies, "Expected dependencies to be nil after exclusion")
				return
			}
			assert.ElementsMatch(t, *tt.expected.Components, *result.Components, "Expected exclude result does not match")

			if tt.bom.Dependencies == nil {
				assert.Nil(t, result.Dependencies, "Expected dependencies to be nil after exclusion")
			} else {
				assert.ElementsMatch(t, *tt.expected.Dependencies, *result.Dependencies, "Expected exclude dependencies do not match")
			}
		})
	}
}
