package tableparser

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/stretchr/testify/assert"
)

func TestSortSbom(t *testing.T) {
	tests := []struct {
		name       string
		components []formats.SbomTableRow
		expected   []formats.SbomTableRow
	}{
		{
			name: "one type of component",
			components: []formats.SbomTableRow{
				{Component: "ComponentB", Version: "2.0.1", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentB", Version: "2.0.0", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentC", Version: "1.0.0", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "Root", Version: "1.0.0", PackageType: "npm", Relation: "Root", RelationPriority: 3},
				{Component: "ComponentD", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentE", Version: "", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentF", Version: "", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
			},
			expected: []formats.SbomTableRow{
				{Component: "Root", Version: "1.0.0", PackageType: "npm", Relation: "Root", RelationPriority: 3},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentC", Version: "1.0.0", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentF", Version: "", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentB", Version: "2.0.1", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentB", Version: "2.0.0", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentD", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentE", Version: "", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
			},
		},
		{
			name: "multiple types of components",
			components: []formats.SbomTableRow{
				{Component: "ComponentB", Version: "2.0.1", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentB", Version: "2.0.0", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentC", Version: "1.0.0", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentD", Version: "1.0.0", PackageType: "maven", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentE", Version: "1.0.0", PackageType: "maven", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentF", Version: "1.0.0", PackageType: "maven", Relation: "Direct", RelationPriority: 2},
			},
			expected: []formats.SbomTableRow{
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentC", Version: "1.0.0", PackageType: "npm", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentF", Version: "1.0.0", PackageType: "maven", Relation: "Direct", RelationPriority: 2},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentB", Version: "2.0.1", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentB", Version: "2.0.0", PackageType: "npm", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentD", Version: "1.0.0", PackageType: "maven", Relation: "Transitive", RelationPriority: 1},
				{Component: "ComponentE", Version: "1.0.0", PackageType: "maven", Relation: "Transitive", RelationPriority: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortSbom(tt.components)
			assert.Equal(t, tt.expected, tt.components)
		})
	}
}
