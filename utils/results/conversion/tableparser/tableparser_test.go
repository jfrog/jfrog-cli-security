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
				{Component: "ComponentB", Version: "2.0.1", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentB", Version: "2.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentC", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentD", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentE", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentF", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
			},
			expected: []formats.SbomTableRow{
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentC", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentF", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentB", Version: "2.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentB", Version: "2.0.1", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentD", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentE", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
			},
		},
		{
			name: "multiple types of components",
			components: []formats.SbomTableRow{
				{Component: "ComponentB", Version: "2.0.1", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentB", Version: "2.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentC", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentD", Version: "1.0.0", PackageType: "maven", Relation: "Transitive", Direct: false},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentE", Version: "1.0.0", PackageType: "maven", Relation: "Transitive", Direct: false},
				{Component: "ComponentF", Version: "1.0.0", PackageType: "maven", Relation: "Direct", Direct: true},
			},
			expected: []formats.SbomTableRow{
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentC", Version: "1.0.0", PackageType: "npm", Relation: "Direct", Direct: true},
				{Component: "ComponentF", Version: "1.0.0", PackageType: "maven", Relation: "Direct", Direct: true},
				{Component: "ComponentA", Version: "1.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentB", Version: "2.0.0", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentB", Version: "2.0.1", PackageType: "npm", Relation: "Transitive", Direct: false},
				{Component: "ComponentD", Version: "1.0.0", PackageType: "maven", Relation: "Transitive", Direct: false},
				{Component: "ComponentE", Version: "1.0.0", PackageType: "maven", Relation: "Transitive", Direct: false},
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
