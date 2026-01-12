package bom

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils/results"
)

func TestGetDiff(t *testing.T) {
	testCases := []struct {
		name         string
		params       SbomGeneratorParams
		sbom         *cyclonedx.BOM
		expectedSbom *cyclonedx.BOM
	}{
		{
			name: "No Diff Mode",
			params: SbomGeneratorParams{
				Target: &results.TargetResults{ScanTarget: results.ScanTarget{Target: "source bom"}},
			},
			sbom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "root", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component1", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component2", Version: "2.0"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"component1", "component2"}},
					{Ref: "component1", Dependencies: &[]string{"component2"}},
				},
			},
			expectedSbom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "root", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component1", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component2", Version: "2.0"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"component1", "component2"}},
					{Ref: "component1", Dependencies: &[]string{"component2"}},
				},
			},
		},
		{
			name: "Diff Mode, No results to compare",
			params: SbomGeneratorParams{
				Target:   &results.TargetResults{ScanTarget: results.ScanTarget{Target: "source bom"}},
				DiffMode: true,
			},
			sbom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "root", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component1", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component2", Version: "2.0"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"component1", "component2"}},
					{Ref: "component1", Dependencies: &[]string{"component2"}},
				},
			},
			expectedSbom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "root", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component1", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component2", Version: "2.0"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"component1", "component2"}},
					{Ref: "component1", Dependencies: &[]string{"component2"}},
				},
			},
		},
		{
			name: "Diff Mode, With results to compare",
			params: SbomGeneratorParams{
				Target:   &results.TargetResults{ScanTarget: results.ScanTarget{Target: "source bom"}},
				DiffMode: true,
				TargetResultToCompare: &results.TargetResults{
					ScanTarget: results.ScanTarget{Target: "bom to exclude"},
					ScaResults: &results.ScaScanResults{
						Sbom: &cyclonedx.BOM{
							Components: &[]cyclonedx.Component{
								{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "root", Version: "1.0"},
								{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component1", PackageURL: "pkg:component1", Version: "1.0"},
							},
							Dependencies: &[]cyclonedx.Dependency{
								{Ref: "root", Dependencies: &[]string{"component1"}},
							},
						},
					},
				},
			},
			sbom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "root", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component1", PackageURL: "pkg:component1", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component2", PackageURL: "pkg:component2", Version: "2.0"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"component1", "component2"}},
					{Ref: "component1", Dependencies: &[]string{"component2"}},
				},
			},
			expectedSbom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "root", Version: "1.0"},
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: "component2", PackageURL: "pkg:component2", Version: "2.0"},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"component2"}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := getDiffSbom(tc.sbom, tc.params)
			assert.Equal(t, tc.expectedSbom.Metadata, actual.Metadata, "Expected SBOM metadata do not match")
			if tc.expectedSbom.Components != nil && actual.Components != nil {
				assert.ElementsMatch(t, *tc.expectedSbom.Components, *actual.Components, "Expected SBOM components do not match")
			}
			if tc.expectedSbom.Dependencies != nil && actual.Dependencies != nil {
				assert.ElementsMatch(t, *tc.expectedSbom.Dependencies, *actual.Dependencies, "Expected SBOM dependencies do not match")
			}
		})
	}
}
