package remediation

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
)

func TestMatchVulnerabilityToRemediationOptions(t *testing.T) {
	tests := []struct {
		name                     string
		bom                      *cyclonedx.BOM
		vulnerability            *cyclonedx.Vulnerability
		remediationOptions       utils.CveRemediationResponse
		expectedAffectedVersions []cyclonedx.AffectedVersions
		description              string
	}{
		{
			name: "Vulnerability with no affects",
			bom:  &cyclonedx.BOM{},
			vulnerability: &cyclonedx.Vulnerability{
				ID:      "CVE-2023-1234",
				Affects: nil,
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.1",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should skip processing when vulnerability has no affects",
		},
		{
			name: "Vulnerability with empty affects",
			bom:  &cyclonedx.BOM{},
			vulnerability: &cyclonedx.Vulnerability{
				ID:      "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.1",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should skip processing when vulnerability has empty affects",
		},
		{
			name: "No remediation options for vulnerability",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "test-component-ref",
						Name:    "test-component",
						Version: "1.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-9999",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "test-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.1",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should skip processing when no remediation options found for vulnerability",
		},
		{
			name: "Component not found in BOM",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "other-component-ref",
						Name:    "other-component",
						Version: "2.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "missing-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "missing-component",
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.1",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should skip processing when affected component is not found in BOM",
		},
		{
			name: "Successful remediation with matching component",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "test-component-ref",
						Name:    "test-component",
						Version: "1.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "test-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.1",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: []cyclonedx.AffectedVersions{
				{
					Version: "1.0.1",
					Status:  cyclonedx.VulnerabilityStatusNotAffected,
				},
			},
			description: "Should successfully add fixed version when component matches",
		},
		{
			name: "Multiple remediation steps for same component",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "test-component-ref",
						Name:    "test-component",
						Version: "1.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "test-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.1",
									},
								},
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.2",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: []cyclonedx.AffectedVersions{
				{
					Version: "1.0.1",
					Status:  cyclonedx.VulnerabilityStatusNotAffected,
				},
				{
					Version: "1.0.2",
					Status:  cyclonedx.VulnerabilityStatusNotAffected,
				},
			},
			description: "Should add multiple fixed versions when multiple remediation steps exist",
		},
		{
			name: "Remediation with non-InLock type should be ignored",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "test-component-ref",
						Name:    "test-component",
						Version: "1.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "test-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.DirectDependency, // Not InLock
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.1",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should ignore remediation options that are not InLock type",
		},
		{
			name: "Remediation with NoFixVersion step type should be ignored",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "test-component-ref",
						Name:    "test-component",
						Version: "1.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "test-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.NoFixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should ignore steps with NoFixVersion step type",
		},
		{
			name: "Remediation with PackageNotFound step type should be ignored",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "test-component-ref",
						Name:    "test-component",
						Version: "1.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "test-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.PackageNotFound,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "1.0.0",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should ignore steps with PackageNotFound step type",
		},
		{
			name: "Component name mismatch should be ignored",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "test-component-ref",
						Name:    "test-component",
						Version: "1.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "test-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "different-component", // Name mismatch
										Version: "1.0.0",
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "1.0.1",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should ignore remediation steps when component name doesn't match",
		},
		{
			name: "Component version mismatch should be ignored",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "test-component-ref",
						Name:    "test-component",
						Version: "1.0.0",
					},
				},
			},
			vulnerability: &cyclonedx.Vulnerability{
				ID: "CVE-2023-1234",
				Affects: &[]cyclonedx.Affects{
					{
						Ref: "test-component-ref",
					},
				},
			},
			remediationOptions: utils.CveRemediationResponse{
				"CVE-2023-1234": []utils.Option{
					{
						Type: utils.InLock,
						Steps: map[utils.FixStrategy][]utils.OptionStep{
							utils.QuickestFixStrategy: {
								{
									StepType: utils.FixVersion,
									PkgVersion: utils.PackageVersionKey{
										Name:    "test-component",
										Version: "2.0.0", // Version mismatch
									},
									UpgradeTo: utils.PackageVersionKey{
										Version: "2.0.1",
									},
								},
							},
						},
					},
				},
			},
			expectedAffectedVersions: nil,
			description:              "Should ignore remediation steps when component version doesn't match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy of the vulnerability to avoid modifying the original
			vulnCopy := *tt.vulnerability
			if tt.vulnerability.Affects != nil {
				affects := make([]cyclonedx.Affects, len(*tt.vulnerability.Affects))
				copy(affects, *tt.vulnerability.Affects)
				vulnCopy.Affects = &affects
			}

			// Execute the function
			matchVulnerabilityToRemediationOptions(tt.bom, &vulnCopy, tt.remediationOptions, utils.QuickestFixStrategy)

			// For most test cases, check if affects remain unchanged (no fixed versions added)
			if tt.expectedAffectedVersions == nil {
				if vulnCopy.Affects != nil {
					for _, affect := range *vulnCopy.Affects {
						if affect.Range != nil {
							for _, affectedVersion := range *affect.Range {
								if affectedVersion.Status == cyclonedx.VulnerabilityStatusNotAffected {
									t.Errorf("Expected no fixed versions to be added, but found: %v", affectedVersion)
								}
							}
						}
					}
				}
			} else {
				// For successful cases, verify that fixed versions were added
				assert.NotNil(t, vulnCopy.Affects, "Expected affects to be present")
				if vulnCopy.Affects != nil && len(*vulnCopy.Affects) > 0 {
					affect := (*vulnCopy.Affects)[0]
					assert.NotNil(t, affect.Range, "Expected range to be present")
					if affect.Range != nil {
						fixedVersions := []cyclonedx.AffectedVersions{}
						for _, affectedVersion := range *affect.Range {
							if affectedVersion.Status == cyclonedx.VulnerabilityStatusNotAffected {
								fixedVersions = append(fixedVersions, affectedVersion)
							}
						}
						assert.Equal(t, len(tt.expectedAffectedVersions), len(fixedVersions), "Expected number of fixed versions to match")
						for _, expectedVersion := range tt.expectedAffectedVersions {
							found := false
							for _, actualVersion := range fixedVersions {
								if actualVersion.Version == expectedVersion.Version && actualVersion.Status == expectedVersion.Status {
									found = true
									break
								}
							}
							assert.True(t, found, "Expected to find fixed version: %v", expectedVersion)
						}
					}
				}
			}
		})
	}
}

func TestMatchVulnerabilityToRemediationOptionsMultipleAffects(t *testing.T) {
	// This test specifically checks the "Multiple affects with mixed results" scenario
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				BOMRef:  "component1-ref",
				Name:    "component1",
				Version: "1.0.0",
			},
			{
				BOMRef:  "component2-ref",
				Name:    "component2",
				Version: "2.0.0",
			},
		},
	}

	vulnerability := &cyclonedx.Vulnerability{
		ID: "CVE-2023-1234",
		Affects: &[]cyclonedx.Affects{
			{
				Ref: "component1-ref",
			},
			{
				Ref: "component2-ref",
			},
			{
				Ref: "missing-ref", // This should be skipped
			},
		},
	}

	remediationOptions := utils.CveRemediationResponse{
		"CVE-2023-1234": []utils.Option{
			{
				Type: utils.InLock,
				Steps: map[utils.FixStrategy][]utils.OptionStep{
					utils.QuickestFixStrategy: {
						{
							StepType: utils.FixVersion,
							PkgVersion: utils.PackageVersionKey{
								Name:    "component1",
								Version: "1.0.0",
							},
							UpgradeTo: utils.PackageVersionKey{
								Version: "1.0.1",
							},
						},
						{
							StepType: utils.FixVersion,
							PkgVersion: utils.PackageVersionKey{
								Name:    "component2",
								Version: "2.0.0",
							},
							UpgradeTo: utils.PackageVersionKey{
								Version: "2.0.1",
							},
						},
					},
				},
			},
		},
	}

	// Execute the function
	matchVulnerabilityToRemediationOptions(bom, vulnerability, remediationOptions, utils.QuickestFixStrategy)

	// Verify results for each affect
	assert.NotNil(t, vulnerability.Affects)
	assert.Equal(t, 3, len(*vulnerability.Affects))

	// Check first affect (component1) - should have fixed version
	affect1 := (*vulnerability.Affects)[0]
	assert.Equal(t, "component1-ref", affect1.Ref)
	if affect1.Range != nil {
		found := false
		for _, affectedVersion := range *affect1.Range {
			if affectedVersion.Version == "1.0.1" && affectedVersion.Status == cyclonedx.VulnerabilityStatusNotAffected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected to find fixed version 1.0.1 for component1")
	}

	// Check second affect (component2) - should have fixed version
	affect2 := (*vulnerability.Affects)[1]
	assert.Equal(t, "component2-ref", affect2.Ref)
	if affect2.Range != nil {
		found := false
		for _, affectedVersion := range *affect2.Range {
			if affectedVersion.Version == "2.0.1" && affectedVersion.Status == cyclonedx.VulnerabilityStatusNotAffected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected to find fixed version 2.0.1 for component2")
	}

	// Check third affect (missing-ref) - should have no fixed versions
	affect3 := (*vulnerability.Affects)[2]
	assert.Equal(t, "missing-ref", affect3.Ref)
	if affect3.Range != nil {
		for _, affectedVersion := range *affect3.Range {
			if affectedVersion.Status == cyclonedx.VulnerabilityStatusNotAffected {
				t.Errorf("Expected no fixed versions for missing component, but found: %v", affectedVersion)
			}
		}
	}
}
