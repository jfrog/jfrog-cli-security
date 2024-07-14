package simplejsonparser

import (
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestSortVulnerabilityOrViolationRows(t *testing.T) {
	testCases := []struct {
		name          string
		rows          []formats.VulnerabilityOrViolationRow
		expectedOrder []string
	}{
		{
			name: "Sort by severity with different severity values",
			rows: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "Summary 1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 9,
						},
						ImpactedDependencyName:    "Dependency 1",
						ImpactedDependencyVersion: "1.0.0",
					},
					FixedVersions: []string{},
				},
				{
					Summary: "Summary 2",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Critical",
							SeverityNumValue: 12,
						},
						ImpactedDependencyName:    "Dependency 2",
						ImpactedDependencyVersion: "2.0.0",
					},
					FixedVersions: []string{"1.0.0"},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Medium",
							SeverityNumValue: 6,
						},
						ImpactedDependencyName:    "Dependency 3",
						ImpactedDependencyVersion: "3.0.0",
					},
					Summary:       "Summary 3",
					FixedVersions: []string{},
				},
			},
			expectedOrder: []string{"Dependency 2", "Dependency 1", "Dependency 3"},
		},
		{
			name: "Sort by severity with same severity values, but different fixed versions",
			rows: []formats.VulnerabilityOrViolationRow{
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Critical",
							SeverityNumValue: 12,
						},
						ImpactedDependencyName:    "Dependency 1",
						ImpactedDependencyVersion: "1.0.0",
					},
					Summary:       "Summary 1",
					FixedVersions: []string{"1.0.0"},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Critical",
							SeverityNumValue: 12,
						},
						ImpactedDependencyName:    "Dependency 2",
						ImpactedDependencyVersion: "2.0.0",
					},
					Summary:       "Summary 2",
					FixedVersions: []string{},
				},
			},
			expectedOrder: []string{"Dependency 1", "Dependency 2"},
		},
		{
			name: "Sort by severity with same severity values different applicability",
			rows: []formats.VulnerabilityOrViolationRow{
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Critical",
							SeverityNumValue: 13,
						},
						ImpactedDependencyName:    "Dependency 1",
						ImpactedDependencyVersion: "1.0.0",
					},
					Summary:       "Summary 1",
					Applicable:    jasutils.Applicable.String(),
					FixedVersions: []string{"1.0.0"},
				},
				{
					Summary:    "Summary 2",
					Applicable: jasutils.NotApplicable.String(),
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Critical",
							SeverityNumValue: 11,
						},
						ImpactedDependencyName:    "Dependency 2",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
				{
					Summary:    "Summary 3",
					Applicable: jasutils.ApplicabilityUndetermined.String(),
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Critical",
							SeverityNumValue: 12,
						},
						ImpactedDependencyName:    "Dependency 3",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
			},
			expectedOrder: []string{"Dependency 1", "Dependency 3", "Dependency 2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sortVulnerabilityOrViolationRows(tc.rows)

			for i, row := range tc.rows {
				assert.Equal(t, tc.expectedOrder[i], row.ImpactedDependencyName)
			}
		})
	}
}

func TestGetOperationalRiskReadableData(t *testing.T) {
	tests := []struct {
		violation       services.Violation
		expectedResults *operationalRiskViolationReadableData
	}{
		{
			services.Violation{IsEol: nil, LatestVersion: "", NewerVersions: nil,
				Cadence: nil, Commits: nil, Committers: nil, RiskReason: "", EolMessage: ""},
			&operationalRiskViolationReadableData{"N/A", "N/A", "N/A", "N/A", "", "", "N/A", "N/A"},
		},
		{
			services.Violation{IsEol: utils.NewBoolPtr(true), LatestVersion: "1.2.3", NewerVersions: utils.NewIntPtr(5),
				Cadence: utils.NewFloat64Ptr(3.5), Commits: utils.NewInt64Ptr(55), Committers: utils.NewIntPtr(10), EolMessage: "no maintainers", RiskReason: "EOL"},
			&operationalRiskViolationReadableData{"true", "3.5", "55", "10", "no maintainers", "EOL", "1.2.3", "5"},
		},
	}

	for _, test := range tests {
		results := getOperationalRiskViolationReadableData(test.violation)
		assert.Equal(t, test.expectedResults, results)
	}
}

func TestPrepareSimpleJsonVulnerabilities(t *testing.T) {
	testScaScanResults := []services.Vulnerability{
		{
			IssueId:    "XRAY-1",
			Summary:    "summary-1",
			Severity:   "High",
			Cves:       []services.Cve{{Id: "CVE-1"}},
			Components: map[string]services.Component{"component-A": {}, "component-B": {}},
		},
		{
			IssueId:    "XRAY-2",
			Summary:    "summary-2",
			Severity:   "Low",
			Cves:       []services.Cve{{Id: "CVE-2"}},
			Components: map[string]services.Component{"component-B": {}},
		},
	}

	testCases := []struct {
		name             string
		input            []services.Vulnerability
		target           string
		entitledForJas   bool
		pretty           bool
		applicablityRuns []*sarif.Run
		expectedOutput   []formats.VulnerabilityOrViolationRow
	}{
		{
			name:             "No vulnerabilities",
			input:            []services.Vulnerability{},
			target:           "target",
			entitledForJas:   false,
			pretty:           false,
			applicablityRuns: []*sarif.Run{},
			expectedOutput:   []formats.VulnerabilityOrViolationRow{},
		},
		{
			name:             "Vulnerabilities with no applicability",
			input:            testScaScanResults,
			target:           "target",
			entitledForJas:   false,
			pretty:           false,
			applicablityRuns: []*sarif.Run{},
			expectedOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High"},
						ImpactedDependencyName: "component-A",
					},
				},
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High"},
						ImpactedDependencyName: "component-B",
					},
				},
				{
					Summary: "summary-2",
					IssueId: "XRAY-2",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
						ImpactedDependencyName: "component-B",
					},
				},
			},
		},
		{
			name:           "Vulnerabilities with applicability",
			input:          testScaScanResults,
			target:         "target",
			entitledForJas: true,
			pretty:         false,
			applicablityRuns: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_CVE-1"),
					sarifutils.CreateResultWithLocations("applic_CVE-2", "applic_CVE-2", "note", sarifutils.CreateLocation("target/file", 0, 0, 0, 0, "snippet")),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target")),
				}),
			},
			expectedOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High"},
						ImpactedDependencyName: "component-A",
						Components:             []formats.ComponentRow{{Name: "component-A", Location: &formats.Location{File: "target"}}},
					},
					Applicable: jasutils.NotApplicable.String(),
					Cves:       []formats.CveRow{{Id: "CVE-1"}},
				},
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High"},
						ImpactedDependencyName: "component-B",
						Components:             []formats.ComponentRow{{Name: "component-B", Location: &formats.Location{File: "target"}}},
					},
					Applicable: jasutils.NotApplicable.String(),
					Cves:       []formats.CveRow{{Id: "CVE-1"}},
				},
				{
					Summary: "summary-2",
					IssueId: "XRAY-2",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
						ImpactedDependencyName: "component-B",
						Components:             []formats.ComponentRow{{Name: "component-B", Location: &formats.Location{File: "target"}}},
					},
					Applicable: jasutils.Applicability.String(),
					Cves: []formats.CveRow{{
						Id: "CVE-2",
						Applicability: &formats.Applicability{
							Status: jasutils.Applicability.String(),
							Evidence: []formats.Evidence{formats.Evidence{
								Location: formats.Location{File: "target/file", StartLine: 0, StartColumn: 0, EndLine: 0, EndColumn: 0, Snippet: "snippet"},
							}},
						},
					}},
				},
			},
		},
		{
			name:             "Vulnerabilities only - with allowed licenses",
			input:            testScaScanResults,
			target:           "target",
			entitledForJas:   false,
			pretty:           false,
			applicablityRuns: []*sarif.Run{},
			expectedOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "high"},
						ImpactedDependencyName: "component-A",
					},
				},
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "high"},
						ImpactedDependencyName: "component-B",
					},
				},
				{
					Summary: "summary-2",
					IssueId: "XRAY-2",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "low"},
						ImpactedDependencyName: "component-B",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := PrepareSimpleJsonVulnerabilities(tc.target, tc.input, tc.pretty, tc.entitledForJas, tc.applicablityRuns...)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedOutput, out)
		})
	}
}

func TestPrepareSimpleJsonViolations(t *testing.T) {
	testCases := []struct {
		name                          string
		input                         []services.Violation
		target                        string
		entitledForJas                bool
		pretty                        bool
		applicablityRuns              []*sarif.Run
		expectedSecurityOutput        []formats.VulnerabilityOrViolationRow
		expectedLicenseOutput         []formats.LicenseRow
		expectedOperationalRiskOutput []formats.OperationalRiskViolationRow
	}{
		{
			name:                   "No violations",
			input:                  []services.Violation{},
			target:                 "target",
			entitledForJas:         false,
			pretty:                 false,
			applicablityRuns:       []*sarif.Run{},
			expectedSecurityOutput: []formats.VulnerabilityOrViolationRow{},
		},
		{
			name: "Violations with no applicability",
			input: []services.Violation{
				{
					IssueId:       "XRAY-1",
					Summary:       "summary-1",
					Severity:      "High",
					ViolationType: "security",
					Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
				},
				{
					IssueId:       "XRAY-2",
					Summary:       "summary-2",
					Severity:      "Low",
					ViolationType: "license",
					LicenseKey:    "license-1",
					Components:    map[string]services.Component{"component-B": {}},
				},
			},
			target:           "target",
			entitledForJas:   false,
			pretty:           false,
			applicablityRuns: []*sarif.Run{},
			expectedSecurityOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High"},
						ImpactedDependencyName: "component-A",
					},
				},
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High"},
						ImpactedDependencyName: "component-B",
					},
				},
				{
					Summary: "summary-2",
					IssueId: "XRAY-2",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
						ImpactedDependencyName: "component-B",
					},
				},
			},
		},
		{
			name: "Violations with applicability",
			input: []services.Violation{
				{
					IssueId:       "XRAY-1",
					Summary:       "summary-1",
					Severity:      "High",
					WatchName:     "watch-1",
					ViolationType: "security",
					Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
				},
				{
					IssueId:       "XRAY-2",
					Summary:       "summary-2",
					Severity:      "Low",
					WatchName:     "watch-1",
					ViolationType: "license",
					LicenseKey:    "license-1",
					Components:    map[string]services.Component{"component-B": {}},
				},
			},
			target:         "target",
			entitledForJas: true,
			pretty:         false,
			applicablityRuns: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_CVE-1"),
					sarifutils.CreateResultWithLocations("applic_CVE-2", "applic_CVE-2", "note", sarifutils.CreateLocation("target/file", 0, 0, 0, 0, "snippet")),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target")),
				}),
			},
			expectedSecurityOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High"},
						ImpactedDependencyName: "component-A",
						Components:             []formats.ComponentRow{{Name: "component-A", Location: &formats.Location{File: "target"}}},
					},
					Applicable: jasutils.NotApplicable.String(),
				},
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High"},
						ImpactedDependencyName: "component-B",
						Components:             []formats.ComponentRow{{Name: "component-B", Location: &formats.Location{File: "target"}}},
					},
					Applicable: jasutils.NotApplicable.String(),
				},
				{
					Summary: "summary-2",
					IssueId: "XRAY-2",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
						ImpactedDependencyName: "component-B",
						Components:             []formats.ComponentRow{{Name: "component-B", Location: &formats.Location{File: "target"}}},
					},
					Applicable: jasutils.Applicability.String(),
				},
			},
		},
		{
			name: "Violations - override allowed licenses",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			securityOutput, licenseOutput, operationalRiskOutput, err := PrepareSimpleJsonViolations(tc.target, tc.input, tc.pretty, tc.entitledForJas, tc.applicablityRuns...)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedSecurityOutput, securityOutput)
			assert.ElementsMatch(t, tc.expectedLicenseOutput, licenseOutput)
			assert.ElementsMatch(t, tc.expectedOperationalRiskOutput, operationalRiskOutput)
		})
	}

}

func TestPrepareSimpleJsonLicenses(t *testing.T) {

}

func TestPrepareSimpleJsonJasIssues(t *testing.T) {

}
