package simplejsonparser

import (
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

var (
	testScaScanVulnerabilities = []services.Vulnerability{
		{
			IssueId:  "XRAY-1",
			Summary:  "summary-1",
			Severity: "High",
			Cves:     []services.Cve{{Id: "CVE-1"}},
			Components: map[string]services.Component{
				"component-A": {
					ImpactPaths: [][]services.ImpactPathNode{{
						{ComponentId: "root"},
						{ComponentId: "component-A"},
					}},
				},
				"component-B": {
					ImpactPaths: [][]services.ImpactPathNode{{
						{ComponentId: "root"},
						{ComponentId: "component-B"},
					}},
				},
			},
		},
		{
			IssueId:  "XRAY-2",
			Summary:  "summary-2",
			Severity: "Low",
			Cves:     []services.Cve{{Id: "CVE-2"}},
			Components: map[string]services.Component{
				"component-B": {
					ImpactPaths: [][]services.ImpactPathNode{{
						{ComponentId: "root"},
						{ComponentId: "component-B"},
					}},
				},
			},
		},
	}
	testScaScanViolation = []services.Violation{
		{
			IssueId:       "XRAY-1",
			Summary:       "summary-1",
			Severity:      "High",
			WatchName:     "watch-name",
			ViolationType: "security",
			Cves:          []services.Cve{{Id: "CVE-1"}},
			Components: map[string]services.Component{
				"component-A": {
					ImpactPaths: [][]services.ImpactPathNode{{
						{ComponentId: "root"},
						{ComponentId: "component-A"},
					}},
				},
				"component-B": {
					ImpactPaths: [][]services.ImpactPathNode{{
						{ComponentId: "root"},
						{ComponentId: "component-B"},
					}},
				},
			},
		},
		{
			IssueId:       "XRAY-2",
			Summary:       "summary-2",
			Severity:      "Low",
			WatchName:     "watch-name",
			ViolationType: "security",
			Cves:          []services.Cve{{Id: "CVE-2"}},
			Components: map[string]services.Component{
				"component-B": {
					ImpactPaths: [][]services.ImpactPathNode{{
						{ComponentId: "root"},
						{ComponentId: "component-B"},
					}},
				},
			},
		},
		{
			IssueId:       "XRAY-3",
			Summary:       "summary-3",
			Severity:      "Low",
			ViolationType: "license",
			LicenseKey:    "license-1",
			Components: map[string]services.Component{
				"component-B": {
					ImpactPaths: [][]services.ImpactPathNode{{
						{ComponentId: "root"},
						{ComponentId: "component-B"},
					}},
				},
			},
		},
	}
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
	testCases := []struct {
		name              string
		input             []services.Vulnerability
		target            results.ScanTarget
		entitledForJas    bool
		applicabilityRuns []*sarif.Run
		expectedOutput    []formats.VulnerabilityOrViolationRow
	}{
		{
			name:   "No vulnerabilities",
			target: results.ScanTarget{Target: "target"},
		},
		{
			name:   "Vulnerabilities not entitled for JAS",
			input:  testScaScanVulnerabilities,
			target: results.ScanTarget{Target: "target"},
			expectedOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					Cves:    []formats.CveRow{{Id: "CVE-1"}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 18},
						ImpactedDependencyName: "component-A",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-A",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-A"}}},
				},
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					Cves:    []formats.CveRow{{Id: "CVE-1"}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 18},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
				{
					Summary: "summary-2",
					IssueId: "XRAY-2",
					Cves:    []formats.CveRow{{Id: "CVE-2"}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
			},
		},
		{
			name:           "Vulnerabilities with Jas",
			input:          testScaScanVulnerabilities,
			target:         results.ScanTarget{Target: "target"},
			entitledForJas: true,
			applicabilityRuns: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(
					sarifutils.CreateDummyPassingResult("applic_CVE-1"),
					[]string{"applicability"}, []string{"not_applicable"},
				).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target"))}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(
					sarifutils.CreateResultWithLocations("applic_CVE-2", "applic_CVE-2", "note", sarifutils.CreateLocation("target/file", 0, 0, 0, 0, "snippet")),
					[]string{"applicability"}, []string{"applicable"},
				).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target"))}),
			},
			expectedOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary:    "summary-1",
					IssueId:    "XRAY-1",
					Applicable: jasutils.NotApplicable.String(),
					Cves:       []formats.CveRow{{Id: "CVE-1", Applicability: &formats.Applicability{Status: jasutils.NotApplicable.String()}}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 4},
						ImpactedDependencyName: "component-A",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-A",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-A"}}},
				},
				{
					Summary:    "summary-1",
					IssueId:    "XRAY-1",
					Applicable: jasutils.NotApplicable.String(),
					Cves:       []formats.CveRow{{Id: "CVE-1", Applicability: &formats.Applicability{Status: jasutils.NotApplicable.String()}}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 4},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
				{
					Summary:    "summary-2",
					IssueId:    "XRAY-2",
					Applicable: jasutils.Applicable.String(),
					Cves: []formats.CveRow{{
						Id: "CVE-2",
						Applicability: &formats.Applicability{
							Status: jasutils.Applicable.String(),
							Evidence: []formats.Evidence{{
								Location: formats.Location{File: "file", StartLine: 0, StartColumn: 0, EndLine: 0, EndColumn: 0, Snippet: "snippet"},
								Reason:   "applic_CVE-2",
							}},
						},
					}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 13},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := PrepareSimpleJsonVulnerabilities(tc.target, services.ScanResponse{Vulnerabilities: tc.input}, false, tc.entitledForJas, tc.applicabilityRuns...)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedOutput, out)
		})
	}
}

func TestPrepareSimpleJsonViolations(t *testing.T) {
	testCases := []struct {
		name                          string
		input                         []services.Violation
		target                        results.ScanTarget
		entitledForJas                bool
		applicabilityRuns             []*sarif.Run
		expectedSecurityOutput        []formats.VulnerabilityOrViolationRow
		expectedLicenseOutput         []formats.LicenseRow
		expectedOperationalRiskOutput []formats.OperationalRiskViolationRow
	}{
		{
			name:   "No violations",
			target: results.ScanTarget{Target: "target"},
		},
		{
			name:   "Violations not entitled for JAS",
			input:  testScaScanViolation,
			target: results.ScanTarget{Target: "target"},
			expectedSecurityOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					Cves:    []formats.CveRow{{Id: "CVE-1"}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 18},
						ImpactedDependencyName: "component-A",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-A",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-A"}}},
				},
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					Cves:    []formats.CveRow{{Id: "CVE-1"}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 18},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
				{
					Summary: "summary-2",
					IssueId: "XRAY-2",
					Cves:    []formats.CveRow{{Id: "CVE-2"}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
			},
			expectedLicenseOutput: []formats.LicenseRow{
				{
					LicenseKey: "license-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10},
						ImpactedDependencyName: "component-B",
						Components:             []formats.ComponentRow{{Name: "component-B", Location: &formats.Location{File: "target"}}},
					},
				},
			},
		},
		{
			name:           "Violations with applicability",
			input:          testScaScanViolation,
			target:         results.ScanTarget{Target: "target"},
			entitledForJas: true,
			applicabilityRuns: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(
					sarifutils.CreateDummyPassingResult("applic_CVE-1"),
					[]string{"applicability"}, []string{"not_applicable"},
				).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target"))}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(
					sarifutils.CreateResultWithLocations("applic_CVE-2", "applic_CVE-2", "note", sarifutils.CreateLocation("target/file", 0, 0, 0, 0, "snippet")),
					[]string{"applicability"}, []string{"applicable"},
				).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target"))}),
			},
			expectedSecurityOutput: []formats.VulnerabilityOrViolationRow{
				{
					Summary:    "summary-1",
					IssueId:    "XRAY-1",
					Applicable: jasutils.NotApplicable.String(),
					Cves:       []formats.CveRow{{Id: "CVE-1", Applicability: &formats.Applicability{Status: jasutils.NotApplicable.String()}}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 4},
						ImpactedDependencyName: "component-A",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-A",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-A"}}},
				},
				{
					Summary:    "summary-1",
					IssueId:    "XRAY-1",
					Applicable: jasutils.NotApplicable.String(),
					Cves:       []formats.CveRow{{Id: "CVE-1", Applicability: &formats.Applicability{Status: jasutils.NotApplicable.String()}}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 4},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
				{
					Summary:    "summary-2",
					IssueId:    "XRAY-2",
					Applicable: jasutils.Applicable.String(),
					Cves: []formats.CveRow{{
						Id: "CVE-2",
						Applicability: &formats.Applicability{
							Status: jasutils.Applicable.String(),
							Evidence: []formats.Evidence{{
								Location: formats.Location{File: "file", StartLine: 0, StartColumn: 0, EndLine: 0, EndColumn: 0, Snippet: "snippet"},
								Reason:   "applic_CVE-2",
							}},
						},
					}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 13},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
			},
			expectedLicenseOutput: []formats.LicenseRow{
				{
					LicenseKey: "license-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			securityOutput, licenseOutput, operationalRiskOutput, err := PrepareSimpleJsonViolations(tc.target, services.ScanResponse{Violations: tc.input}, false, tc.entitledForJas, tc.applicabilityRuns...)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedSecurityOutput, securityOutput)
			assert.ElementsMatch(t, tc.expectedLicenseOutput, licenseOutput)
			assert.ElementsMatch(t, tc.expectedOperationalRiskOutput, operationalRiskOutput)
		})
	}

}

func TestPrepareSimpleJsonLicenses(t *testing.T) {
	testCases := []struct {
		name           string
		target         results.ScanTarget
		licenses       []services.License
		expectedOutput []formats.LicenseRow
	}{
		{
			name:   "No licenses",
			target: results.ScanTarget{Target: "target"},
		},
		{
			name:   "Licenses",
			target: results.ScanTarget{Target: "target"},
			licenses: []services.License{
				{
					Key:  "license-1",
					Name: "license-1-name",
					Components: map[string]services.Component{
						"component-B": {
							ImpactPaths: [][]services.ImpactPathNode{{
								{ComponentId: "root"},
								{ComponentId: "component-B"},
							}},
						},
					},
				},
			},
			expectedOutput: []formats.LicenseRow{
				{
					LicenseKey: "license-1",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Name:     "component-B",
							Location: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Name: "root"}, {Name: "component-B"}}},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := PrepareSimpleJsonLicenses(tc.target, tc.licenses)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedOutput, out)
		})
	}
}

func TestPrepareSimpleJsonJasIssues(t *testing.T) {
	issues := []*sarif.Run{
		// Secret detection
		sarifutils.CreateRunWithDummyResultsInWd("target",
			sarifutils.CreateResultWithOneLocation(filepath.Join("target", "file"), 1, 2, 3, 4, "secret-snippet", "secret-rule-id", "note"),
		),
	}
	testCases := []struct {
		name           string
		target         results.ScanTarget
		entitledForJas bool
		jasIssues      []*sarif.Run
		expectedOutput []formats.SourceCodeRow
	}{
		{
			name:           "No JAS issues",
			entitledForJas: true,
			target:         results.ScanTarget{Target: filepath.Join("root", "target")},
		},
		{
			name:           "JAS issues - not entitled",
			target:         results.ScanTarget{Target: "target"},
			jasIssues:      issues,
			expectedOutput: []formats.SourceCodeRow{},
		},
		{
			name:           "JAS issues",
			entitledForJas: true,
			target:         results.ScanTarget{Target: "target"},
			jasIssues:      issues,
			expectedOutput: []formats.SourceCodeRow{
				{
					Location:        formats.Location{File: "file", StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "secret-snippet"},
					SeverityDetails: formats.SeverityDetails{Severity: "Low", SeverityNumValue: 13},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := PrepareSimpleJsonJasIssues(tc.entitledForJas, false, tc.jasIssues...)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedOutput, out)
		})
	}
}
