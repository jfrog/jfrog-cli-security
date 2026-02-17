package simplejsonparser

import (
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

var (
	testScaScanVulnerabilities = []services.Vulnerability{
		{
			IssueId:  "XRAY-1",
			Summary:  "summary-1",
			Severity: "High",
			Cves:     []services.Cve{{Id: "CVE-1", CvssV3Score: "5.3", CvssV3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", Cwe: []string{"cwe-1"}}},
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
			Cves:     []services.Cve{{Id: "CVE-2", CvssV2Score: "5.0", CvssV2Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P", Cwe: []string{"CWE-284", "NVD-CWE-noinfo"}}},
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
						SeverityDetails:           severityutils.GetAsDetails(severityutils.High, jasutils.Applicable, false),
						ImpactedDependencyName:    "Dependency 1",
						ImpactedDependencyVersion: "1.0.0",
					},
					FixedVersions: []string{},
				},
				{
					Summary: "Summary 2",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Critical, jasutils.Applicable, false),
						ImpactedDependencyName:    "Dependency 2",
						ImpactedDependencyVersion: "2.0.0",
					},
					FixedVersions: []string{"1.0.0"},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Medium, jasutils.NotApplicable, false),
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
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Critical, jasutils.Applicable, false),
						ImpactedDependencyName:    "Dependency 1",
						ImpactedDependencyVersion: "1.0.0",
					},
					Summary:       "Summary 1",
					FixedVersions: []string{"1.0.0"},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Critical, jasutils.Applicable, false),
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
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Critical, jasutils.Applicable, false),
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
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Critical, jasutils.NotApplicable, false),
						ImpactedDependencyName:    "Dependency 2",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
				{
					Summary:    "Summary 3",
					Applicable: jasutils.ApplicabilityUndetermined.String(),
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Critical, jasutils.ApplicabilityUndetermined, false),
						ImpactedDependencyName:    "Dependency 3",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
			},
			expectedOrder: []string{"Dependency 1", "Dependency 3", "Dependency 2"},
		},
		{
			name: "Sort by severity with multiple severity values and different applicability",
			rows: []formats.VulnerabilityOrViolationRow{
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Low, jasutils.Applicable, false),
						ImpactedDependencyName:    "Dependency 1",
						ImpactedDependencyVersion: "1.0.0",
					},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.High, jasutils.NotApplicable, false),
						ImpactedDependencyName:    "Dependency 2",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
				{
					Applicable: jasutils.ApplicabilityUndetermined.String(),
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Information, jasutils.NotCovered, false),
						ImpactedDependencyName:    "Dependency 3",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Low, jasutils.NotCovered, false),
						ImpactedDependencyName:    "Dependency 4",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Unknown, jasutils.ApplicabilityUndetermined, false),
						ImpactedDependencyName:    "Dependency 5",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
				{
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:           severityutils.GetAsDetails(severityutils.Critical, jasutils.Applicable, false),
						ImpactedDependencyName:    "Dependency 6",
						ImpactedDependencyVersion: "2.0.0",
					},
				},
			},
			expectedOrder: []string{"Dependency 6", "Dependency 1", "Dependency 4", "Dependency 3", "Dependency 5", "Dependency 2"},
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
					Cves:    []formats.CveRow{{Id: "CVE-1", CvssV3: "5.3", CvssV3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", Cwe: []string{"cwe-1"}}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 27},
						ImpactedDependencyName: "component-A",
						// Direct
						Components: []formats.ComponentRow{{
							Id:                "component-A",
							Name:              "component-A",
							PreferredLocation: &formats.Location{File: "descriptor.json"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Id: "root", Name: "root"}, {Id: "component-A", Name: "component-A"}}},
				},
				{
					Summary: "summary-1",
					IssueId: "XRAY-1",
					Cves:    []formats.CveRow{{Id: "CVE-1", CvssV3: "5.3", CvssV3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", Cwe: []string{"cwe-1"}}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 27},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Id:                "component-B",
							Name:              "component-B",
							PreferredLocation: &formats.Location{File: "descriptor.json"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Id: "root", Name: "root"}, {Id: "component-B", Name: "component-B"}}},
				},
				{
					Summary: "summary-2",
					IssueId: "XRAY-2",
					Cves:    []formats.CveRow{{Id: "CVE-2", CvssV2: "5.0", CvssV2Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P", Cwe: []string{"CWE-284", "NVD-CWE-noinfo"}}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 17},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Id:                "component-B",
							Name:              "component-B",
							PreferredLocation: &formats.Location{File: "descriptor.json"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Id: "root", Name: "root"}, {Id: "component-B", Name: "component-B"}}},
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
					Cves: []formats.CveRow{{
						Id:            "CVE-1",
						CvssV3:        "5.3",
						CvssV3Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
						Cwe:           []string{"cwe-1"},
						Applicability: &formats.Applicability{ScannerDescription: "rule-msg", Status: jasutils.NotApplicable.String()}},
					},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 5},
						ImpactedDependencyName: "component-A",
						// Direct
						Components: []formats.ComponentRow{{
							Id:                "component-A",
							Name:              "component-A",
							PreferredLocation: &formats.Location{File: "descriptor.json"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Id: "root", Name: "root"}, {Id: "component-A", Name: "component-A"}}},
				},
				{
					Summary:    "summary-1",
					IssueId:    "XRAY-1",
					Applicable: jasutils.NotApplicable.String(),
					Cves: []formats.CveRow{{
						Id:            "CVE-1",
						CvssV3:        "5.3",
						CvssV3Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
						Cwe:           []string{"cwe-1"},
						Applicability: &formats.Applicability{ScannerDescription: "rule-msg", Status: jasutils.NotApplicable.String()}},
					},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 5},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Id:                "component-B",
							Name:              "component-B",
							PreferredLocation: &formats.Location{File: "descriptor.json"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Id: "root", Name: "root"}, {Id: "component-B", Name: "component-B"}}},
				},
				{
					Summary:    "summary-2",
					IssueId:    "XRAY-2",
					Applicable: jasutils.Applicable.String(),
					Cves: []formats.CveRow{{
						Id:           "CVE-2",
						CvssV2:       "5.0",
						CvssV2Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Cwe:          []string{"CWE-284", "NVD-CWE-noinfo"},
						Applicability: &formats.Applicability{
							ScannerDescription: "rule-msg",
							Status:             jasutils.Applicable.String(),
							Evidence: []formats.Evidence{{
								Location: formats.Location{File: "file", StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 1, Snippet: "snippet"},
								Reason:   "applic_CVE-2",
							}},
						},
					}},
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 21},
						ImpactedDependencyName: "component-B",
						// Direct
						Components: []formats.ComponentRow{{
							Id:                "component-B",
							Name:              "component-B",
							PreferredLocation: &formats.Location{File: "descriptor.json"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Id: "root", Name: "root"}, {Id: "component-B", Name: "component-B"}}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := PrepareSimpleJsonVulnerabilities(tc.target, []string{filepath.Join(tc.target.Target, "descriptor.json")}, services.ScanResponse{Vulnerabilities: tc.input}, false, tc.entitledForJas, tc.applicabilityRuns...)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedOutput, out)
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
							Id:                "component-B",
							Name:              "component-B",
							PreferredLocation: &formats.Location{File: "target"},
						}},
					},
					ImpactPaths: [][]formats.ComponentRow{{{Id: "root", Name: "root"}, {Id: "component-B", Name: "component-B"}}},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := PrepareSimpleJsonLicenses(tc.target, tc.licenses, false)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedOutput, out)
		})
	}
}

func TestPrepareSimpleJsonJasIssues(t *testing.T) {
	issues := []*sarif.Run{
		// Secrets detection
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
					Finding:         "result-msg",
					Location:        formats.Location{File: "file", StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "secret-snippet"},
					SeverityDetails: formats.SeverityDetails{Severity: "Low", SeverityNumValue: 21},
					ScannerInfo:     formats.ScannerInfo{RuleId: "secret-rule-id", ScannerDescription: "rule-msg"},
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
