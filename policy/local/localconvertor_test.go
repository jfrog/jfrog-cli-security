package local

import (
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-client-go/xray/services"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

var testScaScanViolation = []services.Violation{
	{
		IssueId:       "XRAY-1",
		Summary:       "summary-1",
		Severity:      "High",
		WatchName:     "watch-name",
		ViolationType: "security",
		Cves:          []services.Cve{{Id: "CVE-1", CvssV3Score: "5.3", CvssV3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", Cwe: []string{"cwe-1"}}},
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
		Cves:          []services.Cve{{Id: "CVE-2", CvssV2Score: "5.0", CvssV2Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P", Cwe: []string{"CWE-284", "NVD-CWE-noinfo"}}},
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
		WatchName:     "lic-watch-name",
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

func TestGenerateViolations(t *testing.T) {
	testCases := []struct {
		name     string
		input    *results.SecurityCommandResults
		expected violationutils.Violations
	}{
		{
			name:     "No violations",
			input:    results.NewCommandResults(utils.SourceCode),
			expected: violationutils.Violations{},
		},
		{
			name:  "With violations not entitled for JAS",
			input: createTestResultsWithViolations(false, testScaScanViolation),
			expected: violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation:     createScaTestViolation("XRAY-1", "component-A", violationutils.CveViolationType, "watch-name", severityutils.High),
						CveVulnerability: createCdxVulnerabilityFull("CVE-1", "XRAY-1", "summary-1", []int{1}, "component-A", 5.3, 8.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
					},
					{
						ScaViolation:     createScaTestViolation("XRAY-1", "component-B", violationutils.CveViolationType, "watch-name", severityutils.High),
						CveVulnerability: createCdxVulnerabilityFull("CVE-1", "XRAY-1", "summary-1", []int{1}, "component-B", 5.3, 8.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
					},
					{
						ScaViolation:     createScaTestViolation("XRAY-2", "component-B", violationutils.CveViolationType, "watch-name", severityutils.Low),
						CveVulnerability: createCdxVulnerabilityFull("CVE-2", "XRAY-2", "summary-2", []int{284}, "component-B", 5.0, 3.9, "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P"),
					},
				},
				License: []violationutils.LicenseViolation{
					{
						ScaViolation: createScaTestViolation("XRAY-3", "component-B", violationutils.LicenseViolationType, "lic-watch-name", severityutils.Low),
						LicenseKey:   "license-1",
					},
				},
			},
		},
		{
			name: "With violations entitled for JAS",
			input: createTestResultsWithViolations(true, testScaScanViolation,
				sarifutils.CreateRunWithDummyResultAndRuleProperties(
					sarifutils.CreateDummyPassingResult("applic_CVE-1"),
					[]string{"applicability"}, []string{"not_applicable"},
				).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target"))}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(
					sarifutils.CreateResultWithLocations("applic_CVE-2", "applic_CVE-2", "note", sarifutils.CreateLocation("target/file", 0, 0, 0, 0, "snippet")),
					[]string{"applicability"}, []string{"applicable"},
				).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target"))}),
			),
			expected: violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation:     createScaTestViolation("XRAY-1", "component-A", violationutils.CveViolationType, "watch-name", severityutils.High),
						CveVulnerability: createCdxVulnerabilityFull("CVE-1", "XRAY-1", "summary-1", []int{1}, "component-A", 5.3, 8.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
						ContextualAnalysis: &formats.Applicability{
							Status:             jasutils.NotApplicable.String(),
							ScannerDescription: "rule-msg",
						},
					},
					{
						ScaViolation:     createScaTestViolation("XRAY-1", "component-B", violationutils.CveViolationType, "watch-name", severityutils.High),
						CveVulnerability: createCdxVulnerabilityFull("CVE-1", "XRAY-1", "summary-1", []int{1}, "component-B", 5.3, 8.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
						ContextualAnalysis: &formats.Applicability{
							Status:             jasutils.NotApplicable.String(),
							ScannerDescription: "rule-msg",
						},
					},
					{
						ScaViolation:     createScaTestViolation("XRAY-2", "component-B", violationutils.CveViolationType, "watch-name", severityutils.Low),
						CveVulnerability: createCdxVulnerabilityFull("CVE-2", "XRAY-2", "summary-2", []int{284}, "component-B", 5.0, 3.9, "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P"),
						ContextualAnalysis: &formats.Applicability{
							Status:             jasutils.Applicable.String(),
							ScannerDescription: "rule-msg",
							Evidence: []formats.Evidence{
								{
									Location: formats.Location{
										File:        "file",
										StartLine:   1,
										StartColumn: 1,
										EndLine:     1,
										EndColumn:   1,
										Snippet:     "snippet",
									},
									Reason: "applic_CVE-2",
								},
							},
						},
					},
				},
				License: []violationutils.LicenseViolation{
					{
						ScaViolation: createScaTestViolation("XRAY-3", "component-B", violationutils.LicenseViolationType, "lic-watch-name", severityutils.Low),
						LicenseKey:   "license-1",
					},
				},
			},
		},
	}

	localConvertor := NewDeprecatedViolationGenerator()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			converted, err := localConvertor.GenerateViolations(tc.input)
			assert.NoError(t, err)
			assert.ElementsMatch(t, converted.Sca, tc.expected.Sca)
			assert.ElementsMatch(t, converted.License, tc.expected.License)
			assert.ElementsMatch(t, converted.OpRisk, tc.expected.OpRisk)
			assert.ElementsMatch(t, converted.Sast, tc.expected.Sast)
			assert.ElementsMatch(t, converted.Secrets, tc.expected.Secrets)
			assert.ElementsMatch(t, converted.Iac, tc.expected.Iac)
		})
	}
}

func createTestResultsWithViolations(entitledForJas bool, violations []services.Violation, applicableRuns ...*sarif.Run) *results.SecurityCommandResults {
	cmdResults := results.NewCommandResults(utils.SourceCode).SetEntitledForJas(entitledForJas)
	target := cmdResults.NewScanResults(results.ScanTarget{Target: "target"})
	if entitledForJas {
		target.AddApplicabilityScanResults(0, applicableRuns...)
	}
	target.ScaScanResults(0, services.ScanResponse{Violations: violations})
	return cmdResults
}

func createScaTestViolation(id, component string, vioType violationutils.ViolationIssueType, watch string, severity severityutils.Severity) violationutils.ScaViolation {
	return violationutils.ScaViolation{
		Violation: violationutils.Violation{
			ViolationId:   id,
			ViolationType: vioType,
			Severity:      severity,
			Watch:         watch,
		},
		ImpactedComponent: cyclonedx.Component{
			BOMRef:     fmt.Sprintf("pkg:generic/%s", component),
			PackageURL: fmt.Sprintf("pkg:generic/%s", component),
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       component,
		},
		DirectComponents: []formats.ComponentRow{{Id: component, Name: component}},
		ImpactPaths: [][]formats.ComponentRow{{
			{Id: "root", Name: "root"},
			{Id: component, Name: component},
		}},
	}
}

func createCdxVulnerabilityFull(ref, id, description string, cweList []int, component string, cvssV3Score, otherScore float64, cvssVector string) cyclonedx.Vulnerability {
	source := &cyclonedx.Source{Name: utils.XrayToolName, URL: ""}
	cvssMethod := "CVSSv3"
	if cvssV3Score == 5.0 {
		cvssMethod = "CVSSv2"
	}
	severity := "high"
	if otherScore < 5.0 {
		severity = "low"
	}
	return cyclonedx.Vulnerability{
		BOMRef:      ref,
		ID:          id,
		Source:      source,
		Description: description,
		CWEs:        &cweList,
		Ratings: &[]cyclonedx.VulnerabilityRating{
			{
				Source: source,
				Score:  &cvssV3Score,
				Method: cyclonedx.ScoringMethod(cvssMethod),
				Vector: cvssVector,
			},
			{
				Source:   source,
				Score:    &otherScore,
				Severity: cyclonedx.Severity(severity),
				Method:   "other",
			},
		},
		Affects: &[]cyclonedx.Affects{
			{
				Ref:   fmt.Sprintf("pkg:generic/%s", component),
				Range: &[]cyclonedx.AffectedVersions{},
			},
		},
	}
}
