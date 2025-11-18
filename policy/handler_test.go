package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

func TestCheckPolicyFailBuildError(t *testing.T) {
	tests := []struct {
		name         string
		resultToTest *results.SecurityCommandResults
		expectedErr  error
	}{
		{
			name: "nil results",
		},
		{
			name:         "no violations",
			resultToTest: results.NewCommandResults(utils.SourceCode),
		},
		{
			name: "some SCA violations",
			resultToTest: createResultsWithViolations(violationutils.Violations{
				Sca: []violationutils.CveViolation{
					createCveViolation("CVE-1234", jasutils.NotApplicable, createPolicy(true, false, false), createPolicy(false, false, false)),
					createCveViolation("CVE-5678", jasutils.Applicable, createPolicy(false, false, false)),
				},
			}),
			expectedErr: NewFailBuildError(),
		},
		{
			name: "skip not applicable with fail",
			resultToTest: createResultsWithViolations(violationutils.Violations{
				Sca: []violationutils.CveViolation{
					createCveViolation("CVE-1234", jasutils.NotApplicable, createPolicy(true, false, true)),
				},
			}),
		},
		{
			name: "violations",
			resultToTest: createResultsWithViolations(violationutils.Violations{
				Sca: []violationutils.CveViolation{
					createCveViolation("CVE-1234", jasutils.NotScanned, createPolicy(false, false, false)),
				},
				Secrets: []violationutils.JasViolation{
					createJasViolation("JAS-1234", violationutils.SecretsViolationType, createPolicy(true, false, false)),
				},
				License: []violationutils.LicenseViolation{
					createLicenseViolation("LIC-1234", createPolicy(false, false, false)),
				},
			}),
			expectedErr: NewFailBuildError(),
		},
		{
			name: "violations with no fail build",
			resultToTest: createResultsWithViolations(violationutils.Violations{
				Sca: []violationutils.CveViolation{
					createCveViolation("CVE-1234", jasutils.NotScanned, createPolicy(false, false, false)),
				},
				Secrets: []violationutils.JasViolation{
					createJasViolation("JAS-1234", violationutils.SecretsViolationType, createPolicy(false, false, false)),
				},
				OpRisk: []violationutils.OperationalRiskViolation{
					createOpRiskViolation("OPRISK-1234", createPolicy(false, true, false)),
				},
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedErr, CheckPolicyFailBuildError(test.resultToTest))
		})
	}
}

func TestCheckPolicyFailPrError(t *testing.T) {
	tests := []struct {
		name         string
		resultToTest *results.SecurityCommandResults
		expectedErr  error
	}{
		{
			name: "nil results",
		},
		{
			name:         "no violations",
			resultToTest: results.NewCommandResults(utils.SourceCode),
		},
		{
			name: "some SCA violations",
			resultToTest: createResultsWithViolations(violationutils.Violations{
				Sca: []violationutils.CveViolation{
					createCveViolation("CVE-1234", jasutils.NotApplicable, createPolicy(false, true, false)),
					createCveViolation("CVE-5678", jasutils.Applicable, createPolicy(false, true, false)),
				},
			}),
			expectedErr: NewFailPrError(),
		},
		{
			name: "skip not applicable with fail PR",
			resultToTest: createResultsWithViolations(violationutils.Violations{
				Sca: []violationutils.CveViolation{
					createCveViolation("CVE-1234", jasutils.NotApplicable, createPolicy(false, true, true)),
				},
			}),
		},
		{
			name: "some violations",
			resultToTest: createResultsWithViolations(violationutils.Violations{
				Sca: []violationutils.CveViolation{
					createCveViolation("CVE-1234", jasutils.NotScanned, createPolicy(false, true, false)),
				},
				Secrets: []violationutils.JasViolation{
					createJasViolation("JAS-1234", violationutils.SecretsViolationType, createPolicy(false, true, false)),
				},
			}),
			expectedErr: NewFailPrError(),
		},
		{
			name: "violations with no fail PR",
			resultToTest: createResultsWithViolations(violationutils.Violations{
				Sca: []violationutils.CveViolation{
					createCveViolation("CVE-1234", jasutils.NotScanned, createPolicy(false, false, false)),
				},
				Secrets: []violationutils.JasViolation{
					createJasViolation("JAS-1234", violationutils.SecretsViolationType, createPolicy(false, false, false)),
				},
				OpRisk: []violationutils.OperationalRiskViolation{
					createOpRiskViolation("OPRISK-1234", createPolicy(true, false, false)),
				},
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedErr, CheckPolicyFailPrError(test.resultToTest))
		})
	}
}

// TestFilterNotApplicableViolations tests the filterNotApplicableViolations function to ensure it
// correctly filters violations based on their ShouldSkipNotApplicable policy setting and
// contextual analysis status. It covers all combinations of policy settings and applicability statuses.
func TestFilterNotApplicableViolations(t *testing.T) {
	tests := []struct {
		name                 string
		violations           []violationutils.CveViolation
		expectedViolationIds []string
	}{
		{
			name:                 "no violations",
			violations:           []violationutils.CveViolation{},
			expectedViolationIds: []string{},
		},
		{
			name: "violation without skip not applicable policy",
			violations: []violationutils.CveViolation{
				createCveViolation("CVE-1234", jasutils.NotApplicable, createPolicy(false, false, false)),
			},
			expectedViolationIds: []string{"CVE-1234"},
		},
		{
			name: "violation with skip not applicable policy and Not Applicable status",
			violations: []violationutils.CveViolation{
				createCveViolation("CVE-5678", jasutils.NotApplicable, createPolicy(true, false, true)),
			},
			expectedViolationIds: []string{},
		},
		{
			name: "violation with skip not applicable policy and Applicable status",
			violations: []violationutils.CveViolation{
				createCveViolation("CVE-9101", jasutils.Applicable, createPolicy(true, false, true)),
			},
			expectedViolationIds: []string{"CVE-9101"},
		},
		{
			name: "violation with skip not applicable policy and Not Scanned status",
			violations: []violationutils.CveViolation{
				createCveViolation("CVE-1121", jasutils.NotScanned, createPolicy(true, false, true)),
			},
			expectedViolationIds: []string{"CVE-1121"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := filterNotApplicableViolations(test.violations)
			assert.Len(t, result, len(test.expectedViolationIds))

			// Verify specific violation IDs if provided
			if len(test.expectedViolationIds) > 0 {
				actualIds := make([]string, len(result))
				for i, violation := range result {
					actualIds[i] = violation.ViolationId
				}
				assert.ElementsMatch(t, test.expectedViolationIds, actualIds)
			}
		})
	}
}

func createResultsWithViolations(Violations violationutils.Violations) *results.SecurityCommandResults {
	return results.NewCommandResults(utils.SourceCode).SetViolations(0, Violations)
}

func createJasViolation(violationId string, violationType violationutils.ViolationIssueType, policies ...violationutils.Policy) violationutils.JasViolation {
	return violationutils.JasViolation{
		Violation: createViolation(violationId, violationType, policies...),
	}
}

func createOpRiskViolation(violationId string, policies ...violationutils.Policy) violationutils.OperationalRiskViolation {
	return violationutils.OperationalRiskViolation{
		ScaViolation: violationutils.ScaViolation{
			Violation: createViolation(violationId, violationutils.OperationalRiskType, policies...),
		},
	}
}

func createLicenseViolation(violationId string, policies ...violationutils.Policy) violationutils.LicenseViolation {
	return violationutils.LicenseViolation{
		ScaViolation: violationutils.ScaViolation{
			Violation: createViolation(violationId, violationutils.LicenseViolationType, policies...),
		},
	}
}

func createCveViolation(violationId string, contextualAnalysis jasutils.ApplicabilityStatus, policies ...violationutils.Policy) violationutils.CveViolation {
	violation := violationutils.CveViolation{
		ScaViolation: violationutils.ScaViolation{
			Violation: createViolation(violationId, violationutils.CveViolationType, policies...),
		},
	}
	if contextualAnalysis != jasutils.NotScanned {
		violation.ContextualAnalysis = &formats.Applicability{
			Status: contextualAnalysis.String(),
		}
	}
	return violation
}

func createViolation(violationId string, violationType violationutils.ViolationIssueType, policies ...violationutils.Policy) violationutils.Violation {
	return violationutils.Violation{
		ViolationId:   violationId,
		ViolationType: violationType,
		Severity:      severityutils.High,
		Watch:         "test-watch",
		Policies:      policies,
	}
}

func createPolicy(failBuild, failPR, skipNotApplicable bool) violationutils.Policy {
	return violationutils.Policy{
		PolicyName:        "test-policy",
		Rule:              "test-rule",
		FailBuild:         failBuild,
		FailPullRequest:   failPR,
		SkipNotApplicable: skipNotApplicable,
	}
}
