package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestViolationFailBuild(t *testing.T) {
	components := map[string]services.Component{"gav://antparent:ant:1.6.5": {}}

	tests := []struct {
		name           string
		auditResults   *results.SecurityCommandResults
		expectedResult bool
	}{
		{
			name:           "non-applicable violations with FailBuild & no skip-non-applicable in ScaResults.Violations - build should fail",
			auditResults:   createSecurityCommandResultsForFailBuildTest(true, true, utils.NewBoolPtr(false)),
			expectedResult: true,
		},
		{
			name:           "non-applicable violations with FailBuild & skip-non-applicable in ScaResults.Violations - build should not fail",
			auditResults:   createSecurityCommandResultsForFailBuildTest(true, true, utils.NewBoolPtr(true)),
			expectedResult: false,
		},
		{
			name:           "non-applicable violations with FailBuild & no skip-non-applicable in DeprecatedXrayResults - build should fail",
			auditResults:   createSecurityCommandResultsForFailBuildTest(false, true, utils.NewBoolPtr(false)),
			expectedResult: true,
		},
		{
			name:           "non-applicable violations with FailBuild & skip-non-applicable in DeprecatedXrayResults - build should not fail",
			auditResults:   createSecurityCommandResultsForFailBuildTest(false, true, utils.NewBoolPtr(true)),
			expectedResult: false,
		},
		{
			name:           "no applicability results, violations with FailBuild in DeprecatedXrayResults - build should fail",
			auditResults:   createSecurityCommandResultsForFailBuildTest(false, false, nil),
			expectedResult: true,
		},
		{
			name:           "no applicability results, violations with FailBuild in ScaResults.Violations - build should fail",
			auditResults:   createSecurityCommandResultsForFailBuildTest(true, false, nil),
			expectedResult: true,
		},
		{
			name: "multiple targets - first target should not fail, second target should fail",
			auditResults: &results.SecurityCommandResults{
				EntitledForJas: true,
				Targets: []*results.TargetResults{
					{
						// First target - should not fail
						ScanTarget: results.ScanTarget{Target: "test-target-1"},
						ScaResults: &results.ScaScanResults{
							Violations: []services.Violation{
								{
									// Violation 1: FailBuild & FailPr set to false - should not fail
									Components:    components,
									ViolationType: ViolationTypeSecurity.String(),
									FailBuild:     false,
									FailPr:        false,
									Cves:          []services.Cve{{Id: "CVE-2024-1111"}},
									Severity:      "High",
								},
								{
									// Violation 2: FailBuild=true, notApplicable, skip-not-applicable - should not fail
									Components:    components,
									ViolationType: ViolationTypeSecurity.String(),
									FailBuild:     true,
									Policies:      []services.Policy{{SkipNotApplicable: true}},
									Cves:          []services.Cve{{Id: "CVE-2024-2222"}},
									Severity:      "High",
								},
							},
						},
						JasResults: &results.JasScansResults{
							ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
								{
									Scan: []*sarif.Run{
										{
											Tool: &sarif.Tool{
												Driver: &sarif.ToolComponent{
													Rules: []*sarif.ReportingDescriptor{
														{
															ID: utils.NewStringPtr(jasutils.CveToApplicabilityRuleId("CVE-2024-2222")),
															Properties: &sarif.PropertyBag{
																Properties: map[string]interface{}{
																	jasutils.ApplicabilitySarifPropertyKey: "not_applicable",
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
					{
						// Second target - should fail
						ScanTarget: results.ScanTarget{Target: "test-target-2"},
						ScaResults: &results.ScaScanResults{
							Violations: []services.Violation{
								{
									// Violation 1: FailBuild=true, notApplicable, NOT skip-not-applicable - should fail
									Components:    components,
									ViolationType: ViolationTypeSecurity.String(),
									FailBuild:     true,
									Policies:      []services.Policy{{SkipNotApplicable: false}},
									Cves:          []services.Cve{{Id: "CVE-2024-3333"}},
									Severity:      "High",
								},
								{
									// Violation 2: FailBuild & FailPr set to false - should not fail
									Components:    components,
									ViolationType: ViolationTypeSecurity.String(),
									FailBuild:     false,
									FailPr:        false,
									Cves:          []services.Cve{{Id: "CVE-2024-4444"}},
									Severity:      "High",
								},
							},
						},
						JasResults: &results.JasScansResults{
							ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
								{
									Scan: []*sarif.Run{
										{
											Tool: &sarif.Tool{
												Driver: &sarif.ToolComponent{
													Rules: []*sarif.ReportingDescriptor{
														{
															ID: utils.NewStringPtr(jasutils.CveToApplicabilityRuleId("CVE-2024-3333")),
															Properties: &sarif.PropertyBag{
																Properties: map[string]interface{}{
																	jasutils.ApplicabilitySarifPropertyKey: "not_applicable",
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedResult: true, // Should fail because second target has a violation that should fail
		},
		{
			name: "no sca results - build should not fail",
			auditResults: &results.SecurityCommandResults{
				EntitledForJas: true,
				Targets: []*results.TargetResults{
					{
						ScanTarget: results.ScanTarget{Target: "test-target"},
						ScaResults: nil,
						JasResults: &results.JasScansResults{},
					},
				},
			},
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			shouldFailBuild, err := CheckIfFailBuild(test.auditResults)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedResult, shouldFailBuild)
		})
	}
}

func createSecurityCommandResultsForFailBuildTest(useNewViolations bool, hasJasResults bool, skipNotApplicable *bool) *results.SecurityCommandResults {
	components := map[string]services.Component{"gav://antparent:ant:1.6.5": {}}
	cveId := "CVE-2024-1234"

	target := &results.TargetResults{
		ScanTarget: results.ScanTarget{Target: "test-target"},
		ScaResults: &results.ScaScanResults{},
	}

	violation := services.Violation{
		Components:    components,
		ViolationType: ViolationTypeSecurity.String(),
		FailBuild:     true,
		Cves:          []services.Cve{{Id: cveId}},
		Severity:      "High",
	}

	if skipNotApplicable != nil {
		violation.Policies = []services.Policy{{SkipNotApplicable: *skipNotApplicable}}
	}

	if useNewViolations {
		target.ScaResults.Violations = []services.Violation{violation}
	} else {
		target.ScaResults.DeprecatedXrayResults = []results.ScanResult[services.ScanResponse]{
			{
				Scan: services.ScanResponse{
					Violations: []services.Violation{violation},
				},
			},
		}
	}

	if hasJasResults {
		target.JasResults = &results.JasScansResults{
			ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
				{
					Scan: []*sarif.Run{
						{
							Tool: &sarif.Tool{
								Driver: &sarif.ToolComponent{
									Rules: []*sarif.ReportingDescriptor{
										{
											ID: utils.NewStringPtr(jasutils.CveToApplicabilityRuleId(cveId)),
											Properties: &sarif.PropertyBag{
												Properties: map[string]interface{}{
													jasutils.ApplicabilitySarifPropertyKey: "not_applicable",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}
	} else {
		target.JasResults = nil
	}

	return &results.SecurityCommandResults{
		EntitledForJas: true,
		Targets:        []*results.TargetResults{target},
	}
}

func TestShouldSkipNotApplicable(t *testing.T) {
	testCases := []struct {
		name                string
		violation           services.Violation
		applicabilityStatus jasutils.ApplicabilityStatus
		shouldSkip          bool
		errorExpected       bool
	}{
		{
			name:                "Applicable CVE - should NOT skip",
			violation:           services.Violation{},
			applicabilityStatus: jasutils.Applicable,
			shouldSkip:          false,
			errorExpected:       false,
		},
		{
			name:                "Undetermined CVE - should NOT skip",
			violation:           services.Violation{},
			applicabilityStatus: jasutils.ApplicabilityUndetermined,
			shouldSkip:          false,
			errorExpected:       false,
		},
		{
			name:                "Not covered CVE - should NOT skip",
			violation:           services.Violation{},
			applicabilityStatus: jasutils.NotCovered,
			shouldSkip:          false,
			errorExpected:       false,
		},
		{
			name:                "Missing Context CVE - should NOT skip",
			violation:           services.Violation{},
			applicabilityStatus: jasutils.MissingContext,
			shouldSkip:          false,
			errorExpected:       false,
		},
		{
			name:                "Not scanned CVE - should NOT skip",
			violation:           services.Violation{},
			applicabilityStatus: jasutils.NotScanned,
			shouldSkip:          false,
			errorExpected:       false,
		},
		{
			name: "Non applicable CVE with skip-non-applicable in ALL policies - SHOULD skip",
			violation: services.Violation{
				Policies: []services.Policy{
					{
						Policy:            "policy-1",
						SkipNotApplicable: true,
					},
					{
						Policy:            "policy-2",
						SkipNotApplicable: true,
					},
				},
			},
			applicabilityStatus: jasutils.NotApplicable,
			shouldSkip:          true,
			errorExpected:       false,
		},
		{
			name: "Non applicable CVE with skip-non-applicable in SOME policies - should NOT skip",
			violation: services.Violation{
				Policies: []services.Policy{
					{
						Policy:            "policy-1",
						SkipNotApplicable: true,
					},
					{
						Policy:            "policy-2",
						SkipNotApplicable: false,
					},
				},
			},
			applicabilityStatus: jasutils.NotApplicable,
			shouldSkip:          false,
			errorExpected:       false,
		},
		{
			name:                "Violation without policy - error expected",
			violation:           services.Violation{},
			applicabilityStatus: jasutils.NotApplicable,
			shouldSkip:          false,
			errorExpected:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shouldSkip, err := shouldSkipNotApplicable(tc.violation, tc.applicabilityStatus)
			if tc.errorExpected {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tc.shouldSkip {
				assert.True(t, shouldSkip)
			} else {
				assert.False(t, shouldSkip)
			}
		})
	}
}
