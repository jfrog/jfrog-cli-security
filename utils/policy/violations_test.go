package policy


func TestViolationFailBuild(t *testing.T) {
	components := map[string]services.Component{"gav://antparent:ant:1.6.5": {}}

	tests := []struct {
		name           string
		auditResults   *SecurityCommandResults
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
			auditResults: &SecurityCommandResults{
				EntitledForJas: true,
				Targets: []*TargetResults{
					{
						// First target - should not fail
						ScanTarget: ScanTarget{Target: "test-target-1"},
						ScaResults: &ScaScanResults{
							Violations: []services.Violation{
								{
									// Violation 1: FailBuild & FailPr set to false - should not fail
									Components:    components,
									ViolationType: utils.ViolationTypeSecurity.String(),
									FailBuild:     false,
									FailPr:        false,
									Cves:          []services.Cve{{Id: "CVE-2024-1111"}},
									Severity:      "High",
								},
								{
									// Violation 2: FailBuild=true, notApplicable, skip-not-applicable - should not fail
									Components:    components,
									ViolationType: utils.ViolationTypeSecurity.String(),
									FailBuild:     true,
									Policies:      []services.Policy{{SkipNotApplicable: true}},
									Cves:          []services.Cve{{Id: "CVE-2024-2222"}},
									Severity:      "High",
								},
							},
						},
						JasResults: &JasScansResults{
							ApplicabilityScanResults: []ScanResult[[]*sarif.Run]{
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
						ScanTarget: ScanTarget{Target: "test-target-2"},
						ScaResults: &ScaScanResults{
							Violations: []services.Violation{
								{
									// Violation 1: FailBuild=true, notApplicable, NOT skip-not-applicable - should fail
									Components:    components,
									ViolationType: utils.ViolationTypeSecurity.String(),
									FailBuild:     true,
									Policies:      []services.Policy{{SkipNotApplicable: false}},
									Cves:          []services.Cve{{Id: "CVE-2024-3333"}},
									Severity:      "High",
								},
								{
									// Violation 2: FailBuild & FailPr set to false - should not fail
									Components:    components,
									ViolationType: utils.ViolationTypeSecurity.String(),
									FailBuild:     false,
									FailPr:        false,
									Cves:          []services.Cve{{Id: "CVE-2024-4444"}},
									Severity:      "High",
								},
							},
						},
						JasResults: &JasScansResults{
							ApplicabilityScanResults: []ScanResult[[]*sarif.Run]{
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
			auditResults: &SecurityCommandResults{
				EntitledForJas: true,
				Targets: []*TargetResults{
					{
						ScanTarget: ScanTarget{Target: "test-target"},
						ScaResults: nil,
						JasResults: &JasScansResults{},
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

func createSecurityCommandResultsForFailBuildTest(useNewViolations bool, hasJasResults bool, skipNotApplicable *bool) *SecurityCommandResults {
	components := map[string]services.Component{"gav://antparent:ant:1.6.5": {}}
	cveId := "CVE-2024-1234"

	target := &TargetResults{
		ScanTarget: ScanTarget{Target: "test-target"},
		ScaResults: &ScaScanResults{},
	}

	violation := services.Violation{
		Components:    components,
		ViolationType: utils.ViolationTypeSecurity.String(),
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
		target.ScaResults.DeprecatedXrayResults = []ScanResult[services.ScanResponse]{
			{
				Scan: services.ScanResponse{
					Violations: []services.Violation{violation},
				},
			},
		}
	}

	if hasJasResults {
		target.JasResults = &JasScansResults{
			ApplicabilityScanResults: []ScanResult[[]*sarif.Run]{
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

	return &SecurityCommandResults{
		EntitledForJas: true,
		Targets:        []*TargetResults{target},
	}
}
