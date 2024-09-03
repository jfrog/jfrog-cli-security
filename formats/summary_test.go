package formats

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCuratedPackages(t *testing.T) {
	testCases := []struct {
		name             string
		curatedPackages  CuratedPackages
		expectedApproved int
		expectedBlocked  int
	}{
		{"Empty", CuratedPackages{}, 0, 0},
		{"Approved", CuratedPackages{PackageCount: 1}, 1, 0},
		{"Blocked", CuratedPackages{Blocked: []BlockedPackages{{Policy: "Test", Condition: "Test condition", Packages: map[string]int{"npm://test:1.0.0": 1}}}, PackageCount: 1}, 0, 1},
		{
			"Multiple",
			CuratedPackages{
				Blocked: []BlockedPackages{
					{
						Policy:    "Test",
						Condition: "Test condition",
						Packages:  map[string]int{"npm://test:1.0.0": 1, "npm://test3:1.0.0": 1},
					},
					{
						Policy:    "Test2",
						Condition: "Test condition 2",
						Packages:  map[string]int{"npm://test2:1.0.0": 1, "npm://test3:1.0.0": 1},
					},
				},
				PackageCount: 9,
			},
			6, 3,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedApproved, testCase.curatedPackages.GetApprovedCount())
			assert.Equal(t, testCase.expectedBlocked, testCase.curatedPackages.GetBlockedCount())
		})
	}
}

func TestResultSummary(t *testing.T) {
	testSummary := ResultSummary{
		"High":    map[string]int{NoStatus: 1, "Status1": 2},
		"Medium":  map[string]int{"Status1": 3, "Status2": 4},
		"Low":     map[string]int{NoStatus: 15},
		"Unknown": map[string]int{"Status2": 6},
	}
	testCases := []struct {
		name            string
		summary         ResultSummary
		severityFilters []string
		expectedTotal   int
	}{
		{
			name:          "Empty",
			summary:       ResultSummary{},
			expectedTotal: 0,
		},
		{
			name:          "No filters",
			summary:       testSummary,
			expectedTotal: 31,
		},
		{
			name:            "With filters",
			summary:         testSummary,
			severityFilters: []string{"Critical", "High", "Low"},
			expectedTotal:   18,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedTotal, testCase.summary.GetTotal(testCase.severityFilters...))
		})
	}
}

func TestScanResultSummary(t *testing.T) {
	ids := []string{"id1", "id2"}
	urls := []string{"url1", "url2"}
	testSummary := ScanResultSummary{
		ScaResults: &ScaScanResultSummary{
			ScanIds:         ids,
			MoreInfoUrls:    urls,
			Security:        ResultSummary{"Critical": map[string]int{"Status": 1}, "High": map[string]int{NoStatus: 1}},
			License:         ResultSummary{"High": map[string]int{NoStatus: 1}},
			OperationalRisk: ResultSummary{"Low": map[string]int{NoStatus: 1}},
		},
		SecretsResults: &ResultSummary{"Medium": map[string]int{NoStatus: 1}},
		SastResults:    &ResultSummary{"High": map[string]int{"Status": 1}},
	}
	testCases := []struct {
		name                 string
		summary              ScanResultSummary
		resultTypeFilters    []SummaryResultType
		expectedTotal        int
		expectedScanIds      []string
		expectedMoreInfoUrls []string
	}{
		{
			name:    "No Issues",
			summary: ScanResultSummary{ScaResults: &ScaScanResultSummary{}, SecretsResults: &ResultSummary{}},
		},
		{
			name:                 "No filters",
			summary:              testSummary,
			expectedTotal:        6,
			expectedScanIds:      ids,
			expectedMoreInfoUrls: urls,
		},
		{
			name:                 "One filter",
			summary:              testSummary,
			resultTypeFilters:    []SummaryResultType{ScaSecurityResult},
			expectedTotal:        2,
			expectedScanIds:      ids,
			expectedMoreInfoUrls: urls,
		},
		{
			name:                 "Multiple filters",
			summary:              testSummary,
			resultTypeFilters:    []SummaryResultType{ScaSecurityResult, ScaLicenseResult, IacResult, SecretsResult, SastResult},
			expectedTotal:        5,
			expectedScanIds:      ids,
			expectedMoreInfoUrls: urls,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedTotal, testCase.summary.GetTotal(testCase.resultTypeFilters...))
			assert.Equal(t, testCase.expectedTotal > 0, testCase.summary.HasIssues())
			assert.ElementsMatch(t, testCase.expectedScanIds, testCase.summary.GetScanIds())
			assert.ElementsMatch(t, testCase.expectedMoreInfoUrls, testCase.summary.GetMoreInfoUrls())
		})
	}
}

func TestScanSummary(t *testing.T) {
	curatedBlocked := &CuratedPackages{Blocked: []BlockedPackages{{Packages: map[string]int{"npm://test:1.0.0": 1}}}, PackageCount: 1}
	vulnerabilities := &ScanResultSummary{SecretsResults: &ResultSummary{"High": map[string]int{"Status": 1}}}
	violations := &ScanViolationsSummary{ScanResultSummary: *vulnerabilities, Watches: []string{"watch1", "watch2"}}
	testCases := []struct {
		name                       string
		summary                    ScanSummary
		expectedHasCuratedPackages bool
		expectedHasBlockedPackages bool
		expectedHasViolations      bool
		expectedHasVulnerabilities bool
	}{
		{
			name:    "Empty",
			summary: ScanSummary{},
		},
		{
			name:                       "CuratedPackages",
			summary:                    ScanSummary{CuratedPackages: &CuratedPackages{PackageCount: 1}, Vulnerabilities: &ScanResultSummary{}},
			expectedHasCuratedPackages: true,
		},
		{
			name:                       "BlockedPackages",
			summary:                    ScanSummary{CuratedPackages: curatedBlocked, Violations: &ScanViolationsSummary{}},
			expectedHasCuratedPackages: true,
			expectedHasBlockedPackages: true,
		},
		{
			name:                       "Vulnerabilities",
			summary:                    ScanSummary{Vulnerabilities: vulnerabilities},
			expectedHasVulnerabilities: true,
		},
		{
			name:                  "Violations",
			summary:               ScanSummary{Violations: violations},
			expectedHasViolations: true,
		},
		{
			name:                       "All",
			summary:                    ScanSummary{CuratedPackages: curatedBlocked, Vulnerabilities: vulnerabilities, Violations: violations},
			expectedHasCuratedPackages: true,
			expectedHasBlockedPackages: true,
			expectedHasVulnerabilities: true,
			expectedHasViolations:      true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedHasCuratedPackages, testCase.summary.HasCuratedPackages())
			assert.Equal(t, testCase.expectedHasBlockedPackages, testCase.summary.HasBlockedPackages())
			assert.Equal(t, testCase.expectedHasViolations, testCase.summary.HasViolations())
			assert.Equal(t, testCase.expectedHasVulnerabilities, testCase.summary.HasVulnerabilities())
		})
	}
}

func TestResultsSummary(t *testing.T) {
	testScans := []ScanSummary{
		{Vulnerabilities: &ScanResultSummary{SecretsResults: &ResultSummary{"High": map[string]int{"Status": 4}}}},
		{Violations: &ScanViolationsSummary{ScanResultSummary: ScanResultSummary{ScaResults: &ScaScanResultSummary{License: ResultSummary{"Medium": map[string]int{NoStatus: 2}}}, SastResults: &ResultSummary{"High": map[string]int{"Status": 1}}}}},
		{Vulnerabilities: &ScanResultSummary{SastResults: &ResultSummary{"Medium": map[string]int{NoStatus: 1}}}},
		{Vulnerabilities: &ScanResultSummary{ScaResults: &ScaScanResultSummary{Security: ResultSummary{"Critical": map[string]int{"Status": 3}}}}},
		{Vulnerabilities: &ScanResultSummary{ScaResults: &ScaScanResultSummary{Security: ResultSummary{"High": map[string]int{NoStatus: 1}, "Low": map[string]int{NoStatus: 1}}}}},
	}
	testCases := []struct {
		name                         string
		summary                      ResultsSummary
		filters                      []SummaryResultType
		expectedTotalVulnerabilities int
		expectedTotalViolations      int
	}{
		{
			name:    "Empty",
			summary: ResultsSummary{},
		},
		{
			name:                         "No filters",
			summary:                      ResultsSummary{Scans: testScans},
			expectedTotalVulnerabilities: 10,
			expectedTotalViolations:      3,
		},
		{
			name:                         "With filters",
			summary:                      ResultsSummary{Scans: testScans},
			filters:                      []SummaryResultType{ScaLicenseResult, IacResult, SecretsResult},
			expectedTotalVulnerabilities: 4,
			expectedTotalViolations:      2,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedTotalVulnerabilities, testCase.summary.GetTotalVulnerabilities(testCase.filters...))
			assert.Equal(t, testCase.expectedTotalViolations, testCase.summary.GetTotalViolations(testCase.filters...))
			assert.Equal(t, testCase.expectedTotalViolations > 0, testCase.summary.HasViolations())
		})
	}
}

func TestGetVulnerabilitiesSummaries(t *testing.T) {
	dummyScaResults := &ScaScanResultSummary{Security: ResultSummary{"High": map[string]int{NoStatus: 1}}}
	dummyResultSummary := &ResultSummary{"Medium": map[string]int{NoStatus: 1}}
	testCases := []struct {
		name                             string
		input                            []ResultsSummary
		expectedShowVulnerabilities      bool
		expectedVulnerabilitiesSummaries *ScanResultSummary
	}{
		{
			name:  "Vulnerabilities not requested",
			input: []ResultsSummary{},
		},
		{
			name:                             "No Vulnerabilities",
			expectedShowVulnerabilities:      true,
			input:                            []ResultsSummary{{Scans: []ScanSummary{{Target: "target", Vulnerabilities: &ScanResultSummary{}}}}},
			expectedVulnerabilitiesSummaries: &ScanResultSummary{},
		},
		{
			name:                             "Single input",
			expectedShowVulnerabilities:      true,
			input:                            []ResultsSummary{{Scans: []ScanSummary{{Target: "target", Vulnerabilities: &ScanResultSummary{ScaResults: dummyScaResults, SecretsResults: dummyResultSummary}}}}},
			expectedVulnerabilitiesSummaries: &ScanResultSummary{ScaResults: dummyScaResults, SecretsResults: dummyResultSummary},
		},
		{
			name:                        "Multiple inputs",
			expectedShowVulnerabilities: true,
			input: []ResultsSummary{
				{Scans: []ScanSummary{{Target: "target1", Vulnerabilities: &ScanResultSummary{ScaResults: dummyScaResults}}}},
				{
					Scans: []ScanSummary{
						{Target: "target2", Vulnerabilities: &ScanResultSummary{SecretsResults: dummyResultSummary}},
						{Target: "target3", Vulnerabilities: &ScanResultSummary{SastResults: dummyResultSummary}},
					},
				},
			},
			expectedVulnerabilitiesSummaries: &ScanResultSummary{ScaResults: dummyScaResults, SecretsResults: dummyResultSummary, SastResults: dummyResultSummary},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			vulnerabilitiesSummaries := GetVulnerabilitiesSummaries(testCase.input...)
			if testCase.expectedShowVulnerabilities {
				assert.Equal(t, testCase.expectedVulnerabilitiesSummaries, vulnerabilitiesSummaries)
			} else {
				assert.Nil(t, vulnerabilitiesSummaries)
			}
		})
	}
}

func TestGetViolationSummaries(t *testing.T) {
	testCases := []struct {
		name                       string
		input                      []ResultsSummary
		expectedShowViolations     bool
		expectedViolationSummaries *ScanViolationsSummary
	}{
		{
			name:  "violation context not defined",
			input: []ResultsSummary{},
		},
		{
			name:                       "No Violations",
			expectedShowViolations:     true,
			input:                      []ResultsSummary{{Scans: []ScanSummary{{Target: "target", Violations: &ScanViolationsSummary{}}}}},
			expectedViolationSummaries: &ScanViolationsSummary{},
		},
		{
			name:                   "Single input",
			expectedShowViolations: true,
			input: []ResultsSummary{{Scans: []ScanSummary{
				{
					Target: "target1",
					Violations: &ScanViolationsSummary{
						Watches:   []string{"watch1"},
						FailBuild: true,
						ScanResultSummary: ScanResultSummary{ScaResults: &ScaScanResultSummary{
							Security:        ResultSummary{"Critical": map[string]int{NoStatus: 1}},
							OperationalRisk: ResultSummary{"Low": map[string]int{NoStatus: 1}},
						}},
					},
				},
				{
					Target: "target2",
					Violations: &ScanViolationsSummary{
						Watches: []string{"watch2"},
						ScanResultSummary: ScanResultSummary{ScaResults: &ScaScanResultSummary{
							Security: ResultSummary{"High": map[string]int{NoStatus: 1}},
							License:  ResultSummary{"High": map[string]int{NoStatus: 1}},
						}},
					},
				},
			}}},
			expectedViolationSummaries: &ScanViolationsSummary{
				Watches:   []string{"watch1", "watch2"},
				FailBuild: true,
				ScanResultSummary: ScanResultSummary{ScaResults: &ScaScanResultSummary{
					Security:        ResultSummary{"Critical": map[string]int{NoStatus: 1}, "High": map[string]int{NoStatus: 1}},
					License:         ResultSummary{"High": map[string]int{NoStatus: 1}},
					OperationalRisk: ResultSummary{"Low": map[string]int{NoStatus: 1}},
				}},
			},
		},
		{
			name:                   "Multiple inputs",
			expectedShowViolations: true,
			input: []ResultsSummary{
				{
					Scans: []ScanSummary{
						{
							Target: "target1",
							Violations: &ScanViolationsSummary{
								Watches: []string{"watch1"},
								ScanResultSummary: ScanResultSummary{ScaResults: &ScaScanResultSummary{
									Security:        ResultSummary{"Critical": map[string]int{NoStatus: 1}},
									OperationalRisk: ResultSummary{"Low": map[string]int{NoStatus: 1}},
								}},
							},
						},
						{
							Target: "target2",
							Violations: &ScanViolationsSummary{
								Watches: []string{"watch2"},
								ScanResultSummary: ScanResultSummary{ScaResults: &ScaScanResultSummary{
									Security: ResultSummary{"High": map[string]int{NoStatus: 1}},
									License:  ResultSummary{"High": map[string]int{NoStatus: 1}},
								}},
							},
						},
					},
				},
				{
					Scans: []ScanSummary{
						{
							Target: "target3",
							Violations: &ScanViolationsSummary{
								Watches: []string{"watch1"},
								ScanResultSummary: ScanResultSummary{ScaResults: &ScaScanResultSummary{
									Security: ResultSummary{"Critical": map[string]int{NoStatus: 1, "status": 2}, "High": map[string]int{NoStatus: 1}},
									License:  ResultSummary{"Medium": map[string]int{NoStatus: 1}},
								}},
							},
						},
					},
				},
			},
			expectedViolationSummaries: &ScanViolationsSummary{
				Watches: []string{"watch1", "watch2"},
				ScanResultSummary: ScanResultSummary{ScaResults: &ScaScanResultSummary{
					Security:        ResultSummary{"Critical": map[string]int{NoStatus: 2, "status": 2}, "High": map[string]int{NoStatus: 2}},
					License:         ResultSummary{"High": map[string]int{NoStatus: 1}, "Medium": map[string]int{NoStatus: 1}},
					OperationalRisk: ResultSummary{"Low": map[string]int{NoStatus: 1}},
				}},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			violationSummaries := GetViolationSummaries(testCase.input...)
			if testCase.expectedShowViolations {
				sort.Strings(violationSummaries.Watches)
				assert.Equal(t, testCase.expectedViolationSummaries, violationSummaries)
			} else {
				assert.Nil(t, violationSummaries)
			}
		})
	}
}
