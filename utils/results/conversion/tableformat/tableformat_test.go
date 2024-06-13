package tableformat

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

func TestIsImpactPathIsSubset(t *testing.T) {
	testCases := []struct {
		name                           string
		target, source, expectedResult []services.ImpactPathNode
	}{
		{"subset found in both target and source",
			[]services.ImpactPathNode{{ComponentId: "B"}, {ComponentId: "C"}},
			[]services.ImpactPathNode{{ComponentId: "A"}, {ComponentId: "B"}, {ComponentId: "C"}},
			[]services.ImpactPathNode{{ComponentId: "B"}, {ComponentId: "C"}},
		},
		{"subset not found in both target and source",
			[]services.ImpactPathNode{{ComponentId: "A"}, {ComponentId: "B"}, {ComponentId: "D"}},
			[]services.ImpactPathNode{{ComponentId: "A"}, {ComponentId: "B"}, {ComponentId: "C"}},
			[]services.ImpactPathNode{},
		},
		{"target and source are identical",
			[]services.ImpactPathNode{{ComponentId: "A"}, {ComponentId: "B"}},
			[]services.ImpactPathNode{{ComponentId: "A"}, {ComponentId: "B"}},
			[]services.ImpactPathNode{{ComponentId: "A"}, {ComponentId: "B"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isImpactPathIsSubset(tc.target, tc.source)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestAppendUniqueFixVersions(t *testing.T) {
	testCases := []struct {
		targetFixVersions []string
		sourceFixVersions []string
		expectedResult    []string
	}{
		{
			targetFixVersions: []string{"1.0", "1.1"},
			sourceFixVersions: []string{"2.0", "2.1"},
			expectedResult:    []string{"1.0", "1.1", "2.0", "2.1"},
		},
		{
			targetFixVersions: []string{"1.0", "1.1"},
			sourceFixVersions: []string{"1.1", "2.0"},
			expectedResult:    []string{"1.0", "1.1", "2.0"},
		},
		{
			targetFixVersions: []string{},
			sourceFixVersions: []string{"1.0", "1.1"},
			expectedResult:    []string{"1.0", "1.1"},
		},
		{
			targetFixVersions: []string{"1.0", "1.1"},
			sourceFixVersions: []string{},
			expectedResult:    []string{"1.0", "1.1"},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("target:%v, source:%v", tc.targetFixVersions, tc.sourceFixVersions), func(t *testing.T) {
			result := appendUniqueFixVersions(tc.targetFixVersions, tc.sourceFixVersions...)
			assert.ElementsMatch(t, tc.expectedResult, result)
		})
	}
}

func TestGetUniqueKey(t *testing.T) {
	vulnerableDependency := "test-dependency"
	vulnerableVersion := "1.0"
	expectedKey := "test-dependency:1.0:XRAY-12234:true"
	key := GetUniqueKey(vulnerableDependency, vulnerableVersion, "XRAY-12234", true)
	assert.Equal(t, expectedKey, key)

	expectedKey = "test-dependency:1.0:XRAY-12143:false"
	key = GetUniqueKey(vulnerableDependency, vulnerableVersion, "XRAY-12143", false)
	assert.Equal(t, expectedKey, key)
}

func TestAppendUniqueImpactPathsForMultipleRoots(t *testing.T) {
	testCases := []struct {
		name           string
		target         [][]services.ImpactPathNode
		source         [][]services.ImpactPathNode
		expectedResult [][]services.ImpactPathNode
	}{
		{
			name: "subset is found in both target and source",
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}, {ComponentId: "C"}},
				{{ComponentId: "D"}, {ComponentId: "E"}},
			},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "B"}, {ComponentId: "C"}},
				{{ComponentId: "F"}, {ComponentId: "G"}},
			},
			expectedResult: [][]services.ImpactPathNode{
				{{ComponentId: "B"}, {ComponentId: "C"}},
				{{ComponentId: "D"}, {ComponentId: "E"}},
				{{ComponentId: "F"}, {ComponentId: "G"}},
			},
		},
		{
			name: "subset is not found in both target and source",
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}, {ComponentId: "C"}},
				{{ComponentId: "D"}, {ComponentId: "E"}},
			},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "B"}, {ComponentId: "C"}},
				{{ComponentId: "F"}, {ComponentId: "G"}},
			},
			expectedResult: [][]services.ImpactPathNode{
				{{ComponentId: "B"}, {ComponentId: "C"}},
				{{ComponentId: "D"}, {ComponentId: "E"}},
				{{ComponentId: "F"}, {ComponentId: "G"}},
			},
		},
		{
			name:   "target slice is empty",
			target: [][]services.ImpactPathNode{},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "E"}},
				{{ComponentId: "F"}, {ComponentId: "G"}},
			},
			expectedResult: [][]services.ImpactPathNode{
				{{ComponentId: "E"}},
				{{ComponentId: "F"}, {ComponentId: "G"}},
			},
		},
		{
			name: "source slice is empty",
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
			source: [][]services.ImpactPathNode{},
			expectedResult: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
		},
		{
			name: "target and source slices are identical",
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
			expectedResult: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
		},
		{
			name: "target and source slices contain multiple subsets",
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}, {ComponentId: "E"}},
				{{ComponentId: "C"}, {ComponentId: "D"}, {ComponentId: "F"}},
				{{ComponentId: "G"}, {ComponentId: "H"}},
			},
			expectedResult: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
				{{ComponentId: "G"}, {ComponentId: "H"}},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedResult, appendUniqueImpactPathsForMultipleRoots(test.target, test.source))
		})
	}
}

func TestGetImpactPathKey(t *testing.T) {
	testCases := []struct {
		path        []services.ImpactPathNode
		expectedKey string
	}{
		{
			path: []services.ImpactPathNode{
				{ComponentId: "A"},
				{ComponentId: "B"},
			},
			expectedKey: "B",
		},
		{
			path: []services.ImpactPathNode{
				{ComponentId: "A"},
			},
			expectedKey: "A",
		},
	}

	for _, test := range testCases {
		key := getImpactPathKey(test.path)
		assert.Equal(t, test.expectedKey, key)
	}
}

func TestAppendUniqueImpactPaths(t *testing.T) {
	testCases := []struct {
		name          string
		multipleRoots bool
		target        [][]services.ImpactPathNode
		source        [][]services.ImpactPathNode
		expected      [][]services.ImpactPathNode
	}{
		{
			name:          "Test case 1: Unique impact paths found",
			multipleRoots: false,
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}},
				{{ComponentId: "B"}},
			},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "C"}},
				{{ComponentId: "D"}},
			},
			expected: [][]services.ImpactPathNode{
				{{ComponentId: "A"}},
				{{ComponentId: "B"}},
				{{ComponentId: "C"}},
				{{ComponentId: "D"}},
			},
		},
		{
			name:          "Test case 2: No unique impact paths found",
			multipleRoots: false,
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}},
				{{ComponentId: "B"}},
			},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "A"}},
				{{ComponentId: "B"}},
			},
			expected: [][]services.ImpactPathNode{
				{{ComponentId: "A"}},
				{{ComponentId: "B"}},
			},
		},
		{
			name:          "Test case 3: paths in source are not in target",
			multipleRoots: false,
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "E"}},
				{{ComponentId: "F"}, {ComponentId: "G"}},
			},
			expected: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
				{{ComponentId: "E"}},
				{{ComponentId: "F"}, {ComponentId: "G"}},
			},
		},
		{
			name:          "Test case 4: paths in source are already in target",
			multipleRoots: false,
			target: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
			source: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
			expected: [][]services.ImpactPathNode{
				{{ComponentId: "A"}, {ComponentId: "B"}},
				{{ComponentId: "C"}, {ComponentId: "D"}},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := appendUniqueImpactPaths(tc.target, tc.source, tc.multipleRoots)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetSeveritiesFormat(t *testing.T) {
	testCases := []struct {
		input          string
		expectedOutput string
		expectedError  error
	}{
		// Test supported severity
		{input: "critical", expectedOutput: "Critical", expectedError: nil},
		{input: "hiGH", expectedOutput: "High", expectedError: nil},
		{input: "Low", expectedOutput: "Low", expectedError: nil},
		{input: "MedIum", expectedOutput: "Medium", expectedError: nil},
		{input: "", expectedOutput: "", expectedError: nil},
		// Test unsupported severity
		{input: "invalid_severity", expectedOutput: "", expectedError: errors.New("only the following severities are supported")},
	}

	for _, tc := range testCases {
		output, err := GetSeveritiesFormat(tc.input)
		if err != nil {
			assert.Contains(t, err.Error(), tc.expectedError.Error())
		} else {
			assert.Equal(t, tc.expectedError, err)
		}
		assert.Equal(t, tc.expectedOutput, output)
	}
}

func TestGetApplicableCveValue(t *testing.T) {
	testCases := []struct {
		name           string
		scanResults    *ExtendedScanResults
		cves           []services.Cve
		expectedResult jasutils.ApplicabilityStatus
		expectedCves   []formats.CveRow
	}{
		{
			name:           "not entitled for jas",
			scanResults:    &ExtendedScanResults{EntitledForJas: false},
			expectedResult: jasutils.NotScanned,
		},
		{
			name: "no cves",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithOneLocation("fileName1", 0, 1, 0, 0, "snippet1", "applic_testCve1", "info"),
						sarifutils.CreateDummyPassingResult("applic_testCve2"),
					),
				},
				EntitledForJas: true,
			},
			cves:           nil,
			expectedResult: jasutils.NotCovered,
			expectedCves:   nil,
		},
		{
			name: "applicable cve",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateDummyPassingResult("applic_testCve1"),
						sarifutils.CreateResultWithOneLocation("fileName2", 1, 0, 0, 0, "snippet2", "applic_testCve2", "warning"),
					),
				},
				EntitledForJas: true,
			},
			cves:           []services.Cve{{Id: "testCve2"}},
			expectedResult: jasutils.Applicable,
			expectedCves:   []formats.CveRow{{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.Applicable)}}},
		},
		{
			name: "undetermined cve",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateDummyPassingResult("applic_testCve1"),
						sarifutils.CreateResultWithOneLocation("fileName3", 0, 1, 0, 0, "snippet3", "applic_testCve2", "info"),
					),
				},
				EntitledForJas: true,
			},
			cves:           []services.Cve{{Id: "testCve3"}},
			expectedResult: jasutils.ApplicabilityUndetermined,
			expectedCves:   []formats.CveRow{{Id: "testCve3"}},
		},
		{
			name: "not applicable cve",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateDummyPassingResult("applic_testCve1"),
						sarifutils.CreateDummyPassingResult("applic_testCve2"),
					),
				},
				EntitledForJas: true,
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.NotApplicable,
			expectedCves:   []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}}, {Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}}},
		},
		{
			name: "applicable and not applicable cves",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateDummyPassingResult("applic_testCve1"),
						sarifutils.CreateResultWithOneLocation("fileName4", 1, 0, 0, 0, "snippet", "applic_testCve2", "warning"),
					),
				},
				EntitledForJas: true,
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.Applicable,
			expectedCves:   []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}}, {Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.Applicable)}}},
		},
		{
			name: "undetermined and not applicable cves",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyPassingResult("applic_testCve1")),
				},
				EntitledForJas: true},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.ApplicabilityUndetermined,
			expectedCves:   []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}}, {Id: "testCve2"}},
		},
		{
			name: "new scan statuses - applicable wins all statuses",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResultAndRuleProperties("applicability", "applicable", sarifutils.CreateDummyPassingResult("applic_testCve1")),
					sarifutils.CreateRunWithDummyResultAndRuleProperties("applicability", "not_applicable", sarifutils.CreateDummyPassingResult("applic_testCve2")),
					sarifutils.CreateRunWithDummyResultAndRuleProperties("applicability", "not_covered", sarifutils.CreateDummyPassingResult("applic_testCve3")),
				},
				EntitledForJas: true},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}, {Id: "testCve3"}},
			expectedResult: jasutils.Applicable,
			expectedCves: []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.Applicable)}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.NotCovered)}},
			},
		},
		{
			name: "new scan statuses - not covered wins not applicable",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResultAndRuleProperties("applicability", "not_covered", sarifutils.CreateDummyPassingResult("applic_testCve1")),
					sarifutils.CreateRunWithDummyResultAndRuleProperties("applicability", "not_applicable", sarifutils.CreateDummyPassingResult("applic_testCve2")),
				},
				EntitledForJas: true},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.NotCovered,
			expectedCves: []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotCovered)}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}},
			},
		},
		{
			name: "new scan statuses - undetermined wins not covered",
			scanResults: &ExtendedScanResults{
				ApplicabilityScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResultAndRuleProperties("applicability", "not_covered", sarifutils.CreateDummyPassingResult("applic_testCve1")),
					sarifutils.CreateRunWithDummyResultAndRuleProperties("applicability", "undetermined", sarifutils.CreateDummyPassingResult("applic_testCve2")),
				},
				EntitledForJas: true},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.ApplicabilityUndetermined,
			expectedCves: []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotCovered)}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.ApplicabilityUndetermined)}},
			},
		},
	}

	for _, testCase := range testCases {
		cves := convertCves(testCase.cves)
		for i := range cves {
			cves[i].Applicability = GetCveApplicabilityField(cves[i].Id, testCase.scanResults.ApplicabilityScanResults, nil)
		}
		applicableValue := getApplicableCveStatus(testCase.scanResults.EntitledForJas, testCase.scanResults.ApplicabilityScanResults, cves)
		assert.Equal(t, testCase.expectedResult, applicableValue)
		if assert.True(t, len(testCase.expectedCves) == len(cves)) {
			for i := range cves {
				if testCase.expectedCves[i].Applicability != nil && assert.NotNil(t, cves[i].Applicability) {
					assert.Equal(t, testCase.expectedCves[i].Applicability.Status, cves[i].Applicability.Status)
				}
			}
		}
	}
}

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

func TestShouldDisqualifyEvidence(t *testing.T) {
	testCases := []struct {
		name       string
		component  map[string]services.Component
		filePath   string
		disqualify bool
	}{
		{
			name:       "package folders",
			component:  map[string]services.Component{"npm://protobufjs:6.11.2": {}},
			filePath:   "file:///Users/jfrog/test/node_modules/protobufjs/src/badCode.js",
			disqualify: true,
		}, {
			name:       "nested folders",
			component:  map[string]services.Component{"npm://protobufjs:6.11.2": {}},
			filePath:   "file:///Users/jfrog/test/node_modules/someDep/node_modules/protobufjs/src/badCode.js",
			disqualify: true,
		}, {
			name:       "applicability in node modules",
			component:  map[string]services.Component{"npm://protobufjs:6.11.2": {}},
			filePath:   "file:///Users/jfrog/test/node_modules/mquery/src/badCode.js",
			disqualify: false,
		}, {
			// Only npm supported
			name:       "not npm",
			component:  map[string]services.Component{"yarn://protobufjs:6.11.2": {}},
			filePath:   "file:///Users/jfrog/test/node_modules/protobufjs/src/badCode.js",
			disqualify: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.disqualify, shouldDisqualifyEvidence(tc.component, tc.filePath))
		})
	}
}
