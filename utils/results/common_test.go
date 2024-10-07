package results

import (
	"path/filepath"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestViolationFailBuild(t *testing.T) {
	components := map[string]services.Component{"gav://antparent:ant:1.6.5": {}}
	tests := []struct {
		violations    []services.Violation
		expectedError bool
	}{
		{[]services.Violation{{Components: components, FailBuild: false}, {Components: components, FailBuild: false}, {Components: components, FailBuild: false}}, false},
		{[]services.Violation{{Components: components, FailBuild: false}, {Components: components, FailBuild: true}, {Components: components, FailBuild: false}}, true},
		{[]services.Violation{{Components: components, FailBuild: true}, {Components: components, FailBuild: true}, {Components: components, FailBuild: true}}, true},
	}

	for _, test := range tests {
		var err error
		if CheckIfFailBuild([]services.ScanResponse{{Violations: test.violations}}) {
			err = NewFailBuildError()
		}
		assert.Equal(t, test.expectedError, err != nil)
	}
}

func TestFindMaxCVEScore(t *testing.T) {
	testCases := []struct {
		name           string
		severity       severityutils.Severity
		status         jasutils.ApplicabilityStatus
		cves           []formats.CveRow
		expectedOutput string
		expectedError  bool
	}{
		{
			name:           "CVEScore with valid float values",
			severity:       severityutils.High,
			status:         jasutils.Applicable,
			cves:           []formats.CveRow{{Id: "CVE-2021-1234", CvssV3: "7.5"}, {Id: "CVE-2021-5678", CvssV3: "9.2"}},
			expectedOutput: "9.2",
		},
		{
			name:           "CVEScore with invalid float value",
			severity:       severityutils.High,
			status:         jasutils.Applicable,
			cves:           []formats.CveRow{{Id: "CVE-2022-4321", CvssV3: "invalid"}},
			expectedOutput: "",
			expectedError:  true,
		},
		{
			name:           "CVEScore without values",
			severity:       severityutils.High,
			status:         jasutils.Applicable,
			cves:           []formats.CveRow{},
			expectedOutput: "8.9",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := FindMaxCVEScore(tc.severity, tc.status, tc.cves)
			assert.False(t, tc.expectedError && err == nil)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestGetIssueIdentifier(t *testing.T) {
	testCases := []struct {
		name           string
		cves           []formats.CveRow
		delimiter      string
		issueId        string
		expectedOutput string
	}{
		{
			name:           "Single CVE",
			cves:           []formats.CveRow{{Id: "CVE-2022-1234"}},
			delimiter:      ",",
			issueId:        "XRAY-123456",
			expectedOutput: "CVE-2022-1234",
		},
		{
			name:           "Multiple CVEs",
			cves:           []formats.CveRow{{Id: "CVE-2022-1234"}, {Id: "CVE-2019-1234"}},
			delimiter:      ", ",
			issueId:        "XRAY-123456",
			expectedOutput: "CVE-2022-1234, CVE-2019-1234",
		},
		{
			name:           "No CVEs",
			cves:           nil,
			delimiter:      ", ",
			issueId:        "XRAY-123456",
			expectedOutput: "XRAY-123456",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := GetIssueIdentifier(tc.cves, tc.issueId, tc.delimiter)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

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
			assert.Equal(t, test.expectedResult, AppendUniqueImpactPathsForMultipleRoots(test.target, test.source))
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
			result := AppendUniqueImpactPaths(tc.target, tc.source, tc.multipleRoots)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetApplicableCveValue(t *testing.T) {
	testCases := []struct {
		name                     string
		entitledForJas           bool
		applicabilityScanResults []*sarif.Run
		cves                     []services.Cve
		components               map[string]services.Component
		expectedResult           jasutils.ApplicabilityStatus
		expectedCves             []formats.CveRow
	}{
		{
			name:           "not entitled for jas",
			entitledForJas: false,
			expectedResult: jasutils.NotScanned,
		},
		{
			name:           "no cves",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithOneLocation("fileName1", 0, 1, 0, 0, "snippet1", "applic_testCve1", "info"),
					sarifutils.CreateDummyPassingResult("applic_testCve2"),
				),
			},
			cves:           nil,
			expectedResult: jasutils.NotCovered,
			expectedCves:   nil,
		},
		{
			name:           "applicable cve",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_testCve1"),
					sarifutils.CreateResultWithOneLocation("fileName2", 1, 0, 0, 0, "snippet2", "applic_testCve2", "warning"),
				),
			},
			cves:           []services.Cve{{Id: "testCve2"}},
			expectedResult: jasutils.Applicable,
			expectedCves: []formats.CveRow{{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.Applicable), Evidence: []formats.Evidence{{
				Location: formats.Location{
					File:      "fileName2",
					StartLine: 1,
					Snippet:   "snippet2",
				},
			}}}}},
		},
		{
			name:           "missing context cve",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve1"), []string{"applicability"}, []string{"missing_context"}),
			},
			cves:           []services.Cve{{Id: "testCve1"}},
			expectedResult: jasutils.MissingContext,
			expectedCves:   []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: jasutils.MissingContext.String()}}},
		},
		{
			name:           "undetermined cve",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_testCve1"),
					sarifutils.CreateResultWithOneLocation("fileName3", 0, 1, 0, 0, "snippet3", "applic_testCve2", "info"),
				),
			},
			cves:           []services.Cve{{Id: "testCve3"}},
			expectedResult: jasutils.ApplicabilityUndetermined,
			expectedCves:   []formats.CveRow{{Id: "testCve3"}},
		},
		{
			name:           "not applicable cve",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_testCve1"),
					sarifutils.CreateDummyPassingResult("applic_testCve2"),
				),
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.NotApplicable,
			expectedCves:   []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}}, {Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}}},
		},
		{
			name:           "applicable and not applicable cves",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_testCve1"),
					sarifutils.CreateResultWithOneLocation("fileName4", 1, 0, 0, 0, "snippet", "applic_testCve2", "warning"),
				),
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.Applicable,
			expectedCves: []formats.CveRow{
				{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.Applicable),
					Evidence: []formats.Evidence{{Location: formats.Location{File: "fileName4", StartLine: 1, Snippet: "snippet"}}},
				}},
			},
		},
		{
			name:           "undetermined and not applicable cves",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyPassingResult("applic_testCve1")),
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.ApplicabilityUndetermined,
			expectedCves:   []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}}, {Id: "testCve2"}},
		},
		{
			name:           "new scan statuses - applicable wins all statuses",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve1"), []string{"applicability"}, []string{"applicable"}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve2"), []string{"applicability"}, []string{"not_applicable"}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve3"), []string{"applicability"}, []string{"not_covered"}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve4"), []string{"applicability"}, []string{"missing_context"}),
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}, {Id: "testCve3"}, {Id: "testCve4"}},
			expectedResult: jasutils.Applicable,
			expectedCves: []formats.CveRow{
				{Id: "testCve1", Applicability: &formats.Applicability{Status: jasutils.Applicable.String()}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: jasutils.NotApplicable.String()}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: jasutils.NotCovered.String()}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: jasutils.MissingContext.String()}},
			},
		},
		{
			name:           "new scan statuses - not covered wins not applicable",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve1"), []string{"applicability"}, []string{"not_covered"}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve2"), []string{"applicability"}, []string{"not_applicable"}),
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.NotCovered,
			expectedCves: []formats.CveRow{
				{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotCovered)}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}},
			},
		},
		{
			name:           "new scan statuses - undetermined wins not covered",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve1"), []string{"applicability"}, []string{"not_covered"}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve2"), []string{"applicability"}, []string{"undetermined"}),
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.ApplicabilityUndetermined,
			expectedCves: []formats.CveRow{
				{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotCovered)}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.ApplicabilityUndetermined)}},
			},
		},
		{
			name:           "new scan statuses - missing context wins not covered",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve1"), []string{"applicability"}, []string{"missing_context"}),
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve2"), []string{"applicability"}, []string{"not_covered"}),
			},
			cves:           []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			expectedResult: jasutils.MissingContext,
			expectedCves: []formats.CveRow{{Id: "testCve1", Applicability: &formats.Applicability{Status: jasutils.MissingContext.String()}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: jasutils.NotCovered.String()}},
			},
		},
		{
			name:           "undetermined with undetermined reason",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleProperties(sarifutils.CreateDummyPassingResult("applic_testCve2"), []string{"applicability", "undetermined_reason"}, []string{"undetermined", "however"}),
			},
			cves:           []services.Cve{{Id: "testCve2"}},
			expectedResult: jasutils.ApplicabilityUndetermined,
			expectedCves: []formats.CveRow{
				{Id: "testCve2", Applicability: &formats.Applicability{Status: jasutils.ApplicabilityUndetermined.String(), UndeterminedReason: "however"}},
			},
		},
		{
			name:           "disqualified evidence",
			entitledForJas: true,
			applicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_testCve1"),
					sarifutils.CreateResultWithOneLocation("fileName4", 1, 0, 0, 0, "snippet", "applic_testCve2", "warning"),
				),
			},
			cves: []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}},
			components: map[string]services.Component{
				"npm://protobufjs:6.11.2": {ImpactPaths: [][]services.ImpactPathNode{{services.ImpactPathNode{FullPath: "fileName4", ComponentId: "npm://mquery:3.2.2"}}}},
				"npm://mquery:3.2.2":      {},
			},
			expectedResult: jasutils.Applicable,
			expectedCves: []formats.CveRow{
				{Id: "testCve1", Applicability: &formats.Applicability{Status: string(jasutils.NotApplicable)}},
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.Applicable), Evidence: []formats.Evidence{{Location: formats.Location{File: "fileName4", StartLine: 1, Snippet: "snippet"}}}}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cves := convertCves(testCase.cves)
			for i := range cves {
				cves[i].Applicability = GetCveApplicabilityField(cves[i].Id, testCase.applicabilityScanResults, testCase.components)
			}
			applicableValue := GetApplicableCveStatus(testCase.entitledForJas, testCase.applicabilityScanResults, cves)
			assert.Equal(t, testCase.expectedResult, applicableValue)
			if assert.True(t, len(testCase.expectedCves) == len(cves)) {
				for i := range cves {
					if testCase.expectedCves[i].Applicability != nil && assert.NotNil(t, cves[i].Applicability) {
						assert.Equal(t, testCase.expectedCves[i].Applicability.Status, cves[i].Applicability.Status)
						assert.ElementsMatch(t, testCase.expectedCves[i].Applicability.Evidence, cves[i].Applicability.Evidence)
					}
				}
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

func TestGetDirectComponents(t *testing.T) {
	tests := []struct {
		name                        string
		target                      string
		impactPaths                 [][]services.ImpactPathNode
		expectedDirectComponentRows []formats.ComponentRow
		expectedConvImpactPaths     [][]formats.ComponentRow
	}{
		{
			name:                        "one direct component",
			impactPaths:                 [][]services.ImpactPathNode{{services.ImpactPathNode{ComponentId: "gav://jfrog:pack:1.2.3"}}},
			expectedDirectComponentRows: []formats.ComponentRow{{Name: "jfrog:pack", Version: "1.2.3"}},
			expectedConvImpactPaths:     [][]formats.ComponentRow{{{Name: "jfrog:pack", Version: "1.2.3"}}},
		},
		{
			name:                        "one direct component with target",
			target:                      filepath.Join("root", "dir", "file"),
			impactPaths:                 [][]services.ImpactPathNode{{services.ImpactPathNode{ComponentId: "gav://jfrog:pack1:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack2:1.2.3"}}},
			expectedDirectComponentRows: []formats.ComponentRow{{Name: "jfrog:pack2", Version: "1.2.3", Location: &formats.Location{File: filepath.Join("root", "dir", "file")}}},
			expectedConvImpactPaths:     [][]formats.ComponentRow{{{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack2", Version: "1.2.3"}}},
		},
		{
			name:        "multiple direct components",
			target:      filepath.Join("root", "dir", "file"),
			impactPaths: [][]services.ImpactPathNode{{services.ImpactPathNode{ComponentId: "gav://jfrog:pack1:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack21:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack3:1.2.3"}}, {services.ImpactPathNode{ComponentId: "gav://jfrog:pack1:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack22:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack3:1.2.3"}}},
			expectedDirectComponentRows: []formats.ComponentRow{
				{Name: "jfrog:pack21", Version: "1.2.3", Location: &formats.Location{File: filepath.Join("root", "dir", "file")}},
				{Name: "jfrog:pack22", Version: "1.2.3", Location: &formats.Location{File: filepath.Join("root", "dir", "file")}},
			},
			expectedConvImpactPaths: [][]formats.ComponentRow{{{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack21", Version: "1.2.3"}, {Name: "jfrog:pack3", Version: "1.2.3"}}, {{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack22", Version: "1.2.3"}, {Name: "jfrog:pack3", Version: "1.2.3"}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualComponentRows, actualConvImpactPaths := getDirectComponentsAndImpactPaths(test.target, test.impactPaths)
			assert.ElementsMatch(t, test.expectedDirectComponentRows, actualComponentRows)
			assert.ElementsMatch(t, test.expectedConvImpactPaths, actualConvImpactPaths)
		})
	}
}

func TestGetFinalApplicabilityStatus(t *testing.T) {
	testCases := []struct {
		name           string
		input          []jasutils.ApplicabilityStatus
		expectedOutput jasutils.ApplicabilityStatus
	}{
		{
			name:           "applicable wins all statuses",
			input:          []jasutils.ApplicabilityStatus{jasutils.ApplicabilityUndetermined, jasutils.Applicable, jasutils.NotCovered, jasutils.NotApplicable},
			expectedOutput: jasutils.Applicable,
		},
		{
			name:           "undetermined wins not covered",
			input:          []jasutils.ApplicabilityStatus{jasutils.NotCovered, jasutils.ApplicabilityUndetermined, jasutils.NotCovered, jasutils.NotApplicable},
			expectedOutput: jasutils.ApplicabilityUndetermined,
		},
		{
			name:           "not covered wins not applicable",
			input:          []jasutils.ApplicabilityStatus{jasutils.NotApplicable, jasutils.NotCovered, jasutils.NotApplicable},
			expectedOutput: jasutils.NotCovered,
		},
		{
			name:           "all statuses are not applicable",
			input:          []jasutils.ApplicabilityStatus{jasutils.NotApplicable, jasutils.NotApplicable, jasutils.NotApplicable},
			expectedOutput: jasutils.NotApplicable,
		},
		{
			name:           "no statuses",
			input:          []jasutils.ApplicabilityStatus{},
			expectedOutput: jasutils.NotScanned,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedOutput, getFinalApplicabilityStatus(tc.input))
		})
	}
}
