package results

import (
	"path"
	"path/filepath"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
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

func TestGetCveApplicabilityFieldAndFilterDisqualify(t *testing.T) {
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
				Reason: "result-msg",
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
					Evidence: []formats.Evidence{{Reason: "result-msg", Location: formats.Location{File: "fileName4", StartLine: 1, Snippet: "snippet"}}},
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
				{Id: "testCve2", Applicability: &formats.Applicability{Status: string(jasutils.Applicable), Evidence: []formats.Evidence{{Reason: "result-msg", Location: formats.Location{File: "fileName4", StartLine: 1, Snippet: "snippet"}}}}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cves := convertCves(testCase.cves)
			for i := range cves {
				cves[i].Applicability = GetCveApplicabilityFieldAndFilterDisqualify(cves[i].Id, testCase.applicabilityScanResults, testCase.components)
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

func TestExtractXrayDirectViolations(t *testing.T) {
	var xrayResponseForDirectViolationsTest = []services.ScanResponse{
		{
			Violations: []services.Violation{
				{IssueId: "issueId_2", Technology: techutils.Pipenv.String(),
					Cves:       []services.Cve{{Id: "testCve4"}, {Id: "testCve5"}},
					Components: map[string]services.Component{"issueId_2_direct_dependency": {}}},
			},
		},
	}
	tests := []struct {
		directDependencies []string
		directCvesCount    int
		indirectCvesCount  int
	}{
		{directDependencies: []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"},
			directCvesCount:   2,
			indirectCvesCount: 0,
		},
		// Vulnerability dependency, should be ignored by function
		{directDependencies: []string{"issueId_1_direct_dependency"},
			directCvesCount:   0,
			indirectCvesCount: 2,
		},
		{directDependencies: []string{},
			directCvesCount:   0,
			indirectCvesCount: 2,
		},
	}

	for _, test := range tests {
		directCves, indirectCves := ExtractCvesFromScanResponse(xrayResponseForDirectViolationsTest, test.directDependencies)
		assert.Len(t, directCves, test.directCvesCount)
		assert.Len(t, indirectCves, test.indirectCvesCount)
	}
}

func TestExtractXrayDirectVulnerabilities(t *testing.T) {
	var xrayResponseForDirectVulnerabilitiesTest = []services.ScanResponse{
		{
			ScanId: "scanId_1",
			Vulnerabilities: []services.Vulnerability{
				{
					IssueId: "issueId_1", Technology: techutils.Pipenv.String(),
					Cves:       []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}, {Id: "testCve3"}},
					Components: map[string]services.Component{"issueId_1_direct_dependency": {}},
				},
				{
					IssueId: "issueId_2", Technology: techutils.Pipenv.String(),
					Cves:       []services.Cve{{Id: "testCve4"}, {Id: "testCve5"}},
					Components: map[string]services.Component{"issueId_2_direct_dependency": {}},
				},
			},
		},
	}
	tests := []struct {
		directDependencies []string
		directCvesCount    int
		indirectCvesCount  int
	}{
		{
			directDependencies: []string{"issueId_1_direct_dependency"},
			directCvesCount:    3,
			indirectCvesCount:  2,
		},
		{
			directDependencies: []string{"issueId_2_direct_dependency"},
			directCvesCount:    2,
			indirectCvesCount:  3,
		},
		{directDependencies: []string{},
			directCvesCount:   0,
			indirectCvesCount: 5,
		},
	}

	for _, test := range tests {
		directCves, indirectCves := ExtractCvesFromScanResponse(xrayResponseForDirectVulnerabilitiesTest, test.directDependencies)
		assert.Len(t, directCves, test.directCvesCount)
		assert.Len(t, indirectCves, test.indirectCvesCount)
	}
}

func TestSearchTargetResultsByRelativePath(t *testing.T) {
	oneTargetCmdResults := NewCommandResults(utils.SourceCode)
	oneTargetCmdResults.NewScanResults(ScanTarget{Target: path.Join("root", "path", "to", "dir")})

	multiTargetCmdResults := NewCommandResults(utils.SourceCode)
	multiTargetCmdResults.NewScanResults(ScanTarget{Target: path.Join("root", "dir")})
	multiTargetCmdResults.NewScanResults(ScanTarget{Target: path.Join("root", "another", "dir")})

	testCases := []struct {
		name          string
		target        string
		cmdResults    *SecurityCommandResults
		expectedFound bool
	}{
		{
			name:          "One target in results - same path",
			target:        path.Join("root", "path", "to", "dir"),
			cmdResults:    oneTargetCmdResults,
			expectedFound: true,
		},
		{
			name:          "One target in results - same relative",
			target:        path.Join("path", "to", "dir"),
			cmdResults:    oneTargetCmdResults,
			expectedFound: false,
		},
		{
			name:          "One target in results - not found",
			target:        path.Join("some", "scan-dir"),
			cmdResults:    oneTargetCmdResults,
			expectedFound: false,
		},
		{
			name:          "Multiple targets in results - same path",
			target:        path.Join("root", "dir"),
			cmdResults:    multiTargetCmdResults,
			expectedFound: true,
		},
		{
			name:          "Multiple targets in results - same relative",
			target:        path.Join("another", "dir"),
			cmdResults:    multiTargetCmdResults,
			expectedFound: true,
		},
		{
			name:          "Multiple targets in results - not found",
			target:        path.Join("a", "scan-dir"),
			cmdResults:    multiTargetCmdResults,
			expectedFound: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			foundTarget := SearchTargetResultsByRelativePath(tc.target, tc.cmdResults)
			assert.Equal(t, tc.expectedFound, foundTarget != nil)
		})
	}
}

func TestDepTreeToSbom(t *testing.T) {
	tests := []struct {
		name                 string
		depTrees             []*xrayUtils.GraphNode
		expectedComponents   *[]cyclonedx.Component
		expectedDependencies *[]cyclonedx.Dependency
	}{
		{
			name:     "empty dep trees",
			depTrees: []*xrayUtils.GraphNode{},
		},
		{
			name: "no deps",
			depTrees: []*xrayUtils.GraphNode{
				{
					Id:    "npm://root:1.0.0",
					Nodes: []*xrayUtils.GraphNode{},
				},
			},
			expectedComponents: &[]cyclonedx.Component{
				{
					// Root
					PackageURL: "pkg:npm/root@1.0.0",
					BOMRef:     "npm:root:1.0.0",
					Name:       "root",
					Version:    "1.0.0",
					Type:       "library",
				},
			},
		},
		{
			name: "one tree with one node",
			depTrees: []*xrayUtils.GraphNode{
				{
					Id:    "npm://root:1.0.0",
					Nodes: []*xrayUtils.GraphNode{{Id: "npm://A:1.0.1"}},
				},
			},
			expectedComponents: &[]cyclonedx.Component{
				{
					// Root
					PackageURL: "pkg:npm/root@1.0.0",
					BOMRef:     "npm:root:1.0.0",
					Name:       "root",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Direct
					PackageURL: "pkg:npm/A@1.0.1",
					BOMRef:     "npm:A:1.0.1",
					Name:       "A",
					Version:    "1.0.1",
					Type:       "library",
				},
			},
			expectedDependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "npm:root:1.0.0",
					Dependencies: &[]string{"npm:A:1.0.1"},
				},
			},
		},
		{
			name: "one tree with multiple nodes",
			depTrees: []*xrayUtils.GraphNode{
				{
					Id: "npm://root:1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "npm://A:1.0.1",
							Nodes: []*xrayUtils.GraphNode{{Id: "npm://B:1.0.0"}, {Id: "npm://C:1.0.1"}},
						},
						{
							Id:    "npm://D:2.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "npm://C:1.0.1"}},
						},
						{
							Id: "npm://B:1.0.0",
						},
					},
				},
			},
			expectedComponents: &[]cyclonedx.Component{
				{
					// Root
					PackageURL: "pkg:npm/root@1.0.0",
					BOMRef:     "npm:root:1.0.0",
					Name:       "root",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Direct
					PackageURL: "pkg:npm/A@1.0.1",
					BOMRef:     "npm:A:1.0.1",
					Name:       "A",
					Version:    "1.0.1",
					Type:       "library",
				},
				{
					// Direct
					PackageURL: "pkg:npm/B@1.0.0",
					BOMRef:     "npm:B:1.0.0",
					Name:       "B",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Indirect
					PackageURL: "pkg:npm/C@1.0.1",
					BOMRef:     "npm:C:1.0.1",
					Name:       "C",
					Version:    "1.0.1",
					Type:       "library",
				},
				{
					// Direct
					PackageURL: "pkg:npm/D@2.0.0",
					BOMRef:     "npm:D:2.0.0",
					Name:       "D",
					Version:    "2.0.0",
					Type:       "library",
				},
			},
			expectedDependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "npm:root:1.0.0",
					Dependencies: &[]string{"npm:A:1.0.1", "npm:D:2.0.0", "npm:B:1.0.0"},
				},
				{
					Ref:          "npm:A:1.0.1",
					Dependencies: &[]string{"npm:B:1.0.0", "npm:C:1.0.1"},
				},
				{
					Ref:          "npm:D:2.0.0",
					Dependencies: &[]string{"npm:C:1.0.1"},
				},
			},
		},
		{
			name: "multiple trees",
			depTrees: []*xrayUtils.GraphNode{
				{
					Id: "npm://npm-app-root:1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "npm://A:1.0.1",
							Nodes: []*xrayUtils.GraphNode{{Id: "npm://B:1.0.0"}},
						},
						{
							Id: "npm://C:1.0.1",
						},
						{
							Id: "npm://D:1.0.0",
						},
					},
				},
				{
					Id: "go://go-app-root:1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "go://A:2.0.1",
							Nodes: []*xrayUtils.GraphNode{{Id: "go://B:1.0.0"}, {Id: "go://C:1.0.1"}, {Id: "go://D:1.2.3"}},
						},
					},
				},
			},
			expectedComponents: &[]cyclonedx.Component{
				{
					// Root
					PackageURL: "pkg:npm/npm-app-root@1.0.0",
					BOMRef:     "npm:npm-app-root:1.0.0",
					Name:       "npm-app-root",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Direct
					PackageURL: "pkg:npm/A@1.0.1",
					BOMRef:     "npm:A:1.0.1",
					Name:       "A",
					Version:    "1.0.1",
					Type:       "library",
				},
				{
					// Indirect
					PackageURL: "pkg:npm/B@1.0.0",
					BOMRef:     "npm:B:1.0.0",
					Name:       "B",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Direct
					PackageURL: "pkg:npm/C@1.0.1",
					BOMRef:     "npm:C:1.0.1",
					Name:       "C",
					Version:    "1.0.1",
					Type:       "library",
				},
				{
					// Direct
					PackageURL: "pkg:npm/D@1.0.0",
					BOMRef:     "npm:D:1.0.0",
					Name:       "D",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Root
					PackageURL: "pkg:golang/go-app-root@1.0.0",
					BOMRef:     "golang:go-app-root:1.0.0",
					Name:       "go-app-root",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Direct
					PackageURL: "pkg:golang/A@2.0.1",
					BOMRef:     "golang:A:2.0.1",
					Name:       "A",
					Version:    "2.0.1",
					Type:       "library",
				},
				{
					// Indirect
					PackageURL: "pkg:golang/B@1.0.0",
					BOMRef:     "golang:B:1.0.0",
					Name:       "B",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Indirect
					PackageURL: "pkg:golang/C@1.0.1",
					BOMRef:     "golang:C:1.0.1",
					Name:       "C",
					Version:    "1.0.1",
					Type:       "library",
				},
				{
					// Indirect
					PackageURL: "pkg:golang/D@1.2.3",
					BOMRef:     "golang:D:1.2.3",
					Name:       "D",
					Version:    "1.2.3",
					Type:       "library",
				},
			},
			expectedDependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "npm:npm-app-root:1.0.0",
					Dependencies: &[]string{"npm:A:1.0.1", "npm:C:1.0.1", "npm:D:1.0.0"},
				},
				{
					Ref:          "npm:A:1.0.1",
					Dependencies: &[]string{"npm:B:1.0.0"},
				},
				{
					Ref:          "golang:go-app-root:1.0.0",
					Dependencies: &[]string{"golang:A:2.0.1"},
				},
				{
					Ref:          "golang:A:2.0.1",
					Dependencies: &[]string{"golang:B:1.0.0", "golang:C:1.0.1", "golang:D:1.2.3"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			components, dependencies := DepsTreeToSbom(test.depTrees...)
			assert.Equal(t, test.expectedComponents, components)
			assert.Equal(t, test.expectedDependencies, dependencies)
		})
	}
}

func TestCompTreeToSbom(t *testing.T) {
	tests := []struct {
		name                 string
		compTrees            []*xrayUtils.BinaryGraphNode
		expectedComponents   *[]cyclonedx.Component
		expectedDependencies *[]cyclonedx.Dependency
	}{
		{
			name:      "empty component trees",
			compTrees: []*xrayUtils.BinaryGraphNode{},
		},
		{
			name: "no deps",
			compTrees: []*xrayUtils.BinaryGraphNode{
				{
					Id:       "gav://jar-app:3.12",
					Path:     "jar-app-3.12.jar",
					Sha1:     "1234567890abcdef1234567890abcdef12345678",
					Sha256:   "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					Licenses: []string{"Apache-2.0"},
				},
			},
			expectedComponents: &[]cyclonedx.Component{
				{
					PackageURL: "pkg:maven/jar-app@3.12",
					BOMRef:     "maven:jar-app:3.12",
					Name:       "jar-app",
					Version:    "3.12",
					Type:       "library",
					Evidence: &cyclonedx.Evidence{
						Occurrences: &[]cyclonedx.EvidenceOccurrence{
							{
								Location: "jar-app-3.12.jar",
							},
						},
					},
					Licenses: &cyclonedx.Licenses{
						{
							License: &cyclonedx.License{ID: "Apache-2.0"},
						},
					},
					Hashes: &[]cyclonedx.Hash{
						{
							Algorithm: "SHA-1",
							Value:     "1234567890abcdef1234567890abcdef12345678",
						},
						{
							Algorithm: "SHA-256",
							Value:     "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						},
					},
				},
			},
		},
		{
			name: "one binary with one dependency",
			compTrees: []*xrayUtils.BinaryGraphNode{
				{
					Id:       "docker://my-docker-image:1.0.0",
					Path:     "my-docker-image-1.0.0.tar",
					Sha1:     "abcdef1234567890abcdef1234567890abcdef12",
					Sha256:   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
					Licenses: []string{"MIT"},
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id:     "docker://my-dependency:2.0.0",
							Path:   "my-docker-image-1.0.0.tar",
							Sha256: "456abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
						},
					},
				},
			},
			expectedComponents: &[]cyclonedx.Component{
				{
					// Root
					PackageURL: "pkg:docker/my-docker-image@1.0.0",
					BOMRef:     "docker:my-docker-image:1.0.0",
					Name:       "my-docker-image",
					Version:    "1.0.0",
					Type:       "library",
					Evidence: &cyclonedx.Evidence{
						Occurrences: &[]cyclonedx.EvidenceOccurrence{
							{
								Location: "my-docker-image-1.0.0.tar",
							},
						},
					},
					Licenses: &cyclonedx.Licenses{
						{
							License: &cyclonedx.License{ID: "MIT"},
						},
					},
					Hashes: &[]cyclonedx.Hash{
						{
							Algorithm: "SHA-1",
							Value:     "abcdef1234567890abcdef1234567890abcdef12",
						},
						{
							Algorithm: "SHA-256",
							Value:     "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
						},
					},
				},
				{
					// Dependency
					PackageURL: "pkg:docker/my-dependency@2.0.0",
					BOMRef:     "docker:my-dependency:2.0.0",
					Name:       "my-dependency",
					Version:    "2.0.0",
					Type:       "library",
					Evidence: &cyclonedx.Evidence{
						Occurrences: &[]cyclonedx.EvidenceOccurrence{
							{
								Location: "my-docker-image-1.0.0.tar",
							},
						},
					},
					Hashes: &[]cyclonedx.Hash{
						{
							Algorithm: "SHA-256",
							Value:     "456abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
						},
					},
				},
			},
			expectedDependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "docker:my-docker-image:1.0.0",
					Dependencies: &[]string{"docker:my-dependency:2.0.0"},
				},
			},
		},
		{
			name: "multiple binaries with multiple dependencies",
			compTrees: []*xrayUtils.BinaryGraphNode{
				{
					Id: "docker://my-docker-image:1.0.0",
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id: "docker://my-dependency:2.0.0",
							Nodes: []*xrayUtils.BinaryGraphNode{
								{Id: "docker://my-sub-dependency:3.0.0"},
								{Id: "docker://my-other-dependency:4.0.0"},
							},
						},
					},
				},
				{
					Id:   "gav://my-java-app:1.0.0",
					Path: "my-java-app.jar",
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id: "gav://my-java-dependency:2.0.0",
							Nodes: []*xrayUtils.BinaryGraphNode{
								{Id: "gav://my-java-sub-dependency:3.0.0"},
								{Id: "gav://dependency:4.0.0"},
							},
						},
						{
							Id: "gav://my-java-other-dependency:4.0.0",
							Nodes: []*xrayUtils.BinaryGraphNode{
								{Id: "gav://my-java-sub-dependency:3.0.0"},
							},
						},
						{
							Id: "gav://my-java-sub-dependency:3.0.0",
						},
					},
				},
			},
			expectedComponents: &[]cyclonedx.Component{
				{
					// Docker Root
					PackageURL: "pkg:docker/my-docker-image@1.0.0",
					BOMRef:     "docker:my-docker-image:1.0.0",
					Name:       "my-docker-image",
					Version:    "1.0.0",
					Type:       "library",
				},
				{
					// Docker Dependency
					PackageURL: "pkg:docker/my-dependency@2.0.0",
					BOMRef:     "docker:my-dependency:2.0.0",
					Name:       "my-dependency",
					Version:    "2.0.0",
					Type:       "library",
				},
				{
					// Docker Sub-dependency
					PackageURL: "pkg:docker/my-sub-dependency@3.0.0",
					BOMRef:     "docker:my-sub-dependency:3.0.0",
					Name:       "my-sub-dependency",
					Version:    "3.0.0",
					Type:       "library",
				},
				{
					// Docker Other Dependency
					PackageURL: "pkg:docker/my-other-dependency@4.0.0",
					BOMRef:     "docker:my-other-dependency:4.0.0",
					Name:       "my-other-dependency",
					Version:    "4.0.0",
					Type:       "library",
				},
				{
					// Jar Root
					PackageURL: "pkg:maven/my-java-app@1.0.0",
					BOMRef:     "maven:my-java-app:1.0.0",
					Name:       "my-java-app",
					Version:    "1.0.0",
					Type:       "library",
					Evidence: &cyclonedx.Evidence{
						Occurrences: &[]cyclonedx.EvidenceOccurrence{
							{
								Location: "my-java-app.jar",
							},
						},
					},
				},
				{
					// Jar Dependency
					PackageURL: "pkg:maven/my-java-dependency@2.0.0",
					BOMRef:     "maven:my-java-dependency:2.0.0",
					Name:       "my-java-dependency",
					Version:    "2.0.0",
					Type:       "library",
				},
				{
					// Jar Sub-dependency
					PackageURL: "pkg:maven/my-java-sub-dependency@3.0.0",
					BOMRef:     "maven:my-java-sub-dependency:3.0.0",
					Name:       "my-java-sub-dependency",
					Version:    "3.0.0",
					Type:       "library",
				},
				{
					// Jar Other Dependency
					PackageURL: "pkg:maven/dependency@4.0.0",
					BOMRef:     "maven:dependency:4.0.0",
					Name:       "dependency",
					Version:    "4.0.0",
					Type:       "library",
				},
				{
					// Jar Other Java Dependency
					PackageURL: "pkg:maven/my-java-other-dependency@4.0.0",
					BOMRef:     "maven:my-java-other-dependency:4.0.0",
					Name:       "my-java-other-dependency",
					Version:    "4.0.0",
					Type:       "library",
				},
			},
			expectedDependencies: &[]cyclonedx.Dependency{
				{
					Ref:          "docker:my-docker-image:1.0.0",
					Dependencies: &[]string{"docker:my-dependency:2.0.0"},
				},
				{
					Ref:          "docker:my-dependency:2.0.0",
					Dependencies: &[]string{"docker:my-sub-dependency:3.0.0", "docker:my-other-dependency:4.0.0"},
				},
				{
					Ref:          "maven:my-java-app:1.0.0",
					Dependencies: &[]string{"maven:my-java-dependency:2.0.0", "maven:my-java-other-dependency:4.0.0", "maven:my-java-sub-dependency:3.0.0"},
				},
				{
					Ref:          "maven:my-java-dependency:2.0.0",
					Dependencies: &[]string{"maven:my-java-sub-dependency:3.0.0", "maven:dependency:4.0.0"},
				},
				{
					Ref:          "maven:my-java-other-dependency:4.0.0",
					Dependencies: &[]string{"maven:my-java-sub-dependency:3.0.0"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			components, dependencies := CompTreeToSbom(test.compTrees...)
			assert.Equal(t, test.expectedComponents, components)
			assert.Equal(t, test.expectedDependencies, dependencies)
		})
	}
}

func TestIsMultiProject(t *testing.T) {
	tests := []struct {
		name     string
		bom      *cyclonedx.BOM
		expected bool
	}{
		{
			name: "no root",
		},
		{
			name: "single root",
			bom: &cyclonedx.BOM{
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root", Dependencies: &[]string{"dep1", "dep2", "dep3"}},
					{Ref: "dep2", Dependencies: &[]string{"dep3", "dep4"}},
					{Ref: "dep4", Dependencies: &[]string{"dep5"}},
				},
			},
			expected: false,
		},
		{
			name: "multiple roots",
			bom: &cyclonedx.BOM{
				Dependencies: &[]cyclonedx.Dependency{
					{Ref: "root1", Dependencies: &[]string{"dep1", "dep2"}},
					{Ref: "root2", Dependencies: &[]string{"dep3", "dep4"}},
					{Ref: "dep2", Dependencies: &[]string{"dep5"}},
					{Ref: "dep4", Dependencies: &[]string{"dep6"}},
				},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, IsMultiProject(test.bom))
		})
	}
}

func TestBomToFlatTree(t *testing.T) {
	tests := []struct {
		name     string
		bom      *cyclonedx.BOM
		expected *xrayUtils.GraphNode
	}{
		{
			name:     "No components",
			bom:      cyclonedx.NewBOM(),
			expected: &xrayUtils.GraphNode{Id: "root"},
		},
		{
			name: "BOM with components",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:     "component1",
						Name:       "Component 1",
						Version:    "1.0.0",
						Type:       "library",
						PackageURL: "pkg:npm/component1@1.0.0",
					},
					{
						BOMRef: "3fac3b2",
						Name:   path.Join("path", "to", "file.txt"),
						Type:   "file",
					},
					{
						BOMRef:     "component2",
						Name:       "Component 2",
						Version:    "2.0.0",
						Type:       "library",
						PackageURL: "pkg:golang/component2@2.0.0",
					},
				},
			},
			expected: &xrayUtils.GraphNode{
				Id: "root",
				Nodes: []*xrayUtils.GraphNode{
					{Id: "npm://component1:1.0.0"},
					{Id: "go://component2:2.0.0"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, *test.expected, *BomToFlatTree(test.bom, true))
		})
	}
}

func TestBomToFullTree(t *testing.T) {
	tests := []struct {
		name            string
		bom             *cyclonedx.BOM
		isBuildInfoXray bool
		expected        []*xrayUtils.GraphNode
	}{
		{
			name: "BOM with no libraries",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef: "3fac3b2",
						Name:   path.Join("path", "to", "file.txt"),
						Type:   "file",
					},
				},
			},
			expected: []*xrayUtils.GraphNode{},
		},
		{
			name: "BOM with one tree",
			bom:  getTestBom(true),
			expected: []*xrayUtils.GraphNode{
				{
					Id: "pkg:npm/root@1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "pkg:npm/component1@1.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "pkg:npm/component2@2.1.2"}},
						},
						{
							Id:    "pkg:npm/component2@2.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "pkg:npm/component4@4.0.0"}},
						},
						{
							Id: "pkg:npm/component3@3.0.0",
							Nodes: []*xrayUtils.GraphNode{
								{
									Id:    "pkg:npm/component2@2.0.0",
									Nodes: []*xrayUtils.GraphNode{{Id: "pkg:npm/component4@4.0.0"}},
								},
							},
						},
					},
				},
			},
		},
		{
			name:            "BOM with one tree (converted to xray-component-id)",
			isBuildInfoXray: true,
			bom:             getTestBom(true),
			expected: []*xrayUtils.GraphNode{
				{
					Id: "npm://root:1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "npm://component1:1.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "npm://component2:2.1.2"}},
						},
						{
							Id:    "npm://component2:2.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "npm://component4:4.0.0"}},
						},
						{
							Id: "npm://component3:3.0.0",
							Nodes: []*xrayUtils.GraphNode{
								{
									Id:    "npm://component2:2.0.0",
									Nodes: []*xrayUtils.GraphNode{{Id: "npm://component4:4.0.0"}},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "BOM with multiple trees",
			bom:  getTestBom(false),
			expected: []*xrayUtils.GraphNode{
				{
					Id: "pkg:npm/root@1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "pkg:npm/component1@1.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "pkg:npm/component2@2.1.2"}},
						},
						{
							Id:    "pkg:npm/component2@2.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "pkg:npm/component4@4.0.0"}},
						},
						{
							Id: "pkg:npm/component3@3.0.0",
							Nodes: []*xrayUtils.GraphNode{
								{
									Id:    "pkg:npm/component2@2.0.0",
									Nodes: []*xrayUtils.GraphNode{{Id: "pkg:npm/component4@4.0.0"}},
								},
							},
						},
					},
				},
				{
					Id: "pkg:golang/root@v1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id: "pkg:golang/component1@v1.0.0",
							Nodes: []*xrayUtils.GraphNode{
								{Id: "pkg:golang/component2@v2.0.0"},
								{Id: "pkg:golang/component3@v3.0.0"},
							},
						},
						{
							Id: "pkg:golang/component2@v2.0.0",
						},
					},
				},
			},
		},
		{
			name:            "BOM with multiple trees (converted to xray-component-id)",
			isBuildInfoXray: true,
			bom:             getTestBom(false),
			expected: []*xrayUtils.GraphNode{
				{
					Id: "npm://root:1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id:    "npm://component1:1.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "npm://component2:2.1.2"}},
						},
						{
							Id:    "npm://component2:2.0.0",
							Nodes: []*xrayUtils.GraphNode{{Id: "npm://component4:4.0.0"}},
						},
						{
							Id: "npm://component3:3.0.0",
							Nodes: []*xrayUtils.GraphNode{
								{
									Id:    "npm://component2:2.0.0",
									Nodes: []*xrayUtils.GraphNode{{Id: "npm://component4:4.0.0"}},
								},
							},
						},
					},
				},
				{
					Id: "go://root:v1.0.0",
					Nodes: []*xrayUtils.GraphNode{
						{
							Id: "go://component1:v1.0.0",
							Nodes: []*xrayUtils.GraphNode{
								{Id: "go://component2:v2.0.0"},
								{Id: "go://component3:v3.0.0"},
							},
						},
						{
							Id: "go://component2:v2.0.0",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, root := range test.expected {
				setParentsToTestNodes(nil, root)
			}
			result := BomToFullTree(test.bom, test.isBuildInfoXray)
			assert.ElementsMatch(t, test.expected, result)
		})
	}
}

func getTestBom(oneRoot bool) *cyclonedx.BOM {
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				// Root component
				BOMRef:     "npm:root:1.0.0",
				Name:       "root",
				Version:    "1.0.0",
				Type:       "library",
				PackageURL: "pkg:npm/root@1.0.0",
			},
			{

				BOMRef:     "npm:component1:1.0.0",
				Name:       "Component 1",
				Version:    "1.0.0",
				Type:       "library",
				PackageURL: "pkg:npm/component1@1.0.0",
			},
			{
				BOMRef: "3fac3b2",
				Name:   path.Join("path", "to", "file.txt"),
				Type:   "file",
			},
			{
				BOMRef:     "npm:component2:2.0.0",
				Name:       "Component 2",
				Version:    "2.0.0",
				Type:       "library",
				PackageURL: "pkg:npm/component2@2.0.0",
			},
			{
				BOMRef:     "npm:component2:2.1.2",
				Name:       "Component 2",
				Version:    "2.1.2",
				Type:       "library",
				PackageURL: "pkg:npm/component2@2.1.2",
			},
			{
				BOMRef:     "npm:component3:3.0.0",
				Name:       "Component 3",
				Version:    "3.0.0",
				Type:       "library",
				PackageURL: "pkg:npm/component3@3.0.0",
			},
			{
				BOMRef:     "npm:component4:4.0.0",
				Name:       "Component 4",
				Version:    "4.0.0",
				Type:       "library",
				PackageURL: "pkg:npm/component4@4.0.0",
			},
		},
		Dependencies: &[]cyclonedx.Dependency{
			{
				Ref:          "npm:root:1.0.0",
				Dependencies: &[]string{"npm:component1:1.0.0", "npm:component2:2.0.0", "npm:component3:3.0.0"},
			},
			{
				Ref:          "npm:component2:2.0.0",
				Dependencies: &[]string{"npm:component4:4.0.0"},
			},
			{
				Ref:          "npm:component1:1.0.0",
				Dependencies: &[]string{"npm:component2:2.1.2"},
			},
			{
				Ref:          "npm:component3:3.0.0",
				Dependencies: &[]string{"npm:component2:2.0.0"},
			},
		},
	}
	if oneRoot {
		return bom
	}
	// Multiple roots case
	*bom.Components = append(*bom.Components,
		// Root 2
		cyclonedx.Component{
			BOMRef:     "golang:root:v1.0.0",
			Name:       "root",
			Version:    "v1.0.0",
			Type:       "library",
			PackageURL: "pkg:golang/root@v1.0.0",
		},
		// Component 1
		cyclonedx.Component{
			BOMRef:     "golang:component1:v1.0.0",
			Name:       "Component 1",
			Version:    "v1.0.0",
			Type:       "library",
			PackageURL: "pkg:golang/component1@v1.0.0",
		},
		// Component 2
		cyclonedx.Component{
			BOMRef:     "golang:component2:v2.0.0",
			Name:       "Component 2",
			Version:    "v2.0.0",
			Type:       "library",
			PackageURL: "pkg:golang/component2@v2.0.0",
		},
		// Component 3
		cyclonedx.Component{
			BOMRef:     "golang:component3:v3.0.0",
			Name:       "Component 3",
			Version:    "v3.0.0",
			Type:       "library",
			PackageURL: "pkg:golang/component3@v3.0.0",
		},
	)
	*bom.Dependencies = append(*bom.Dependencies,
		cyclonedx.Dependency{
			Ref:          "golang:root:v1.0.0",
			Dependencies: &[]string{"golang:component1:v1.0.0", "golang:component2:v2.0.0"},
		},
		cyclonedx.Dependency{
			Ref:          "golang:component1:v1.0.0",
			Dependencies: &[]string{"golang:component2:v2.0.0", "golang:component3:v3.0.0"},
		},
	)
	return bom
}

func setParentsToTestNodes(parent *xrayUtils.GraphNode, nodes ...*xrayUtils.GraphNode) {
	for _, node := range nodes {
		node.Parent = parent
		setParentsToTestNodes(node, node.Nodes...)
	}
}

func TestBomToFullCompTree(t *testing.T) {
	tests := []struct {
		name         string
		bom          *cyclonedx.BOM
		isXrayCompId bool
		expected     []*xrayUtils.BinaryGraphNode
	}{
		{
			name: "BOM with no libraries",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef: "8624ef95f4305969d180d3b1eab81bef",
						Name:   path.Join("path", "to", "binary.jar"),
						Type:   "file",
					},
				},
			},
			expected: []*xrayUtils.BinaryGraphNode{},
		},
		{
			name: "BOM with component no dependencies",
			bom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:     "generic://log4j-core-2.17.1.jar",
						Name:       "log4j-core-2.17.1.jar",
						Type:       "library",
						PackageURL: "pkg:generic/log4j-core-2.17.1.jar",
					},
				},
			},
			expected: []*xrayUtils.BinaryGraphNode{
				{
					Id: "pkg:generic/log4j-core-2.17.1.jar",
				},
			},
		},
		{
			name: "Binary file BOM",
			bom:  getBinaryTestBom(true),
			expected: []*xrayUtils.BinaryGraphNode{
				{
					Id:       "pkg:generic/binary-2.jar",
					Sha1:     "c8637440d377d5af307b8e4689148a12cf078807",
					Sha256:   "a3ddf66ccb764afcc56cc0d0c054dea842ee6b9db44bd2e0e9a7f421fbbb088e",
					Licenses: []string{"Apache-2.0"},
					Path:     "binary-2.jar",
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id:     "pkg:maven/com.google.code.findbugs:jsr305@3.0.2",
							Sha1:   "fbc25c55a6f50643a13473b762dd67857de459d5",
							Sha256: "000000000000000000000000fbc25c55a6f50643a13473b762dd67857de459d5",
							Path:   "META-INF/maven/com.google.code.findbugs/jsr305/pom.xml",
						},
						{
							Id:       "pkg:maven/commons-lang:commons-lang@2.4",
							Sha1:     "c0bf256037c9b26d203c4b1fca4e3a1d4d8caf63",
							Licenses: []string{"Apache-2.0"},
							Path:     "META-INF/maven/commons-lang/commons-lang/pom.xml",
						},
					},
				},
			},
		},
		{
			name:         "Binary file BOM (converted to xray-component-id)",
			bom:          getBinaryTestBom(true),
			isXrayCompId: true,
			expected: []*xrayUtils.BinaryGraphNode{
				{
					Id:       "generic://binary-2.jar",
					Sha1:     "c8637440d377d5af307b8e4689148a12cf078807",
					Sha256:   "a3ddf66ccb764afcc56cc0d0c054dea842ee6b9db44bd2e0e9a7f421fbbb088e",
					Licenses: []string{"Apache-2.0"},
					Path:     "binary-2.jar",
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id:     "gav://com.google.code.findbugs:jsr305:3.0.2",
							Sha1:   "fbc25c55a6f50643a13473b762dd67857de459d5",
							Sha256: "000000000000000000000000fbc25c55a6f50643a13473b762dd67857de459d5",
							Path:   "META-INF/maven/com.google.code.findbugs/jsr305/pom.xml",
						},
						{
							Id:       "gav://commons-lang:commons-lang:2.4",
							Sha1:     "c0bf256037c9b26d203c4b1fca4e3a1d4d8caf63",
							Licenses: []string{"Apache-2.0"},
							Path:     "META-INF/maven/commons-lang/commons-lang/pom.xml",
						},
					},
				},
			},
		},
		{
			name: "Multiple binaries BOM",
			bom:  getBinaryTestBom(false),
			expected: []*xrayUtils.BinaryGraphNode{
				{
					Id:       "pkg:generic/binary-2.jar",
					Sha1:     "c8637440d377d5af307b8e4689148a12cf078807",
					Sha256:   "a3ddf66ccb764afcc56cc0d0c054dea842ee6b9db44bd2e0e9a7f421fbbb088e",
					Licenses: []string{"Apache-2.0"},
					Path:     "binary-2.jar",
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id:     "pkg:maven/com.google.code.findbugs:jsr305@3.0.2",
							Sha1:   "fbc25c55a6f50643a13473b762dd67857de459d5",
							Sha256: "000000000000000000000000fbc25c55a6f50643a13473b762dd67857de459d5",
							Path:   "META-INF/maven/com.google.code.findbugs/jsr305/pom.xml",
						},
						{
							Id:       "pkg:maven/commons-lang:commons-lang@2.4",
							Sha1:     "c0bf256037c9b26d203c4b1fca4e3a1d4d8caf63",
							Licenses: []string{"Apache-2.0"},
							Path:     "META-INF/maven/commons-lang/commons-lang/pom.xml",
						},
					},
				},
				{
					Id:     "pkg:docker/docker.io/library/nginx@1.27-alpine",
					Sha1:   "b79749300dc03448c42b7005a11afff9cc40eba5",
					Sha256: "336c419faa875b96017a062e4b94b0e2840ab032d67935042acec36ec24f6d63",
					Path:   "/docker.io/library/nginx/1.27-alpine/manifest.json",
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id:     "pkg:generic/sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
							Sha256: "534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c",
							Path:   "sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
							Nodes: []*xrayUtils.BinaryGraphNode{
								{
									Id:       "pkg:alpine/alpine-baselayout@3.6.5-r0",
									Licenses: []string{"GPL-2.0-only"},
									Path:     "3.20:alpine-baselayout:3.6.5-r0",
								},
							},
						},
						{
							Id:     "pkg:generic/scripts.tar",
							Sha1:   "8c9c1d3b4ef3c8e95ee08625198453b8868a916f",
							Sha256: "6955e7ad2d1222ef20a2de04bfa6a94d33d64e529cfc99217a7123b9fe2222b2",
							Path:   "lib/apk/db/scripts.tar",
						},
					},
				},
			},
		},
		{
			name:         "Multiple binaries BOM (converted to xray-component-id)",
			bom:          getBinaryTestBom(false),
			isXrayCompId: true,
			expected: []*xrayUtils.BinaryGraphNode{
				{
					Id:       "generic://binary-2.jar",
					Sha1:     "c8637440d377d5af307b8e4689148a12cf078807",
					Sha256:   "a3ddf66ccb764afcc56cc0d0c054dea842ee6b9db44bd2e0e9a7f421fbbb088e",
					Licenses: []string{"Apache-2.0"},
					Path:     "binary-2.jar",
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id:     "gav://com.google.code.findbugs:jsr305:3.0.2",
							Sha1:   "fbc25c55a6f50643a13473b762dd67857de459d5",
							Sha256: "000000000000000000000000fbc25c55a6f50643a13473b762dd67857de459d5",
							Path:   "META-INF/maven/com.google.code.findbugs/jsr305/pom.xml",
						},
						{
							Id:       "gav://commons-lang:commons-lang:2.4",
							Sha1:     "c0bf256037c9b26d203c4b1fca4e3a1d4d8caf63",
							Licenses: []string{"Apache-2.0"},
							Path:     "META-INF/maven/commons-lang/commons-lang/pom.xml",
						},
					},
				},
				{
					Id:     "docker://docker.io/library/nginx:1.27-alpine",
					Sha1:   "b79749300dc03448c42b7005a11afff9cc40eba5",
					Sha256: "336c419faa875b96017a062e4b94b0e2840ab032d67935042acec36ec24f6d63",
					Path:   "/docker.io/library/nginx/1.27-alpine/manifest.json",
					Nodes: []*xrayUtils.BinaryGraphNode{
						{
							Id:     "generic://sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
							Sha256: "534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c",
							Path:   "sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
							Nodes: []*xrayUtils.BinaryGraphNode{
								{
									Id:       "alpine://alpine-baselayout:3.6.5-r0",
									Licenses: []string{"GPL-2.0-only"},
									Path:     "3.20:alpine-baselayout:3.6.5-r0",
								},
							},
						},
						{
							Id:     "generic://scripts.tar",
							Sha1:   "8c9c1d3b4ef3c8e95ee08625198453b8868a916f",
							Sha256: "6955e7ad2d1222ef20a2de04bfa6a94d33d64e529cfc99217a7123b9fe2222b2",
							Path:   "lib/apk/db/scripts.tar",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := BomToFullCompTree(test.bom, test.isXrayCompId)
			assert.ElementsMatch(t, test.expected, result)
		})
	}
}

func getBinaryTestBom(oneBinary bool) *cyclonedx.BOM {
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				// Root component
				BOMRef:     "generic://binary-2.jar",
				Name:       "binary-2.jar",
				Type:       "library",
				PackageURL: "pkg:generic/binary-2.jar",
				Hashes: &[]cyclonedx.Hash{
					{
						Algorithm: "SHA-1",
						Value:     "c8637440d377d5af307b8e4689148a12cf078807",
					},
					{
						Algorithm: "SHA-256",
						Value:     "a3ddf66ccb764afcc56cc0d0c054dea842ee6b9db44bd2e0e9a7f421fbbb088e",
					},
				},
				Licenses: &cyclonedx.Licenses{
					{
						License: &cyclonedx.License{ID: "Apache-2.0"},
					},
				},
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{
						{
							Location: "binary-2.jar",
						},
					},
				},
			},
			{
				// Direct dependency
				BOMRef:     "maven:com.google.code.findbugs:jsr305:3.0.2",
				Name:       "com.google.code.findbugs:jsr305",
				Version:    "3.0.2",
				Type:       "library",
				PackageURL: "pkg:maven/com.google.code.findbugs:jsr305@3.0.2",
				Hashes: &[]cyclonedx.Hash{
					{
						Algorithm: "SHA-1",
						Value:     "fbc25c55a6f50643a13473b762dd67857de459d5",
					},
					{
						Algorithm: "SHA-256",
						Value:     "000000000000000000000000fbc25c55a6f50643a13473b762dd67857de459d5",
					},
				},
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{
						{
							Location: "META-INF/maven/com.google.code.findbugs/jsr305/pom.xml",
						},
					},
				},
			},
			{
				// Direct dependency
				BOMRef:     "maven:commons-lang:commons-lang:2.4",
				Name:       "commons-lang:commons-lang",
				Version:    "2.4",
				Type:       "library",
				PackageURL: "pkg:maven/commons-lang:commons-lang@2.4",
				Hashes: &[]cyclonedx.Hash{
					{
						Algorithm: "SHA-1",
						Value:     "c0bf256037c9b26d203c4b1fca4e3a1d4d8caf63",
					},
				},
				Licenses: &cyclonedx.Licenses{
					{
						License: &cyclonedx.License{ID: "Apache-2.0"},
					},
				},
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{
						{
							Location: "META-INF/maven/commons-lang/commons-lang/pom.xml",
						},
					},
				},
			},
		},
		Dependencies: &[]cyclonedx.Dependency{
			{
				Ref:          "generic://binary-2.jar",
				Dependencies: &[]string{"maven:com.google.code.findbugs:jsr305:3.0.2", "maven:commons-lang:commons-lang:2.4"},
			},
		},
	}
	if oneBinary {
		return bom
	}
	*bom.Components = append(*bom.Components,
		cyclonedx.Component{
			// Root Docker component
			BOMRef:     "docker:docker.io/library/nginx:1.27-alpine",
			Name:       "docker.io/library/nginx",
			Version:    "1.27-alpine",
			Type:       "library",
			PackageURL: "pkg:docker/docker.io/library/nginx@1.27-alpine",
			Hashes: &[]cyclonedx.Hash{
				{
					Algorithm: "SHA-1",
					Value:     "b79749300dc03448c42b7005a11afff9cc40eba5",
				},
				{
					Algorithm: "SHA-256",
					Value:     "336c419faa875b96017a062e4b94b0e2840ab032d67935042acec36ec24f6d63",
				},
			},
			Evidence: &cyclonedx.Evidence{
				Occurrences: &[]cyclonedx.EvidenceOccurrence{
					{
						Location: "/docker.io/library/nginx/1.27-alpine/manifest.json",
					},
				},
			},
		},
		cyclonedx.Component{
			// Direct dependency
			BOMRef:     "generic:sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
			Name:       "sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
			Type:       "library",
			PackageURL: "pkg:generic/sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
			Hashes: &[]cyclonedx.Hash{
				{
					Algorithm: "SHA-256",
					Value:     "534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c",
				},
			},
			Evidence: &cyclonedx.Evidence{
				Occurrences: &[]cyclonedx.EvidenceOccurrence{
					{
						Location: "sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
					},
				},
			},
		},
		cyclonedx.Component{
			// Transitive dependency
			BOMRef:     "alpine:3.20:alpine-baselayout:3.6.5-r0",
			Name:       "alpine:3.20:alpine-baselayout",
			Version:    "3.6.5-r0",
			Type:       "library",
			PackageURL: "pkg:alpine/alpine-baselayout@3.6.5-r0",
			Licenses: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{ID: "GPL-2.0-only"},
				},
			},
			Evidence: &cyclonedx.Evidence{
				Occurrences: &[]cyclonedx.EvidenceOccurrence{
					{
						Location: "3.20:alpine-baselayout:3.6.5-r0",
					},
				},
			},
		},
		cyclonedx.Component{
			BOMRef:     "generic:scripts.tar",
			Name:       "scripts.tar",
			Type:       "library",
			PackageURL: "pkg:generic/scripts.tar",
			Hashes: &[]cyclonedx.Hash{
				{
					Algorithm: "SHA-1",
					Value:     "8c9c1d3b4ef3c8e95ee08625198453b8868a916f",
				},
				{
					Algorithm: "SHA-256",
					Value:     "6955e7ad2d1222ef20a2de04bfa6a94d33d64e529cfc99217a7123b9fe2222b2",
				},
			},
			Evidence: &cyclonedx.Evidence{
				Occurrences: &[]cyclonedx.EvidenceOccurrence{
					{
						Location: "lib/apk/db/scripts.tar",
					},
				},
			},
		},
	)
	*bom.Dependencies = append(*bom.Dependencies,
		cyclonedx.Dependency{
			Ref:          "docker:docker.io/library/nginx:1.27-alpine",
			Dependencies: &[]string{"generic:sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar", "generic:scripts.tar"},
		},
		cyclonedx.Dependency{
			Ref:          "generic:sha256__534a70dc82967ee32184e13d28ea485e909b20d3f13d553122bab3e4de03b50c.tar",
			Dependencies: &[]string{"alpine:3.20:alpine-baselayout:3.6.5-r0"},
		},
	)
	return bom
}

func TestScanResponseToSbom(t *testing.T) {
	tests := []struct {
		name     string
		response services.ScanResponse
		expected *cyclonedx.BOM
	}{
		{
			name:     "Empty response",
			response: services.ScanResponse{},
			expected: &cyclonedx.BOM{},
		},
		{
			name:     "Response with components and dependencies",
			response: services.ScanResponse{},
			expected: getTestBom(true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination := &cyclonedx.BOM{}
			assert.NoError(t, ScanResponseToSbom(destination, test.response))
			assert.Equal(t, test.expected, destination)
		})
	}
}
