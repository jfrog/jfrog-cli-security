package simplejsonformat

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/jfrog/jfrog-client-go/xray/services"
)

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
			services.Violation{IsEol: newBoolPtr(true), LatestVersion: "1.2.3", NewerVersions: newIntPtr(5),
				Cadence: newFloat64Ptr(3.5), Commits: newInt64Ptr(55), Committers: newIntPtr(10), EolMessage: "no maintainers", RiskReason: "EOL"},
			&operationalRiskViolationReadableData{"true", "3.5", "55", "10", "no maintainers", "EOL", "1.2.3", "5"},
		},
	}

	for _, test := range tests {
		results := getOperationalRiskViolationReadableData(test.violation)
		assert.Equal(t, test.expectedResults, results)
	}
}

func newBoolPtr(v bool) *bool {
	return &v
}

func newIntPtr(v int) *int {
	return &v
}

func newInt64Ptr(v int64) *int64 {
	return &v
}

func newFloat64Ptr(v float64) *float64 {
	return &v
}

func TestPrepareIac(t *testing.T) {
	testCases := []struct {
		name           string
		input          []*sarif.Run
		expectedOutput []formats.SourceCodeRow
	}{
		{
			name:           "No Iac run",
			input:          []*sarif.Run{},
			expectedOutput: []formats.SourceCodeRow{},
		},
		{
			name: "Prepare Iac run - no results",
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(),
			},
			expectedOutput: []formats.SourceCodeRow{},
		},
		{
			name: "Prepare Iac run - with results",
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("iac finding", "rule1", "info",
						sarifutils.CreateLocation("file://wd/file", 1, 2, 3, 4, "snippet"),
						sarifutils.CreateLocation("file://wd/file2", 5, 6, 7, 8, "other-snippet"),
					),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd")),
				}),
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("other iac finding", "rule2", "error",
						sarifutils.CreateLocation("file://wd2/file3", 1, 2, 3, 4, "snippet"),
					),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd2")),
				}),
			},
			expectedOutput: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "High",
						SeverityNumValue: 17,
					},
					Finding: "other iac finding",
					Location: formats.Location{
						File:        "file3",
						StartLine:   1,
						StartColumn: 2,
						EndLine:     3,
						EndColumn:   4,
						Snippet:     "snippet",
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 14,
					},
					Finding: "iac finding",
					Location: formats.Location{
						File:        "file",
						StartLine:   1,
						StartColumn: 2,
						EndLine:     3,
						EndColumn:   4,
						Snippet:     "snippet",
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 14,
					},
					Finding: "iac finding",
					Location: formats.Location{
						File:        "file2",
						StartLine:   5,
						StartColumn: 6,
						EndLine:     7,
						EndColumn:   8,
						Snippet:     "other-snippet",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expectedOutput, prepareIacs(tc.input, false))
		})
	}
}

func TestPrepareSecrets(t *testing.T) {
	testCases := []struct {
		name           string
		input          []*sarif.Run
		expectedOutput []formats.SourceCodeRow
	}{
		{
			name:           "No Secret run",
			input:          []*sarif.Run{},
			expectedOutput: []formats.SourceCodeRow{},
		},
		{
			name: "Prepare Secret run - no results",
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(),
			},
			expectedOutput: []formats.SourceCodeRow{},
		},
		{
			name: "Prepare Secret run - with results",
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("secret finding", "rule1", "info",
						sarifutils.CreateLocation("file://wd/file", 1, 2, 3, 4, "some-secret-snippet"),
						sarifutils.CreateLocation("file://wd/file2", 5, 6, 7, 8, "other-secret-snippet"),
					),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd")),
				}),
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("other secret finding", "rule2", "note",
						sarifutils.CreateLocation("file://wd2/file3", 1, 2, 3, 4, "some-secret-snippet"),
					),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd2")),
				}),
			},
			expectedOutput: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Low",
						SeverityNumValue: 11,
					},
					Finding: "other secret finding",
					Location: formats.Location{
						File:        "file3",
						StartLine:   1,
						StartColumn: 2,
						EndLine:     3,
						EndColumn:   4,
						Snippet:     "some-secret-snippet",
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 14,
					},
					Finding: "secret finding",
					Location: formats.Location{
						File:        "file",
						StartLine:   1,
						StartColumn: 2,
						EndLine:     3,
						EndColumn:   4,
						Snippet:     "some-secret-snippet",
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 14,
					},
					Finding: "secret finding",
					Location: formats.Location{
						File:        "file2",
						StartLine:   5,
						StartColumn: 6,
						EndLine:     7,
						EndColumn:   8,
						Snippet:     "other-secret-snippet",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expectedOutput, prepareSecrets(tc.input, false))
		})
	}
}

// TODO: remove and replace with resource

func TestPrepareSast(t *testing.T) {
	testCases := []struct {
		name           string
		input          []*sarif.Run
		expectedOutput []formats.SourceCodeRow
	}{
		{
			name:           "No Sast run",
			input:          []*sarif.Run{},
			expectedOutput: []formats.SourceCodeRow{},
		},
		{
			name: "Prepare Sast run - no results",
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(),
			},
			expectedOutput: []formats.SourceCodeRow{},
		},
		{
			name: "Prepare Sast run - with results",
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(),
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("sast finding", "rule1", "info",
						sarifutils.CreateLocation("file://wd/file", 1, 2, 3, 4, "snippet"),
						sarifutils.CreateLocation("file://wd/file2", 5, 6, 7, 8, "other-snippet"),
					).WithCodeFlows([]*sarif.CodeFlow{
						sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
							sarifutils.CreateLocation("file://wd/file2", 0, 2, 0, 2, "snippetA"),
							sarifutils.CreateLocation("file://wd/file", 1, 2, 3, 4, "snippet"),
						)),
						sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
							sarifutils.CreateLocation("file://wd/file4", 1, 0, 1, 8, "snippetB"),
							sarifutils.CreateLocation("file://wd/file", 1, 2, 3, 4, "snippet"),
						)),
					}),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd")),
				}),
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("other sast finding", "rule2", "error",
						sarifutils.CreateLocation("file://wd2/file3", 1, 2, 3, 4, "snippet"),
					),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd2")),
				}),
			},
			expectedOutput: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "High",
						SeverityNumValue: 17,
					},
					Finding: "other sast finding",
					Location: formats.Location{
						File:        "file3",
						StartLine:   1,
						StartColumn: 2,
						EndLine:     3,
						EndColumn:   4,
						Snippet:     "snippet",
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 14,
					},
					Finding: "sast finding",
					Location: formats.Location{
						File:        "file",
						StartLine:   1,
						StartColumn: 2,
						EndLine:     3,
						EndColumn:   4,
						Snippet:     "snippet",
					},
					CodeFlow: [][]formats.Location{
						{
							{
								File:        "file2",
								StartLine:   0,
								StartColumn: 2,
								EndLine:     0,
								EndColumn:   2,
								Snippet:     "snippetA",
							},
							{
								File:        "file",
								StartLine:   1,
								StartColumn: 2,
								EndLine:     3,
								EndColumn:   4,
								Snippet:     "snippet",
							},
						},
						{
							{
								File:        "file4",
								StartLine:   1,
								StartColumn: 0,
								EndLine:     1,
								EndColumn:   8,
								Snippet:     "snippetB",
							},
							{
								File:        "file",
								StartLine:   1,
								StartColumn: 2,
								EndLine:     3,
								EndColumn:   4,
								Snippet:     "snippet",
							},
						},
					},
				},
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 14,
					},
					Finding: "sast finding",
					Location: formats.Location{
						File:        "file2",
						StartLine:   5,
						StartColumn: 6,
						EndLine:     7,
						EndColumn:   8,
						Snippet:     "other-snippet",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expectedOutput, prepareSast(tc.input, false))
		})
	}
}
