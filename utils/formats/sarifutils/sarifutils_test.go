package sarifutils

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/jasutils"

	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregateMultipleRunsIntoSingle(t *testing.T) {
	tests := []struct {
		runs           []*sarif.Run
		expectedOutput *sarif.Run
	}{
		{
			runs:           []*sarif.Run{},
			expectedOutput: CreateRunWithDummyResults(),
		},
		{
			runs: []*sarif.Run{
				CreateRunWithDummyResults(
					CreateDummyPassingResult("rule1"),
					CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule2", "level"),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd")),
				}),
				CreateRunWithDummyResults(),
			},
			expectedOutput: CreateRunWithDummyResults(
				CreateDummyPassingResult("rule1"),
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule2", "level"),
			).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd")),
			}),
		},
		{
			runs: []*sarif.Run{
				CreateRunWithDummyResults(
					CreateDummyPassingResult("rule1"),
					CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule2", "level"),
					CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule3", "level"),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd")),
				}),
				CreateRunWithDummyResults(
					CreateResultWithLocations("msg", "rule2", "level",
						CreateLocation("file", 1, 2, 3, 4, "snippet"),
						CreateLocation("file2", 1, 2, 3, 4, "other-snippet"),
					),
					CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet2", "rule2", "level"),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd2")),
				}),
			},
			expectedOutput: CreateRunWithDummyResults(
				// First run results
				CreateDummyPassingResult("rule1"),
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule2", "level"),
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule3", "level"),
				// Second run results
				CreateResultWithLocations("msg", "rule2", "level",
					CreateLocation("file", 1, 2, 3, 4, "snippet"),
					CreateLocation("file2", 1, 2, 3, 4, "other-snippet"),
				),
				CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet2", "rule2", "level"),
			).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd")),
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("wd2")),
			}),
		},
	}

	for _, test := range tests {
		run := CreateRunWithDummyResults()
		AggregateMultipleRunsIntoSingle(test.runs, run)
		assert.Equal(t, test.expectedOutput, run)
	}
}

func TestGetLocationRelatedCodeFlowsFromResult(t *testing.T) {
	tests := []struct {
		result         *sarif.Result
		location       *sarif.Location
		expectedOutput []*sarif.CodeFlow
	}{
		{
			result:         CreateDummyPassingResult("rule"),
			location:       CreateLocation("file", 0, 0, 0, 0, "snippet"),
			expectedOutput: nil,
		},
		{
			result:         CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule", "level"),
			location:       CreateLocation("file", 0, 0, 0, 0, "snippet"),
			expectedOutput: nil,
		},
		{
			result:         CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule", "level").WithCodeFlows([]*sarif.CodeFlow{CreateCodeFlow(CreateThreadFlow(CreateLocation("file", 0, 0, 0, 0, "snippet")))}),
			location:       CreateLocation("file2", 0, 0, 0, 0, "snippet"),
			expectedOutput: nil,
		},
		{
			result:         CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule", "level").WithCodeFlows([]*sarif.CodeFlow{CreateCodeFlow(CreateThreadFlow(CreateLocation("file", 0, 0, 0, 0, "snippet")))}),
			location:       CreateLocation("file", 0, 0, 0, 0, "snippet"),
			expectedOutput: []*sarif.CodeFlow{CreateCodeFlow(CreateThreadFlow(CreateLocation("file", 0, 0, 0, 0, "snippet")))},
		},
		{
			result: CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule", "level").WithCodeFlows([]*sarif.CodeFlow{
				CreateCodeFlow(CreateThreadFlow(
					CreateLocation("file4", 2, 0, 2, 0, "snippetB"),
					CreateLocation("file2", 0, 2, 0, 2, "snippetA"),
					CreateLocation("file", 0, 0, 0, 0, "snippet"),
				)),
				CreateCodeFlow(CreateThreadFlow(
					CreateLocation("file", 0, 0, 0, 0, "snippet"),
					CreateLocation("file2", 1, 0, 1, 0, "snippet"),
				)),
				CreateCodeFlow(CreateThreadFlow(
					CreateLocation("fileC", 1, 1, 1, 1, "snippetC"),
					CreateLocation("file", 0, 0, 0, 0, "snippet"),
				)),
			}),
			location: CreateLocation("file", 0, 0, 0, 0, "snippet"),
			expectedOutput: []*sarif.CodeFlow{
				CreateCodeFlow(CreateThreadFlow(
					CreateLocation("file4", 2, 0, 2, 0, "snippetB"),
					CreateLocation("file2", 0, 2, 0, 2, "snippetA"),
					CreateLocation("file", 0, 0, 0, 0, "snippet"),
				)),
				CreateCodeFlow(CreateThreadFlow(
					CreateLocation("fileC", 1, 1, 1, 1, "snippetC"),
					CreateLocation("file", 0, 0, 0, 0, "snippet"),
				)),
			},
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetLocationRelatedCodeFlowsFromResult(test.location, test.result))
	}
}

func TestGetResultsLocationCount(t *testing.T) {
	tests := []struct {
		runs           []*sarif.Run
		expectedOutput int
	}{
		{
			runs:           []*sarif.Run{},
			expectedOutput: 0,
		},
		{
			runs:           []*sarif.Run{CreateRunWithDummyResults()},
			expectedOutput: 0,
		},
		{
			runs: []*sarif.Run{CreateRunWithDummyResults(
				CreateDummyPassingResult("rule"),
				CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule", "level"),
			)},
			expectedOutput: 1,
		},
		{
			runs: []*sarif.Run{
				CreateRunWithDummyResults(
					CreateDummyPassingResult("rule"),
					CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule", "level"),
				),
				CreateRunWithDummyResults(
					CreateResultWithLocations(
						"msg",
						"rule",
						"level",
						CreateLocation("file", 0, 0, 0, 0, "snippet"),
						CreateLocation("file", 0, 0, 0, 0, "snippet"),
						CreateLocation("file", 0, 0, 0, 0, "snippet"),
					),
				),
			},
			expectedOutput: 4,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetResultsLocationCount(test.runs...))
	}
}

func TestGetResultMsgText(t *testing.T) {
	tests := []struct {
		result         *sarif.Result
		expectedOutput string
	}{
		{
			result:         &sarif.Result{},
			expectedOutput: "",
		},
		{
			result:         CreateResultWithLocations("msg", "rule", "level"),
			expectedOutput: "msg",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetResultMsgText(test.result))
	}
}

func TestGetLocationSnippetText(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput string
	}{
		{
			location:       nil,
			expectedOutput: "",
		},
		{
			location:       CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: "snippet",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetLocationSnippetText(test.location))
	}
}

func TestSetLocationSnippet(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput string
	}{
		{
			location:       nil,
			expectedOutput: "",
		},
		{
			location:       CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: "changedSnippet",
		},
	}

	for _, test := range tests {
		SetLocationSnippet(test.location, test.expectedOutput)
		assert.Equal(t, test.expectedOutput, GetLocationSnippetText(test.location))
	}
}

func TestGetLocationFileName(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput string
	}{
		{
			location:       nil,
			expectedOutput: "",
		},
		{
			location:       CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: "filename",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetLocationFileName(test.location))
	}
}

func TestGetRelativeLocationFileName(t *testing.T) {
	tests := []struct {
		name           string
		location       *sarif.Location
		invocations    []*sarif.Invocation
		expectedOutput string
	}{
		{
			name:           "No invocations",
			location:       CreateLocation("file:///root/someDir/another/file", 1, 2, 3, 4, "snippet"),
			invocations:    []*sarif.Invocation{},
			expectedOutput: "file:///root/someDir/another/file",
		},
		{
			name:           "With not relevant invocations",
			location:       CreateLocation("file:///root/someDir/another/file", 1, 2, 3, 4, "snippet"),
			invocations:    []*sarif.Invocation{{WorkingDirectory: sarif.NewSimpleArtifactLocation("file:///not/relevant")}},
			expectedOutput: "file:///root/someDir/another/file",
		},
		{
			name:           "With invocations",
			location:       CreateLocation("file:///root/someDir/another/file", 1, 2, 3, 4, "snippet"),
			invocations:    []*sarif.Invocation{{WorkingDirectory: sarif.NewSimpleArtifactLocation("file:///root/someDir/")}},
			expectedOutput: "another/file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedOutput, GetRelativeLocationFileName(test.location, test.invocations))
		})
	}
}

func TestGetFullLocationFileName(t *testing.T) {
	tests := []struct {
		file           string
		invocations    []*sarif.Invocation
		expectedOutput string
	}{
		{
			file:           filepath.Join("root", "someDir", "another", "file"),
			invocations:    []*sarif.Invocation{},
			expectedOutput: filepath.Join("root", "someDir", "another", "file"),
		},
		{
			file: filepath.Join("another", "file"),
			invocations: []*sarif.Invocation{
				{WorkingDirectory: sarif.NewSimpleArtifactLocation(filepath.Join("root", "someDir"))},
				{WorkingDirectory: sarif.NewSimpleArtifactLocation(filepath.Join("not", "relevant"))},
			},
			expectedOutput: filepath.Join("root", "someDir", "another", "file"),
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetFullLocationFileName(test.file, test.invocations))
	}
}

func TestSetLocationFileName(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput string
	}{
		{
			location:       nil,
			expectedOutput: "",
		},
		{
			location:       CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: "changedFilename",
		},
	}

	for _, test := range tests {
		SetLocationFileName(test.location, test.expectedOutput)
		assert.Equal(t, test.expectedOutput, GetLocationFileName(test.location))
	}
}

func TestGetLocationRegion(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput *sarif.Region
	}{
		{
			location:       nil,
			expectedOutput: nil,
		},
		{
			location:       &sarif.Location{PhysicalLocation: &sarif.PhysicalLocation{}},
			expectedOutput: nil,
		},
		{
			location: CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: sarif.NewRegion().WithByteOffset(0).WithCharOffset(0).WithStartLine(1).WithStartColumn(2).WithEndLine(3).WithEndColumn(4).
				WithSnippet(sarif.NewArtifactContent().WithText("snippet")),
		},
	}

	for _, test := range tests {
		actual := getLocationRegion(test.location)
		assert.Equal(t, test.expectedOutput, actual)
	}
}

func TestGetLocationStartLine(t *testing.T) {
	tests := []struct {
		name           string
		location       *sarif.Location
		expectedOutput int
	}{
		{
			name:           "Nil location",
			location:       nil,
			expectedOutput: 1,
		},
		{
			name:           "Location with valid start line",
			location:       CreateLocation("filename", 2, 2, 2, 2, "snippet"),
			expectedOutput: 2,
		},
		{
			name:           "Location with not valid start line",
			location:       CreateLocation("filename", -1, 2, 3, 4, "snippet"),
			expectedOutput: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedOutput, GetLocationStartLine(test.location))
		})
	}
}

func TestGetLocationStartColumn(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput int
	}{
		{
			location:       nil,
			expectedOutput: 1,
		},
		{
			location:       CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: 2,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetLocationStartColumn(test.location))
	}
}

func TestGetLocationEndLine(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput int
	}{
		{
			location:       nil,
			expectedOutput: 1,
		},
		{
			location:       CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: 3,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetLocationEndLine(test.location))
	}
}

func TestGetLocationEndColumn(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput int
	}{
		{
			location:       nil,
			expectedOutput: 1,
		},
		{
			location:       CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: 4,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetLocationEndColumn(test.location))
	}
}

func TestGetResultLevel(t *testing.T) {
	levelValueErr := "error"
	levelValueWarn := "warning"
	levelValueInfo := "info"
	levelValueNote := "note"
	levelValueNone := "none"

	tests := []struct {
		result           *sarif.Result
		expectedSeverity string
	}{
		{result: &sarif.Result{Level: levelValueErr},
			expectedSeverity: severityutils.LevelError.String()},
		{result: &sarif.Result{Level: levelValueWarn},
			expectedSeverity: severityutils.LevelWarning.String()},
		{result: &sarif.Result{Level: levelValueInfo},
			expectedSeverity: severityutils.LevelInfo.String()},
		{result: &sarif.Result{Level: levelValueNote},
			expectedSeverity: severityutils.LevelNote.String()},
		{result: &sarif.Result{Level: levelValueNone},
			expectedSeverity: severityutils.LevelNone.String()},
		{result: &sarif.Result{},
			expectedSeverity: ""},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedSeverity, test.result.Level)
	}
}

func TestGetRuleFullDescription(t *testing.T) {
	tests := []struct {
		rule           *sarif.ReportingDescriptor
		expectedOutput string
	}{
		{
			rule:           sarif.NewRule("rule"),
			expectedOutput: "",
		},
		{
			rule:           sarif.NewRule("rule").WithFullDescription(nil),
			expectedOutput: "",
		},
		{
			rule:           sarif.NewRule("rule").WithFullDescription(sarif.NewMultiformatMessageString().WithText("description")),
			expectedOutput: "description",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetRuleFullDescriptionText(test.rule))
	}
}

func TestGetRunRules(t *testing.T) {
	tests := []struct {
		run            *sarif.Run
		expectedOutput []*sarif.ReportingDescriptor
	}{
		{
			run:            &sarif.Run{},
			expectedOutput: []*sarif.ReportingDescriptor{},
		},
		{
			run:            CreateRunWithDummyResults(),
			expectedOutput: []*sarif.ReportingDescriptor{},
		},
		{
			run: CreateRunWithDummyResults(
				CreateDummyPassingResult("rule1"),
			),
			expectedOutput: []*sarif.ReportingDescriptor{sarif.NewRule("rule1").WithShortDescription(sarif.NewMultiformatMessageString().WithText("")).WithFullDescription(sarif.NewMultiformatMessageString().WithMarkdown("rule-markdown").WithText("rule-msg"))},
		},
		{
			run: CreateRunWithDummyResults(
				CreateDummyPassingResult("rule1"),
				CreateDummyPassingResult("rule1"),
				CreateDummyPassingResult("rule2"),
				CreateDummyPassingResult("rule3"),
				CreateDummyPassingResult("rule2"),
			),
			expectedOutput: []*sarif.ReportingDescriptor{
				sarif.NewRule("rule1").WithShortDescription(sarif.NewMultiformatMessageString().WithText("")).WithFullDescription(sarif.NewMultiformatMessageString().WithMarkdown("rule-markdown").WithText("rule-msg")),
				sarif.NewRule("rule2").WithShortDescription(sarif.NewMultiformatMessageString().WithText("")).WithFullDescription(sarif.NewMultiformatMessageString().WithMarkdown("rule-markdown").WithText("rule-msg")),
				sarif.NewRule("rule3").WithShortDescription(sarif.NewMultiformatMessageString().WithText("")).WithFullDescription(sarif.NewMultiformatMessageString().WithMarkdown("rule-markdown").WithText("rule-msg")),
			},
		},
	}

	for _, test := range tests {
		rules := GetRunRules(test.run)
		assert.Equal(t, test.expectedOutput, rules)
	}
}

func TestGetInvocationWorkingDirectory(t *testing.T) {
	tests := []struct {
		invocation     *sarif.Invocation
		expectedOutput string
	}{
		{
			invocation:     nil,
			expectedOutput: "",
		},
		{
			invocation:     sarif.NewInvocation(),
			expectedOutput: "",
		},
		{
			invocation:     sarif.NewInvocation().WithWorkingDirectory(nil),
			expectedOutput: "",
		},
		{
			invocation:     sarif.NewInvocation().WithWorkingDirectory(sarif.NewArtifactLocation()),
			expectedOutput: "",
		},
		{
			invocation:     sarif.NewInvocation().WithWorkingDirectory(sarif.NewArtifactLocation().WithURI("file_to_wd")),
			expectedOutput: "file_to_wd",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetInvocationWorkingDirectory(test.invocation))
	}
}

func TestGetResultFingerprint(t *testing.T) {
	tests := []struct {
		name           string
		result         *sarif.Result
		expectedOutput string
	}{
		{
			name:           "No results",
			result:         &sarif.Result{},
			expectedOutput: "",
		},
		{
			name:           "Empty fingerprint field in the result",
			result:         CreateResultWithLocations("msg", "rule", "level"),
			expectedOutput: "",
		},
		{
			name:           "Results with fingerprint field",
			result:         CreateDummyResultWithFingerprint("some_markdown", "msg", jasutils.SastFingerprintKey, "sast_fingerprint"),
			expectedOutput: "sast_fingerprint",
		},
	}
	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetResultFingerprint(test.result))
	}
}

func TestGroupResultsByLocation(t *testing.T) {
	tests := []struct {
		run            *sarif.Run
		expectedOutput *sarif.Run
	}{
		{
			run:            CreateRunWithDummyResults(),
			expectedOutput: CreateRunWithDummyResults(),
		},
		{
			// No similar groups at all
			run: CreateRunWithDummyResults(
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "note"),
				CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					CreateCodeFlow(CreateThreadFlow(
						CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
				CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule2", "info").WithCodeFlows([]*sarif.CodeFlow{
					CreateCodeFlow(CreateThreadFlow(
						CreateLocation("other2", 1, 1, 1, 1, "other-snippet2"),
						CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
			),
			expectedOutput: CreateRunWithDummyResults(
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "note"),
				CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					CreateCodeFlow(CreateThreadFlow(
						CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
				CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule2", "info").WithCodeFlows([]*sarif.CodeFlow{
					CreateCodeFlow(CreateThreadFlow(
						CreateLocation("other2", 1, 1, 1, 1, "other-snippet2"),
						CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
			),
		},
		{
			// With similar groups
			run: CreateRunWithDummyResults(
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					CreateCodeFlow(CreateThreadFlow(
						CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					CreateCodeFlow(CreateThreadFlow(
						CreateLocation("other2", 1, 1, 1, 1, "other-snippet"),
						CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
			),
			expectedOutput: CreateRunWithDummyResults(
				CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					CreateCodeFlow(CreateThreadFlow(
						CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
					CreateCodeFlow(CreateThreadFlow(
						CreateLocation("other2", 1, 1, 1, 1, "other-snippet"),
						CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
			),
		},
	}

	for _, test := range tests {
		grouped := GroupResultsByLocation([]*sarif.Run{test.run})
		require.Len(t, grouped, 1)
		assert.ElementsMatch(t, test.expectedOutput.Results, grouped[0].Results)
	}
}

// GroupResultsByLocation copies results via go-sarif constructors, which default index fields to -1.
// Analyzer Manager output unmarshals omitted indexes as 0; the copy must keep those values so uploaded CDX matches --output-dir dumps.
func TestCopyLocationPreservesSourceIdAndRegionOffsets(t *testing.T) {
	location := CreateLocation("file.go", 1, 2, 3, 4, "snippet")
	location.ID = -1
	location.PhysicalLocation.Region.CharOffset = -1
	location.PhysicalLocation.Region.ByteOffset = -1

	copied := CopyLocation(location)
	require.NotNil(t, copied)
	assert.Equal(t, -1, copied.ID, "must not replace constructor sentinel with 0")
	assert.Equal(t, -1, copied.PhysicalLocation.Region.CharOffset)
	assert.Equal(t, -1, copied.PhysicalLocation.Region.ByteOffset)

	location.ID = 7
	location.PhysicalLocation.Region.CharOffset = 10
	location.PhysicalLocation.Region.ByteOffset = 20
	copied = CopyLocation(location)
	assert.Equal(t, 7, copied.ID)
	assert.Equal(t, 10, copied.PhysicalLocation.Region.CharOffset)
	assert.Equal(t, 20, copied.PhysicalLocation.Region.ByteOffset)
}

func TestGroupResultsByLocationPreservesZeroIndexes(t *testing.T) {
	location := CreateLocation("src/main/java/com/example/HelloWorld.java", 5, 29, 5, 42, "String[] args")
	location.PhysicalLocation.ArtifactLocation.Index = 0
	location.LogicalLocations = []*sarif.LogicalLocation{{
		FullyQualifiedName: ptrTo("com.example.HelloWorld.main"),
		Index:              0,
		ParentIndex:        0,
	}}

	threadFlowLocation := &sarif.ThreadFlowLocation{
		ExecutionOrder: 0,
		Importance:     "",
		Index:          0,
		Location:       location,
	}
	result := CreateResultWithLocations("result-msg", "rule1", "error", location).WithCodeFlows([]*sarif.CodeFlow{
		{ThreadFlows: []*sarif.ThreadFlow{{Locations: []*sarif.ThreadFlowLocation{threadFlowLocation}}}},
	})

	grouped := GroupResultsByLocation([]*sarif.Run{CreateRunWithDummyResults(result)})
	require.Len(t, grouped, 1)
	require.Len(t, grouped[0].Results, 1)

	copiedLocation := grouped[0].Results[0].Locations[0]
	assert.Equal(t, 0, copiedLocation.PhysicalLocation.ArtifactLocation.Index)
	require.Len(t, copiedLocation.LogicalLocations, 1)
	assert.Equal(t, 0, copiedLocation.LogicalLocations[0].Index)
	assert.Equal(t, 0, copiedLocation.LogicalLocations[0].ParentIndex)

	copiedThreadFlowLocation := grouped[0].Results[0].CodeFlows[0].ThreadFlows[0].Locations[0]
	assert.Equal(t, 0, copiedThreadFlowLocation.Index)
	assert.Equal(t, 0, copiedThreadFlowLocation.ExecutionOrder)
	assert.Equal(t, "", copiedThreadFlowLocation.Importance)
}

func ptrTo[T any](v T) *T {
	return &v
}

// Mirrors go-sarif v1.1.1 index fields (*uint + omitempty). Negative sentinels from v3 fail to decode.
type legacySarifPayload struct {
	Runs []legacyRun `json:"runs"`
}

type legacyRun struct {
	Results []legacyResult `json:"results"`
}

type legacyResult struct {
	RuleIndex *uint            `json:"ruleIndex,omitempty"`
	Locations []legacyLocation `json:"locations"`
	CodeFlows []legacyCodeFlow `json:"codeFlows,omitempty"`
}

type legacyCodeFlow struct {
	ThreadFlows []legacyThreadFlow `json:"threadFlows"`
}

type legacyThreadFlow struct {
	Locations []legacyThreadFlowLocation `json:"locations"`
}

type legacyThreadFlowLocation struct {
	Index          *uint           `json:"index,omitempty"`
	ExecutionOrder *uint           `json:"executionOrder,omitempty"`
	Location       *legacyLocation `json:"location,omitempty"`
}

type legacyLocation struct {
	ID               *uint                   `json:"id,omitempty"`
	PhysicalLocation *legacyPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []legacyLogicalLocation `json:"logicalLocations,omitempty"`
}

type legacyPhysicalLocation struct {
	ArtifactLocation *legacyArtifactLocation `json:"artifactLocation,omitempty"`
}

type legacyArtifactLocation struct {
	URI   string `json:"uri,omitempty"`
	Index *uint  `json:"index,omitempty"`
}

type legacyLogicalLocation struct {
	Index       *uint `json:"index,omitempty"`
	ParentIndex *uint `json:"parentIndex,omitempty"`
}

func TestStripUnsetIndexesKeepsPayloadDecodableByLegacyConsumers(t *testing.T) {
	payload := []byte(`{
		"runs": [{
			"results": [{
				"ruleIndex": -1,
				"locations": [{
					"id": -1,
					"physicalLocation": {
						"artifactLocation": {"uri": "file.go", "index": -1}
					},
					"logicalLocations": [{"index": -1, "parentIndex": -1}]
				}],
				"codeFlows": [{
					"threadFlows": [{
						"locations": [{
							"index": -1,
							"executionOrder": -1,
							"location": {
								"physicalLocation": {
									"artifactLocation": {"uri": "file.go", "index": 0}
								}
							}
						}]
					}]
				}]
			}, {
				"ruleIndex": 2,
				"locations": [{
					"id": 0,
					"physicalLocation": {
						"artifactLocation": {"uri": "other.go", "index": 5}
					}
				}]
			}]
		}]
	}`)

	var before legacySarifPayload
	require.Error(t, json.Unmarshal(payload, &before), "negative indexes must fail go-sarif v1 *uint decoding")

	sanitized, err := StripUnsetIndexes(payload)
	require.NoError(t, err)

	var after legacySarifPayload
	require.NoError(t, json.Unmarshal(sanitized, &after))
	require.Len(t, after.Runs, 1)
	require.Len(t, after.Runs[0].Results, 2)

	first := after.Runs[0].Results[0]
	assert.Nil(t, first.RuleIndex)
	require.Len(t, first.Locations, 1)
	assert.Nil(t, first.Locations[0].ID)
	assert.Nil(t, first.Locations[0].PhysicalLocation.ArtifactLocation.Index)
	require.Len(t, first.Locations[0].LogicalLocations, 1)
	assert.Nil(t, first.Locations[0].LogicalLocations[0].Index)
	assert.Nil(t, first.Locations[0].LogicalLocations[0].ParentIndex)
	require.Len(t, first.CodeFlows, 1)
	threadLoc := first.CodeFlows[0].ThreadFlows[0].Locations[0]
	assert.Nil(t, threadLoc.Index)
	assert.Nil(t, threadLoc.ExecutionOrder)
	require.NotNil(t, threadLoc.Location.PhysicalLocation.ArtifactLocation.Index)
	assert.Equal(t, uint(0), *threadLoc.Location.PhysicalLocation.ArtifactLocation.Index)

	second := after.Runs[0].Results[1]
	require.NotNil(t, second.RuleIndex)
	assert.Equal(t, uint(2), *second.RuleIndex)
	require.NotNil(t, second.Locations[0].ID)
	assert.Equal(t, uint(0), *second.Locations[0].ID)
	require.NotNil(t, second.Locations[0].PhysicalLocation.ArtifactLocation.Index)
	assert.Equal(t, uint(5), *second.Locations[0].PhysicalLocation.ArtifactLocation.Index)
}
