package sarifutils

import (
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
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
		location       *sarif.Location
		invocations    []*sarif.Invocation
		expectedOutput string
	}{
		{
			location:       CreateLocation("file:///root/someDir/another/file", 1, 2, 3, 4, "snippet"),
			invocations:    []*sarif.Invocation{},
			expectedOutput: "root/someDir/another/file",
		},
		{
			location:       CreateLocation("file:///root/someDir/another/file", 1, 2, 3, 4, "snippet"),
			invocations:    []*sarif.Invocation{{WorkingDirectory: sarif.NewSimpleArtifactLocation("/not/relevant")}},
			expectedOutput: "root/someDir/another/file",
		},
		{
			location:       CreateLocation("file:///root/someDir/another/file", 1, 2, 3, 4, "snippet"),
			invocations:    []*sarif.Invocation{{WorkingDirectory: sarif.NewSimpleArtifactLocation("/root/someDir/")}},
			expectedOutput: "another/file",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetRelativeLocationFileName(test.location, test.invocations))
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
			expectedOutput: sarif.NewRegion().WithStartLine(1).WithStartColumn(2).WithEndLine(3).WithEndColumn(4).
				WithSnippet(sarif.NewArtifactContent().WithText("snippet")),
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, getLocationRegion(test.location))
	}
}

func TestGetLocationStartLine(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput int
	}{
		{
			location:       nil,
			expectedOutput: 0,
		},
		{
			location:       CreateLocation("filename", 1, 2, 3, 4, "snippet"),
			expectedOutput: 1,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetLocationStartLine(test.location))
	}
}

func TestGetLocationStartColumn(t *testing.T) {
	tests := []struct {
		location       *sarif.Location
		expectedOutput int
	}{
		{
			location:       nil,
			expectedOutput: 0,
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
			expectedOutput: 0,
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
			expectedOutput: 0,
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

func TestExtractRelativePath(t *testing.T) {
	tests := []struct {
		fullPath       string
		projectPath    string
		expectedResult string
	}{
		{fullPath: "file:///Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js",
			projectPath: "Users/user/Desktop/secrets_scanner/", expectedResult: "tests/req.nodejs/file.js"},
		{fullPath: "file:///private/Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js",
			projectPath: "Users/user/Desktop/secrets_scanner/", expectedResult: "tests/req.nodejs/file.js"},
		{fullPath: "invalidFullPath",
			projectPath: "Users/user/Desktop/secrets_scanner/", expectedResult: "invalidFullPath"},
		{fullPath: "",
			projectPath: "Users/user/Desktop/secrets_scanner/", expectedResult: ""},
		{fullPath: "file:///Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js",
			projectPath: "invalidProjectPath", expectedResult: "Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js"},
		{fullPath: "file:///private/Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js",
			projectPath: "invalidProjectPath", expectedResult: "Users/user/Desktop/secrets_scanner/tests/req.nodejs/file.js"},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedResult, ExtractRelativePath(test.fullPath, test.projectPath))
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
		{result: &sarif.Result{Level: &levelValueErr},
			expectedSeverity: severityutils.LevelError.String()},
		{result: &sarif.Result{Level: &levelValueWarn},
			expectedSeverity: severityutils.LevelWarning.String()},
		{result: &sarif.Result{Level: &levelValueInfo},
			expectedSeverity: severityutils.LevelInfo.String()},
		{result: &sarif.Result{Level: &levelValueNote},
			expectedSeverity: severityutils.LevelNote.String()},
		{result: &sarif.Result{Level: &levelValueNone},
			expectedSeverity: severityutils.LevelNone.String()},
		{result: &sarif.Result{},
			expectedSeverity: ""},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedSeverity, GetResultLevel(test.result))
	}
}

func TestIsApplicableResult(t *testing.T) {
	tests := []struct {
		name           string
		sarifResult    *sarif.Result
		expectedOutput bool
	}{
		{
			sarifResult:    CreateDummyPassingResult("rule"),
			expectedOutput: false,
		},
		{
			sarifResult:    CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet1", "ruleId1", "level1"),
			expectedOutput: true,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, IsResultKindNotPass(test.sarifResult))
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
			rule:           sarif.NewRule("rule").WithFullDescription(sarif.NewMultiformatMessageString("description")),
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
			expectedOutput: []*sarif.ReportingDescriptor{sarif.NewRule("rule1")},
		},
		{
			run: CreateRunWithDummyResults(
				CreateDummyPassingResult("rule1"),
				CreateDummyPassingResult("rule1"),
				CreateDummyPassingResult("rule2"),
				CreateDummyPassingResult("rule3"),
				CreateDummyPassingResult("rule2"),
			),
			expectedOutput: []*sarif.ReportingDescriptor{sarif.NewRule("rule1"), sarif.NewRule("rule2"), sarif.NewRule("rule3")},
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetRunRules(test.run))
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
			invocation:     sarif.NewInvocation().WithWorkingDirectory(sarif.NewArtifactLocation().WithUri("file_to_wd")),
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
			result:         CreateDummyResultWithFingerprint("some_markdown", "masg", jasutils.SastFingerprintKey, "sast_fingerprint"),
			expectedOutput: "sast_fingerprint",
		},
	}
	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, GetResultFingerprint(test.result))
	}
}
