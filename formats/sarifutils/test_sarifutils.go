package sarifutils

import "github.com/owenrumney/go-sarif/v2/sarif"

func CreateRunWithDummyResultsInWd(wd string, results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults("", results...).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))})
}

func CreateRunWithDummyResults(results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults("", results...)
}

func CreateRunNameWithResults(toolName string, results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults(toolName, results...)
}

func createRunWithDummyResults(toolName string, results ...*sarif.Result) *sarif.Run {
	run := sarif.NewRunWithInformationURI(toolName, "")
	for _, result := range results {
		if result.RuleID != nil {
			run.AddRule(*result.RuleID)
		}
		run.AddResult(result)
	}
	return run
}

func CreateRunWithDummyResultAndRuleProperties(property, value string, result *sarif.Result) *sarif.Run {
	run := sarif.NewRunWithInformationURI("", "")
	if result.RuleID != nil {
		run.AddRule(*result.RuleID)
	}
	run.AddResult(result)
	run.Tool.Driver.Rules[0].Properties = make(sarif.Properties)
	run.Tool.Driver.Rules[0].Properties[property] = value
	return run
}

func CreateDummyResultInPath(fileName string) *sarif.Result {
	return CreateResultWithOneLocation(fileName, 0, 0, 0, 0, "snippet", "rule", "level")
}

func CreateResultWithPropertyAndDummyLocation(fileName, property, value string) *sarif.Result {
	resultWithLocation := CreateDummyResultInPath(fileName)
	resultWithLocation.Properties = map[string]interface{}{property: value}
	return resultWithLocation
}

func CreateResultWithLocations(msg, ruleId, level string, locations ...*sarif.Location) *sarif.Result {
	return &sarif.Result{
		Message:   *sarif.NewTextMessage(msg),
		Locations: locations,
		Level:     &level,
		RuleID:    &ruleId,
	}
}

func CreateLocation(fileName string, startLine, startCol, endLine, endCol int, snippet string) *sarif.Location {
	return &sarif.Location{
		PhysicalLocation: &sarif.PhysicalLocation{
			ArtifactLocation: &sarif.ArtifactLocation{URI: &fileName},
			Region: &sarif.Region{
				StartLine:   &startLine,
				StartColumn: &startCol,
				EndLine:     &endLine,
				EndColumn:   &endCol,
				Snippet:     &sarif.ArtifactContent{Text: &snippet}}},
	}
}

func CreateLogicalLocationWithProperty(name, kind, property, value string) *sarif.LogicalLocation {
	location := sarif.NewLogicalLocation().WithName(name).WithKind(kind)
	location.Properties = map[string]interface{}{property: value}
	return location
}

func CreateDummyPassingResult(ruleId string) *sarif.Result {
	kind := "pass"
	return &sarif.Result{
		Kind:   &kind,
		RuleID: &ruleId,
	}
}

func CreateResultWithOneLocation(fileName string, startLine, startCol, endLine, endCol int, snippet, ruleId, level string) *sarif.Result {
	return CreateResultWithLocations("", ruleId, level, CreateLocation(fileName, startLine, startCol, endLine, endCol, snippet))
}

func CreateCodeFlow(threadFlows ...*sarif.ThreadFlow) *sarif.CodeFlow {
	flow := sarif.NewCodeFlow()
	for _, threadFlow := range threadFlows {
		flow.AddThreadFlow(threadFlow)
	}
	return flow
}

func CreateThreadFlow(locations ...*sarif.Location) *sarif.ThreadFlow {
	stackStrace := sarif.NewThreadFlow()
	for _, location := range locations {
		stackStrace.AddLocation(sarif.NewThreadFlowLocation().WithLocation(location))
	}
	return stackStrace
}
