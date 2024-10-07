package sarifutils

import (
	"github.com/owenrumney/go-sarif/v2/sarif"
)

func CreateRunWithDummyResultsInWd(wd string, results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults("", results...).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))})
}

func CreateRunWithDummyResults(results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults("", results...)
}

func CreateDummyDriver(toolName string, rules ...*sarif.ReportingDescriptor) *sarif.ToolComponent {
	return &sarif.ToolComponent{
		Name:  toolName,
		Rules: rules,
	}
}

func CreateRunNameWithResults(toolName string, results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults(toolName, results...)
}

func createRunWithDummyResults(toolName string, results ...*sarif.Result) *sarif.Run {
	run := sarif.NewRun(*sarif.NewSimpleTool(toolName))
	for _, result := range results {
		if result.RuleID != nil {
			run.AddRule(*result.RuleID)
		}
		run.AddResult(result)
	}
	return run
}

func CreateRunWithDummyResultAndRuleProperties(result *sarif.Result, properties, values []string) *sarif.Run {
	if len(properties) != len(values) {
		return nil
	}
	run := CreateRunWithDummyResults(result)
	rule := GetRuleById(run, GetResultRuleId(result))
	if rule == nil {
		return nil
	}
	rule.Properties = map[string]interface{}{}
	for index := range properties {
		rule.Properties[properties[index]] = values[index]
	}
	return run
}

func CreateDummyResultInPath(fileName string) *sarif.Result {
	return CreateResultWithOneLocation(fileName, 0, 0, 0, 0, "snippet", "rule", "level")
}

func CreateDummyResult(markdown, msg, ruleId, level string) *sarif.Result {
	return &sarif.Result{
		Message: *sarif.NewTextMessage(msg).WithMarkdown(markdown),
		Level:   &level,
		RuleID:  &ruleId,
	}
}

func CreateResultWithProperties(msg, ruleId, level string, properties map[string]string, locations ...*sarif.Location) *sarif.Result {
	result := &sarif.Result{
		Message:   *sarif.NewTextMessage(msg),
		Level:     &level,
		RuleID:    &ruleId,
		Locations: locations,
	}
	result.Properties = map[string]interface{}{}
	for key, val := range properties {
		result.Properties[key] = val
	}
	return result
}

func CreateResultWithDummyLocationAmdProperty(fileName, property, value string) *sarif.Result {
	resultWithLocation := CreateDummyResultInPath(fileName)
	resultWithLocation.Properties = map[string]interface{}{property: value}
	return resultWithLocation
}

func CreateResultWithLocations(msg, ruleId, level string, locations ...*sarif.Location) *sarif.Result {
	result := CreateDummyResult("", msg, ruleId, level)
	result.Locations = locations
	return result
}

func CreateDummyResultWithFingerprint(markdown, msg, algorithm, value string, locations ...*sarif.Location) *sarif.Result {
	result := CreateDummyResult(markdown, msg, "rule", "level")
	if result.RuleIndex == nil {
		result.RuleIndex = newUintPtr(0)
	}
	result.Locations = locations
	result.Fingerprints = map[string]interface{}{algorithm: value}
	return result
}

func newUintPtr(v uint) *uint {
	return &v
}

func CreateDummyResultWithPathAndLogicalLocation(fileName, logicalName, kind, property, value string) *sarif.Result {
	result := CreateDummyResult("", "", "rule", "level")
	result.Locations = append(result.Locations, CreateDummyLocationWithPathAndLogicalLocation(fileName, logicalName, kind, property, value))
	return result
}

func CreateDummyLocationWithPathAndLogicalLocation(fileName, logicalName, kind, property, value string) *sarif.Location {
	location := CreateDummyLocationInPath(fileName)
	location.LogicalLocations = append(location.LogicalLocations, CreateLogicalLocationWithProperty(logicalName, kind, property, value))
	return location
}

func CreateDummyLocationInPath(fileName string) *sarif.Location {
	return CreateLocation(fileName, 0, 0, 0, 0, "snippet")
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
