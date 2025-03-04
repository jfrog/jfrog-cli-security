package sarifutils

import (
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// TODO: Create a Builder struct (with dynamic setters) and refactor sarif tests for better maintenance

func CreateRunWithDummyResultsWithRuleInformation(toolName, ruleShortTxtDescription, ruleTxtDescription, ruleMarkdownDescription, ruleHelpMsg, ruleHelpMarkdown, wd string, results ...*sarif.Result) *sarif.Run {
	run := createRunWithDummyResults(toolName, ruleShortTxtDescription, ruleTxtDescription, ruleMarkdownDescription, ruleHelpMsg, ruleHelpMarkdown, results...)
	run.Invocations = []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))}
	return run
}

func CreateRunWithDummyResultsInWdWithHelp(helpMsg, helpMarkdown, wd string, results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults("", "", "rule-msg", "rule-markdown", helpMsg, helpMarkdown, results...).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))})
}

func CreateRunWithDummyResultsInWd(wd string, results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults("", "", "rule-msg", "rule-markdown", "", "", results...).WithInvocations([]*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))})
}

func CreateRunWithDummyResults(results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults("", "", "rule-msg", "rule-markdown", "", "", results...)
}

func CreateDummyDriver(toolName string, rules ...*sarif.ReportingDescriptor) *sarif.ToolComponent {
	return &sarif.ToolComponent{
		Name:  toolName,
		Rules: rules,
	}
}

func CreateRunNameWithResults(toolName string, results ...*sarif.Result) *sarif.Run {
	return createRunWithDummyResults(toolName, "", "rule-msg", "rule-markdown", "", "", results...)
}

func createRunWithDummyResults(toolName, ruleShortTxtDescription, ruleMsg, ruleMarkdown, ruleHelpMsg, ruleHelpMarkdown string, results ...*sarif.Result) *sarif.Run {
	run := sarif.NewRun(*sarif.NewSimpleTool(toolName))
	for _, result := range results {
		if result.RuleID != nil {
			rule := run.AddRule(*result.RuleID)
			SetRuleFullDescription(ruleMsg, ruleMarkdown, rule)
			if ruleHelpMsg != "" || ruleHelpMarkdown != "" {
				SetRuleHelp(ruleHelpMsg, ruleHelpMarkdown, rule)
			}
			SetRuleShortDescriptionText(ruleShortTxtDescription, rule)
		}
		run.AddResult(result)
	}
	return run
}

func CreateRunWithDummyResultAndRuleInformation(result *sarif.Result, ruleHelpMsg, ruleHelpMarkdown string, properties, values []string) *sarif.Run {
	run := CreateRunWithDummyResultAndRuleProperties(result, properties, values)
	if run != nil {
		rule := GetRuleById(run, GetResultRuleId(result))
		if rule != nil {
			SetRuleHelp(ruleHelpMsg, ruleHelpMarkdown, rule)
		}
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

func CreateDummyRule(ruleId, ruleDescription, summary, markdownDescription string, properties sarif.Properties) *sarif.ReportingDescriptor {
	return sarif.NewRule(ruleId).WithProperties(properties).WithDescription(ruleDescription).WithHelp(sarif.NewMultiformatMessageString(summary).WithMarkdown(markdownDescription))

}

func CreateDummyResultInPath(fileName string) *sarif.Result {
	return CreateResultWithOneLocation(fileName, 0, 0, 0, 0, "snippet", "rule", "level")
}

func CreateDummyResult(markdown, msg, ruleId, level string, locations ...*sarif.Location) *sarif.Result {
	result := &sarif.Result{
		Message: sarif.Message{Text: &msg, Markdown: &markdown},
		Level:   &level,
		RuleID:  &ruleId,
	}
	if len(locations) > 0 {
		result.Locations = locations
	}
	return result
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
	result := CreateDummyResult("result-markdown", msg, ruleId, level)
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
	result := CreateDummyResult("result-markdown", "result-msg", "rule", "level")
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
	return CreateResultWithLocations("result-msg", ruleId, level, CreateLocation(fileName, startLine, startCol, endLine, endCol, snippet))
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

func CreateDummyRuleWithProperties(id string, properties sarif.Properties) *sarif.ReportingDescriptor {
	return &sarif.ReportingDescriptor{
		ID:               id,
		Properties:       properties,
		ShortDescription: sarif.NewMultiformatMessageString(""),
		FullDescription:  sarif.NewMarkdownMultiformatMessageString("rule-markdown").WithText("rule-msg"),
	}
}
