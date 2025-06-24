package sarifutils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	WatchSarifPropertyKey                   = "watch"
	PoliciesSarifPropertyKey                = "policies"
	JasIssueIdSarifPropertyKey              = "issueId"
	JasScannerIdSarifPropertyKey            = "scanner_id"
	CWEPropertyKey                          = "CWE"
	SarifImpactPathsRulePropertyKey         = "impactPaths"
	TokenValidationStatusSarifPropertyKey   = "tokenValidation"
	TokenValidationMetadataSarifPropertyKey = "metadata"
	CAUndeterminedReasonSarifPropertyKey    = "undetermined_reason"
)

// Specific JFrog Sarif Utils

func GetResultPropertyTokenValidation(result *sarif.Result) string {
	return GetResultProperty(TokenValidationStatusSarifPropertyKey, result)
}

func GetResultPropertyMetadata(result *sarif.Result) string {
	return GetResultProperty(TokenValidationMetadataSarifPropertyKey, result)
}

func GetResultWatches(result *sarif.Result) (watches string) {
	return GetResultProperty(WatchSarifPropertyKey, result)
}

func GetResultPolicies(result *sarif.Result) (policies []string) {
	if result == nil || result.Properties == nil {
		return
	}
	// Check if the property exists
	if policiesProperty, ok := result.Properties.Properties[PoliciesSarifPropertyKey]; ok {
		if policiesValue, ok := policiesProperty.(string); ok {
			split := strings.Split(policiesValue, ",")
			for _, policy := range split {
				policies = append(policies, strings.TrimSpace(policy))
			}
			return
		}
	}
	return
}

func GetResultIssueId(result *sarif.Result) (issueId string) {
	if result == nil || result.Properties == nil {
		return
	}
	// Check if the property exists
	if issueIdProperty, ok := result.Properties.Properties[JasIssueIdSarifPropertyKey]; ok {
		if issueIdValue, ok := issueIdProperty.(string); ok {
			return issueIdValue
		}
	}
	return
}

func GetDockerLayer(location *sarif.Location) (layer, algorithm string) {
	// If location has logical location with kind "layer" return it
	if logicalLocation := GetLogicalLocation("layer", location); logicalLocation != nil && logicalLocation.Name != nil && logicalLocation.Properties != nil {
		layer = *logicalLocation.Name
		if algorithmValue, ok := logicalLocation.Properties.Properties["algorithm"].(string); ok {
			algorithm = algorithmValue
		}
		return
	}
	return
}

func GetRuleScannerId(rule *sarif.ReportingDescriptor) (issueId string) {
	return GetRuleProperty(JasScannerIdSarifPropertyKey, rule)
}

func GetRuleUndeterminedReason(rule *sarif.ReportingDescriptor) string {
	return GetRuleProperty(CAUndeterminedReasonSarifPropertyKey, rule)
}

func GetRuleCWE(rule *sarif.ReportingDescriptor) (cwe []string) {
	if rule == nil || rule.DefaultConfiguration == nil || rule.DefaultConfiguration.Parameters == nil || rule.DefaultConfiguration.Parameters.Properties == nil {
		// No CWE property
		return
	}
	if cweProperty, ok := rule.DefaultConfiguration.Parameters.Properties[CWEPropertyKey]; ok {
		if cweValue, ok := cweProperty.(string); ok {
			split := strings.Split(cweValue, ",")
			for _, policy := range split {
				cwe = append(cwe, strings.TrimSpace(policy))
			}
			return
		}
	}
	return
}

// General Sarif Utils

func CombineReports(reports ...*sarif.Report) (combined *sarif.Report) {
	combined = sarif.NewReport()
	for _, report := range reports {
		for _, run := range report.Runs {
			appendRunInfoToReport(combined, run)
		}
	}
	return
}

func CombineMultipleRunsWithSameTool(report *sarif.Report) (combined *sarif.Report) {
	combined = sarif.NewReport()
	for _, run := range report.Runs {
		appendRunInfoToReport(combined, run)
	}
	return
}

func appendRunInfoToReport(combined *sarif.Report, run *sarif.Run) {
	if existingRun := getRunByToolName(GetRunToolName(run), combined); existingRun != nil {
		AggregateMultipleRunsIntoSingle([]*sarif.Run{run}, existingRun)
	} else {
		combined.AddRun(run)
	}
}

func getRunByToolName(toolName string, report *sarif.Report) (run *sarif.Run) {
	for _, r := range report.Runs {
		if GetRunToolName(r) == toolName {
			return r
		}
	}
	return
}

func GetRunsByToolName(report *sarif.Report, toolName string) (filteredRuns []*sarif.Run) {
	for _, run := range report.Runs {
		if GetRunToolName(run) == toolName {
			filteredRuns = append(filteredRuns, run)
		}
	}
	return
}

func GetToolVersion(run *sarif.Run) string {
	if run.Tool.Driver != nil && run.Tool.Driver.Version != nil {
		return *run.Tool.Driver.Version
	}
	return ""
}

func CopyRun(run *sarif.Run) *sarif.Run {
	copy := CopyRunMetadata(run)
	if run.Tool.Driver != nil {
		copy.Tool.Driver.Rules = CopyRules(run.Tool.Driver.Rules...)
	}
	for _, result := range run.Results {
		copy.Results = append(copy.Results, CopyResult(result))
	}
	return copy
}

func CopyRunMetadata(run *sarif.Run) (copied *sarif.Run) {
	if run == nil {
		return
	}
	copied = sarif.NewRun().WithTool(sarif.NewTool().WithDriver(sarif.NewToolComponent().WithName(GetRunToolName(run)))).WithInvocations(run.Invocations)

	if toolFullName := GetRunToolFullName(run); toolFullName != "" {
		copied.Tool.Driver.FullName = &toolFullName
	}
	if toolVersion := GetToolVersion(run); toolVersion != "" {
		copied.Tool.Driver.Version = &toolVersion
	}
	if fullDescription := GetRunToolFullDescription(run); fullDescription != "" {
		SetRunToolFullDescriptionText(fullDescription, copied)
	}
	if fullDescriptionMarkdown := GetRunToolFullDescriptionMarkdown(run); fullDescriptionMarkdown != "" {
		SetRunToolFullDescriptionMarkdown(fullDescriptionMarkdown, copied)
	}
	if run.Language != "" {
		copied.Language = run.Language
	}
	if informationURI := GetRunToolInformationURI(run); informationURI != "" {
		copied.Tool.Driver.InformationURI = &informationURI
	}
	return
}

func CopyRules(rules ...*sarif.ReportingDescriptor) (copied []*sarif.ReportingDescriptor) {
	for _, rule := range rules {
		cloned := sarif.NewRule(GetRuleId(rule))
		cloned.HelpURI = copyStrAttribute(rule.HelpURI)
		cloned.Name = copyStrAttribute(rule.Name)
		cloned.ShortDescription = copyMultiMsgAttribute(rule.ShortDescription)
		cloned.FullDescription = copyMultiMsgAttribute(rule.FullDescription)
		cloned.DefaultConfiguration = rule.DefaultConfiguration
		cloned.Help = copyMultiMsgAttribute(rule.Help)
		cloned.Properties = rule.Properties
		cloned.MessageStrings = rule.MessageStrings
		copied = append(copied, cloned)
	}
	return
}

func GetRunToolFullName(run *sarif.Run) string {
	if run.Tool.Driver != nil && run.Tool.Driver.FullName != nil {
		return *run.Tool.Driver.FullName
	}
	return ""
}

func GetRunToolFullDescription(run *sarif.Run) string {
	if run.Tool.Driver != nil && run.Tool.Driver.FullDescription != nil && run.Tool.Driver.FullDescription.Text != nil {
		return *run.Tool.Driver.FullDescription.Text
	}
	return ""
}

func GetRunToolInformationURI(run *sarif.Run) string {
	if run.Tool.Driver != nil && run.Tool.Driver.InformationURI != nil {
		return *run.Tool.Driver.InformationURI
	}
	return ""
}

func NewPhysicalLocation(physicalPath string) *sarif.PhysicalLocation {
	return &sarif.PhysicalLocation{
		ArtifactLocation: sarif.NewArtifactLocation().WithURI(physicalPath),
	}
}

func NewPhysicalLocationWithRegion(physicalPath string, startRow, endRow, startCol, endCol int) *sarif.PhysicalLocation {
	location := NewPhysicalLocation(physicalPath)
	location.Region = &sarif.Region{
		StartLine:   &startRow,
		EndLine:     &endRow,
		StartColumn: &startCol,
		EndColumn:   &endCol,
	}
	return location
}

func NewLogicalLocation(name, kind string) *sarif.LogicalLocation {
	return &sarif.LogicalLocation{
		Name: &name,
		Kind: &kind,
	}
}

func ReadScanRunsFromFile(fileName string) (sarifRuns []*sarif.Run, err error) {
	report, err := sarif.Open(fileName)
	if errorutils.CheckError(err) != nil {
		err = fmt.Errorf("can't read valid Sarif run from %s: %s", fileName, err.Error())
		return
	}
	sarifRuns = report.Runs
	return
}

func CopyResult(result *sarif.Result) *sarif.Result {
	copied := &sarif.Result{
		RuleID:       result.RuleID,
		RuleIndex:    result.RuleIndex,
		Kind:         result.Kind,
		Fingerprints: result.Fingerprints,
		CodeFlows:    copyCodeFlows(result.CodeFlows...),
		Level:        result.Level,
		Message:      copyMsgAttribute(result.Message),
		Properties:   result.Properties,
	}
	for _, location := range result.Locations {
		copied.Locations = append(copied.Locations, CopyLocation(location))
	}
	return copied
}

func copyCodeFlows(flows ...*sarif.CodeFlow) []*sarif.CodeFlow {
	var copied []*sarif.CodeFlow
	for _, flow := range flows {
		copied = append(copied, copyCodeFlow(flow))
	}
	return copied
}

func copyCodeFlow(flow *sarif.CodeFlow) *sarif.CodeFlow {
	copied := &sarif.CodeFlow{}
	for _, threadFlow := range flow.ThreadFlows {
		copied.ThreadFlows = append(copied.ThreadFlows, copyThreadFlow(threadFlow))
	}
	return copied
}

func copyThreadFlow(threadFlow *sarif.ThreadFlow) *sarif.ThreadFlow {
	copied := &sarif.ThreadFlow{}
	for _, location := range threadFlow.Locations {
		copied.Locations = append(copied.Locations, sarif.NewThreadFlowLocation().WithLocation(CopyLocation(location.Location)))
	}
	return copied
}

func copyMsgAttribute(attr *sarif.Message) *sarif.Message {
	return &sarif.Message{
		Text:     copyStrAttribute(attr.Text),
		Markdown: copyStrAttribute(attr.Markdown),
	}
}

func copyMultiMsgAttribute(attr *sarif.MultiformatMessageString) *sarif.MultiformatMessageString {
	if attr == nil {
		return nil
	}
	return &sarif.MultiformatMessageString{
		Text:     copyStrAttribute(attr.Text),
		Markdown: copyStrAttribute(attr.Markdown),
	}
}

func copyStrAttribute(attr *string) *string {
	if attr == nil {
		return nil
	}
	copy := *attr
	return &copy
}

func CopyLocation(location *sarif.Location) *sarif.Location {
	if location == nil {
		return nil
	}
	copied := sarif.NewLocation()
	copied.ID = 0
	if location.PhysicalLocation != nil {
		copied.PhysicalLocation = sarif.NewPhysicalLocation()
		if location.PhysicalLocation.ArtifactLocation != nil {
			copied.PhysicalLocation.WithArtifactLocation(sarif.NewArtifactLocation().WithIndex(0).WithURI(GetLocationFileName(location)))
			copied.PhysicalLocation.WithRegion(sarif.NewRegion().
				WithCharOffset(0).
				WithByteOffset(0).
				WithStartLine(GetLocationStartLine(location)).
				WithStartColumn(GetLocationStartColumn(location)).
				WithEndLine(GetLocationEndLine(location)).
				WithEndColumn(GetLocationEndColumn(location)))
			if snippet := GetLocationSnippetText(location); len(snippet) > 0 {
				copied.PhysicalLocation.Region.WithSnippet(sarif.NewArtifactContent().WithText(snippet))
			}
		}
	}
	copied.Properties = location.Properties
	for _, logicalLocation := range location.LogicalLocations {
		logicalCopy := sarif.NewLogicalLocation().WithProperties(logicalLocation.Properties)
		if logicalLocation.Name != nil {
			logicalCopy.WithName(*logicalLocation.Name)
		}
		if logicalLocation.FullyQualifiedName != nil {
			logicalCopy.WithFullyQualifiedName(*logicalLocation.FullyQualifiedName)
		}
		if logicalLocation.DecoratedName != nil {
			logicalCopy.WithDecoratedName(*logicalLocation.DecoratedName)
		}
		if logicalLocation.Kind != nil {
			logicalCopy.WithKind(*logicalLocation.Kind)
		}
		copied.LogicalLocations = append(copied.LogicalLocations, logicalCopy)
	}
	return copied
}

func AggregateMultipleRunsIntoSingle(runs []*sarif.Run, destination *sarif.Run) {
	if len(runs) == 0 {
		return
	}
	for _, run := range runs {
		if run == nil || len(run.Results) == 0 {
			continue
		}
		for _, rule := range GetRunRules(run) {
			if exists := GetRuleById(destination, GetRuleId(rule)); exists != nil {
				// If the rule already exists in the destination run, we can skip adding it again.
				continue
			}
			// Add the rule to the destination run.
			if destination.Tool.Driver != nil {
				destination.Tool.Driver.AddRule(rule)
			}
		}
		for _, result := range run.Results {
			destination.AddResult(result)
		}
		for _, invocation := range run.Invocations {
			destination.AddInvocation(invocation)
		}
	}
}

func GetLocationRelatedCodeFlowsFromResult(location *sarif.Location, result *sarif.Result) (codeFlows []*sarif.CodeFlow) {
	for _, codeFlow := range result.CodeFlows {
		for _, stackTrace := range codeFlow.ThreadFlows {
			// The threadFlow is reverse stack trace.
			// The last location is the location that it relates to.
			if isSameLocation(location, stackTrace.Locations[len(stackTrace.Locations)-1].Location) {
				codeFlows = append(codeFlows, codeFlow)
			}
		}
	}
	return
}

func isSameLocation(location *sarif.Location, other *sarif.Location) bool {
	if location == other {
		return true
	}
	return GetLocationId(location) == GetLocationId(other)
}

func GetLogicalLocation(kind string, location *sarif.Location) *sarif.LogicalLocation {
	if location == nil {
		return nil
	}
	// Search for a logical location that has the same kind as the location
	for _, logicalLocation := range location.LogicalLocations {
		if logicalLocation.Kind != nil && *logicalLocation.Kind == kind {
			return logicalLocation
		}
	}
	return nil
}

func GetLocationId(location *sarif.Location) string {
	return fmt.Sprintf("%s:%s:%d:%d:%d:%d",
		GetLocationFileName(location),
		GetLocationSnippetText(location),
		GetLocationStartLine(location),
		GetLocationStartColumn(location),
		GetLocationEndLine(location),
		GetLocationEndColumn(location),
	)
}

func SetRunToolName(toolName string, run *sarif.Run) {
	if run.Tool.Driver == nil {
		run.Tool.Driver = &sarif.ToolComponent{}
	}
	run.Tool.Driver.Name = &toolName
}

func GetRunToolName(run *sarif.Run) string {
	if run != nil && run.Tool != nil && run.Tool.Driver != nil && run.Tool.Driver.Name != nil {
		return *run.Tool.Driver.Name
	}
	return ""
}

func SetRunToolFullDescriptionText(txt string, run *sarif.Run) {
	if run.Tool.Driver == nil {
		run.Tool.Driver = &sarif.ToolComponent{}
	}
	if run.Tool.Driver.FullDescription == nil {
		run.Tool.Driver.FullDescription = sarif.NewMultiformatMessageString().WithText(txt)
		return
	}
	run.Tool.Driver.FullDescription.Text = &txt
}

func SetRunToolFullDescriptionMarkdown(markdown string, run *sarif.Run) {
	if run.Tool.Driver == nil {
		run.Tool.Driver = &sarif.ToolComponent{}
	}
	if run.Tool.Driver.FullDescription == nil {
		run.Tool.Driver.FullDescription = sarif.NewMultiformatMessageString().WithMarkdown(markdown)
	}
	run.Tool.Driver.FullDescription.Markdown = &markdown
}

func GetRunToolFullDescriptionText(run *sarif.Run) string {
	if run.Tool.Driver != nil && run.Tool.Driver.FullDescription != nil && run.Tool.Driver.FullDescription.Text != nil {
		return *run.Tool.Driver.FullDescription.Text
	}
	return ""
}

func GetRunToolFullDescriptionMarkdown(run *sarif.Run) string {
	if run.Tool.Driver != nil && run.Tool.Driver.FullDescription != nil && run.Tool.Driver.FullDescription.Markdown != nil {
		return *run.Tool.Driver.FullDescription.Markdown
	}
	return ""
}

func GetResultsLocationCount(runs ...*sarif.Run) (count int) {
	for _, run := range runs {
		for _, result := range run.Results {
			count += len(result.Locations)
		}
	}
	return
}

func GetRunsByWorkingDirectory(workingDirectory string, runs ...*sarif.Run) (filteredRuns []*sarif.Run) {
	for _, run := range runs {
		for _, invocation := range run.Invocations {
			runWorkingDir := GetInvocationWorkingDirectory(invocation)
			if runWorkingDir == workingDirectory {
				filteredRuns = append(filteredRuns, run)
				break
			}
		}
	}
	return
}

func SetResultMsgMarkdown(markdown string, result *sarif.Result) {
	result.Message.Markdown = &markdown
}

func GetResultMsgMarkdown(result *sarif.Result) string {
	if result != nil && result.Message.Markdown != nil {
		return *result.Message.Markdown
	}
	return ""
}

func GetResultMsgText(result *sarif.Result) string {
	if result != nil && result.Message != nil && result.Message.Text != nil {
		return *result.Message.Text
	}
	return ""
}

func GetResultRuleId(result *sarif.Result) string {
	if result.RuleID != nil {
		return *result.RuleID
	}
	return ""
}

func GetResultProperty(key string, result *sarif.Result) (value string) {
	if result == nil || result.Properties == nil || result.Properties.Properties == nil {
		return
	}
	if _, exists := result.Properties.Properties[key]; !exists {
		return
	}
	if value, ok := result.Properties.Properties[key].(string); ok {
		return value
	}
	return
}

func IsFingerprintsExists(result *sarif.Result) bool {
	return len(result.Fingerprints) > 0
}

func SetResultFingerprint(algorithm, value string, result *sarif.Result) {
	if result.Fingerprints == nil {
		result.Fingerprints = make(map[string]string)
	}
	result.Fingerprints[algorithm] = value
}

func GetResultLocationSnippets(result *sarif.Result) []string {
	var snippets []string
	for _, location := range result.Locations {
		if snippet := GetLocationSnippetText(location); snippet != "" {
			snippets = append(snippets, snippet)
		}
	}
	return snippets
}

func GetLocationSnippetText(location *sarif.Location) string {
	snippetContent := GetLocationSnippet(location)
	if snippetContent != nil && snippetContent.Text != nil {
		return *snippetContent.Text
	}
	return ""
}

func GetLocationSnippet(location *sarif.Location) *sarif.ArtifactContent {
	region := getLocationRegion(location)
	if region != nil && region.Snippet != nil {
		return region.Snippet
	}
	return nil
}

func SetLocationSnippet(location *sarif.Location, snippet string) {
	if location != nil && location.PhysicalLocation != nil && location.PhysicalLocation.Region != nil && location.PhysicalLocation.Region.Snippet != nil {
		location.PhysicalLocation.Region.Snippet.Text = &snippet
	}
}

func GetLocationFileName(location *sarif.Location) string {
	if location != nil && location.PhysicalLocation != nil && location.PhysicalLocation.ArtifactLocation != nil && location.PhysicalLocation.ArtifactLocation.URI != nil {
		return *location.PhysicalLocation.ArtifactLocation.URI
	}
	return ""
}

func GetResultFileLocations(result *sarif.Result) []string {
	var locations []string
	for _, location := range result.Locations {
		locations = append(locations, GetLocationFileName(location))
	}
	return locations
}

func ConvertRunsPathsToRelative(runs ...*sarif.Run) {
	for _, run := range runs {
		for _, result := range run.Results {
			for _, location := range result.Locations {
				SetLocationFileName(location, GetRelativeLocationFileName(location, run.Invocations))
			}
			for _, flows := range result.CodeFlows {
				for _, flow := range flows.ThreadFlows {
					for _, location := range flow.Locations {
						SetLocationFileName(location.Location, GetRelativeLocationFileName(location.Location, run.Invocations))
					}
				}
			}
		}
	}
}

func GetRelativeLocationFileName(location *sarif.Location, invocations []*sarif.Invocation) string {
	wd := ""
	if len(invocations) > 0 {
		wd = GetInvocationWorkingDirectory(invocations[0])
	}
	filePath := GetLocationFileName(location)
	if filePath != "" {
		return ExtractRelativePath(filePath, wd)
	}
	return ""
}

func GetFullLocationFileName(relative string, invocations []*sarif.Invocation) string {
	if len(invocations) == 0 {
		return relative
	}
	return filepath.Join(GetInvocationWorkingDirectory(invocations[0]), relative)
}

func SetLocationFileName(location *sarif.Location, fileName string) {
	if location != nil && location.PhysicalLocation != nil && location.PhysicalLocation.ArtifactLocation != nil {
		location.PhysicalLocation.ArtifactLocation.URI = &fileName
	}
}

func getLocationRegion(location *sarif.Location) *sarif.Region {
	if location != nil && location.PhysicalLocation != nil {
		return location.PhysicalLocation.Region
	}
	return nil
}

func GetLocationStartLine(location *sarif.Location) int {
	region := getLocationRegion(location)
	if region != nil && region.StartLine != nil {
		return *region.StartLine
	}
	// Default start line is 1
	return 1
}

func GetLocationStartColumn(location *sarif.Location) int {
	region := getLocationRegion(location)
	if region != nil && region.StartColumn != nil {
		return *region.StartColumn
	}
	// Default start column is 1
	return 1
}

func GetLocationEndLine(location *sarif.Location) int {
	region := getLocationRegion(location)
	if region != nil && region.EndLine != nil {
		return *region.EndLine
	}
	// Default end line is 1
	return 1
}

func GetLocationEndColumn(location *sarif.Location) int {
	region := getLocationRegion(location)
	if region != nil && region.EndColumn != nil {
		return *region.EndColumn
	}
	// Default end column is 1
	return 1
}

func ExtractRelativePath(resultPath string, projectRoot string) string {
	relPath, err := filepath.Rel(projectRoot, resultPath)
	if err != nil {
		return resultPath
	}
	return relPath
}

func GetRuleById(run *sarif.Run, ruleId string) *sarif.ReportingDescriptor {
	for _, rule := range GetRunRules(run) {
		if GetRuleId(rule) == ruleId {
			return rule
		}
	}
	return nil
}

func GetRuleId(rule *sarif.ReportingDescriptor) string {
	if rule != nil && rule.ID != nil {
		return *rule.ID
	}
	return ""
}

func GetRuleFullDescription(rule *sarif.ReportingDescriptor) string {
	if rule != nil && rule.FullDescription != nil && rule.FullDescription.Text != nil {
		return *rule.FullDescription.Text
	}
	return ""
}

func GetRuleFullDescriptionMarkdown(rule *sarif.ReportingDescriptor) string {
	if rule.FullDescription != nil && rule.FullDescription.Markdown != nil {
		return *rule.FullDescription.Markdown
	}
	return ""

}

func GetRuleHelp(rule *sarif.ReportingDescriptor) string {
	if rule.Help != nil && rule.Help.Text != nil {
		return *rule.Help.Text
	}
	return ""
}

func GetRuleHelpMarkdown(rule *sarif.ReportingDescriptor) string {
	if rule.Help != nil && rule.Help.Markdown != nil {
		return *rule.Help.Markdown
	}
	return ""
}

func GetRuleShortDescription(rule *sarif.ReportingDescriptor) string {
	if rule != nil && rule.ShortDescription != nil && rule.ShortDescription.Text != nil {
		return *rule.ShortDescription.Text
	}
	return ""
}

func GetRuleFullDescriptionText(rule *sarif.ReportingDescriptor) string {
	if rule.FullDescription != nil && rule.FullDescription.Text != nil {
		return *rule.FullDescription.Text
	}
	return ""
}

func SetRuleShortDescriptionText(value string, rule *sarif.ReportingDescriptor) {
	if rule.ShortDescription == nil {
		rule.ShortDescription = sarif.NewMultiformatMessageString().WithText(value)
		return
	}
	rule.ShortDescription.Text = &value
}

func SetRuleHelp(msg, markdown string, rule *sarif.ReportingDescriptor) {
	if rule.Help == nil {
		rule.Help = &sarif.MultiformatMessageString{
			Text:     &msg,
			Markdown: &markdown,
		}
		return
	}
	rule.Help.Markdown = &markdown
	rule.Help.Text = &msg
}

func SetRuleFullDescription(msg, markdown string, rule *sarif.ReportingDescriptor) {
	if rule.FullDescription == nil {
		rule.FullDescription = &sarif.MultiformatMessageString{
			Text:     &msg,
			Markdown: &markdown,
		}
		return
	}
	rule.FullDescription.Markdown = &markdown
	rule.FullDescription.Text = &msg
}

func GetRuleShortDescriptionText(rule *sarif.ReportingDescriptor) string {
	if rule.ShortDescription != nil && rule.ShortDescription.Text != nil {
		return *rule.ShortDescription.Text
	}
	return ""
}

func GetRuleProperty(key string, rule *sarif.ReportingDescriptor) string {
	if rule != nil && rule.Properties != nil && rule.Properties.Properties != nil && rule.Properties.Properties[key] != nil {
		prop, ok := rule.Properties.Properties[key].(string)
		if !ok {
			return ""
		}
		return prop
	}
	return ""
}

func GetRunRules(run *sarif.Run) []*sarif.ReportingDescriptor {
	if run != nil && run.Tool != nil && run.Tool.Driver != nil {
		return run.Tool.Driver.Rules
	}
	return []*sarif.ReportingDescriptor{}
}

func GetInvocationWorkingDirectory(invocation *sarif.Invocation) string {
	if invocation != nil && invocation.WorkingDirectory != nil && invocation.WorkingDirectory.URI != nil {
		return *invocation.WorkingDirectory.URI
	}
	return ""
}

func GetRulesPropertyCount(property, value string, runs ...*sarif.Run) (count int) {
	for _, run := range runs {
		for _, rule := range run.Tool.Driver.Rules {
			if rule.Properties != nil && rule.Properties.Properties[property] != nil && rule.Properties.Properties[property] == value {
				count += 1
			}
		}
	}
	return
}

func GetResultFingerprint(result *sarif.Result) string {
	if result.Fingerprints != nil {
		return result.Fingerprints[jasutils.SastFingerprintKey]
	}
	return ""
}

func GetResultsByRuleId(ruleId string, runs ...*sarif.Run) (results []*sarif.Result) {
	for _, run := range runs {
		for _, result := range run.Results {
			if GetResultRuleId(result) == ruleId {
				results = append(results, result)
			}
		}
	}
	return
}
