package sarifutils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

func NewReport() (*sarif.Report, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	return report, nil
}

func CombineReports(reports ...*sarif.Report) (combined *sarif.Report, err error) {
	if combined, err = NewReport(); err != nil {
		return
	}
	for _, report := range reports {
		for _, run := range report.Runs {
			combined.AddRun(run)
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

func CopyRunMetadata(run *sarif.Run) (copied *sarif.Run) {
	if run == nil {
		return
	}
	copied = sarif.NewRun(*sarif.NewTool(sarif.NewDriver(GetRunToolName(run)))).WithInvocations(run.Invocations)

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
	if language := getRunLanguage(run); language != "" {
		copied.Language = &language
	}
	if informationURI := GetRunToolInformationURI(run); informationURI != "" {
		copied.Tool.Driver.InformationURI = &informationURI
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

func getRunLanguage(run *sarif.Run) string {
	if run.Language != nil {
		return *run.Language
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
		ArtifactLocation: &sarif.ArtifactLocation{
			URI: &physicalPath,
		},
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
		CodeFlows:    result.CodeFlows,
		Level:        result.Level,
		Message:      result.Message,
		PropertyBag:  result.PropertyBag,
	}
	for _, location := range result.Locations {
		copied.Locations = append(copied.Locations, CopyLocation(location))
	}
	return copied
}

func copyStrAttribute(attr *string) *string {
	if attr == nil {
		return nil
	}
	copy := *attr
	return &copy
}

func copyIntAttribute(attr *int) *int {
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
	if location.PhysicalLocation != nil {
		copied.PhysicalLocation = &sarif.PhysicalLocation{}
		if location.PhysicalLocation.ArtifactLocation != nil {
			copied.PhysicalLocation.ArtifactLocation = &sarif.ArtifactLocation{
				URI: copyStrAttribute(location.PhysicalLocation.ArtifactLocation.URI),
			}
		}
		if location.PhysicalLocation.Region != nil {
			copied.PhysicalLocation.Region = &sarif.Region{
				StartLine:   copyIntAttribute(location.PhysicalLocation.Region.StartLine),
				StartColumn: copyIntAttribute(location.PhysicalLocation.Region.StartColumn),
				EndLine:     copyIntAttribute(location.PhysicalLocation.Region.EndLine),
				EndColumn:   copyIntAttribute(location.PhysicalLocation.Region.EndColumn),
			}
			if location.PhysicalLocation.Region.Snippet != nil {
				copied.PhysicalLocation.Region.Snippet = &sarif.ArtifactContent{
					Text: copyStrAttribute(location.PhysicalLocation.Region.Snippet.Text),
				}
			}
		}
	}
	copied.Properties = location.Properties
	for _, logicalLocation := range location.LogicalLocations {
		copied.LogicalLocations = append(copied.LogicalLocations, &sarif.LogicalLocation{
			Name:               logicalLocation.Name,
			FullyQualifiedName: logicalLocation.FullyQualifiedName,
			DecoratedName:      logicalLocation.DecoratedName,
			Kind:               logicalLocation.Kind,
			PropertyBag:        logicalLocation.PropertyBag,
		})
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
			if destination.Tool.Driver != nil {
				destination.Tool.Driver.AddRule(rule)
			}
		}
		for _, result := range run.Results {
			destination.AddResult(result)
		}
		for _, invocation := range run.Invocations {
			destination.AddInvocations(invocation)
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
	run.Tool.Driver.Name = toolName
}

func GetRunToolName(run *sarif.Run) string {
	if run.Tool.Driver != nil {
		return run.Tool.Driver.Name
	}
	return ""
}

func SetRunToolFullDescriptionText(txt string, run *sarif.Run) {
	if run.Tool.Driver == nil {
		run.Tool.Driver = &sarif.ToolComponent{}
	}
	if run.Tool.Driver.FullDescription == nil {
		run.Tool.Driver.FullDescription = sarif.NewMultiformatMessageString(txt)
		return
	}
	run.Tool.Driver.FullDescription.Text = &txt
}

func SetRunToolFullDescriptionMarkdown(markdown string, run *sarif.Run) {
	if run.Tool.Driver == nil {
		run.Tool.Driver = &sarif.ToolComponent{}
	}
	if run.Tool.Driver.FullDescription == nil {
		run.Tool.Driver.FullDescription = sarif.NewMarkdownMultiformatMessageString(markdown)
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

func GetRunsByToolName(report *sarif.Report, toolName string) (filteredRuns []*sarif.Run) {
	for _, run := range report.Runs {
		if run.Tool.Driver != nil && run.Tool.Driver.Name == toolName {
			filteredRuns = append(filteredRuns, run)
		}
	}
	return
}

func SetResultMsgMarkdown(markdown string, result *sarif.Result) {
	result.Message.Markdown = &markdown
}

func GetResultMsgText(result *sarif.Result) string {
	if result.Message.Text != nil {
		return *result.Message.Text
	}
	return ""
}

func GetResultLevel(result *sarif.Result) string {
	if result.Level != nil {
		return *result.Level
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
	if result == nil || result.Properties == nil {
		return
	}
	if _, exists := result.Properties[key]; !exists {
		return
	}
	if value, ok := result.Properties[key].(string); ok {
		return value
	}
	return
}

func IsFingerprintsExists(result *sarif.Result) bool {
	return len(result.Fingerprints) > 0
}

func SetResultFingerprint(algorithm, value string, result *sarif.Result) {
	if result.Fingerprints == nil {
		result.Fingerprints = make(map[string]interface{})
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
	return 0
}

func GetLocationStartColumn(location *sarif.Location) int {
	region := getLocationRegion(location)
	if region != nil && region.StartColumn != nil {
		return *region.StartColumn
	}
	return 0
}

func GetLocationEndLine(location *sarif.Location) int {
	region := getLocationRegion(location)
	if region != nil && region.EndLine != nil {
		return *region.EndLine
	}
	return 0
}

func GetLocationEndColumn(location *sarif.Location) int {
	region := getLocationRegion(location)
	if region != nil && region.EndColumn != nil {
		return *region.EndColumn
	}
	return 0
}

func ExtractRelativePath(resultPath string, projectRoot string) string {
	// Remove OS-specific file prefix
	resultPath = strings.TrimPrefix(resultPath, "file:///private")
	resultPath = strings.TrimPrefix(resultPath, "file://")

	// Get relative path
	relativePath := strings.ReplaceAll(resultPath, projectRoot, "")
	trimSlash := strings.TrimPrefix(relativePath, string(filepath.Separator))
	return strings.TrimPrefix(trimSlash, "/")
}

func IsResultKindNotPass(result *sarif.Result) bool {
	return !(result.Kind != nil && *result.Kind == "pass")
}

func GetRuleById(run *sarif.Run, ruleId string) *sarif.ReportingDescriptor {
	for _, rule := range GetRunRules(run) {
		if rule.ID == ruleId {
			return rule
		}
	}
	return nil
}

func GetRuleFullDescription(rule *sarif.ReportingDescriptor) string {
	if rule.FullDescription != nil && rule.FullDescription.Text != nil {
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
	if rule.ShortDescription != nil && rule.ShortDescription.Text != nil {
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
		rule.ShortDescription = sarif.NewMultiformatMessageString(value)
		return
	}
	rule.ShortDescription.Text = &value
}

func GetRuleShortDescriptionText(rule *sarif.ReportingDescriptor) string {
	if rule.ShortDescription != nil && rule.ShortDescription.Text != nil {
		return *rule.ShortDescription.Text
	}
	return ""
}

func GetRuleProperty(key string, rule *sarif.ReportingDescriptor) string {
	if rule != nil && rule.Properties != nil && rule.Properties[key] != nil {
		prop, ok := rule.Properties[key].(string)
		if !ok {
			return ""
		}
		return prop
	}
	return ""
}

func GetRunRules(run *sarif.Run) []*sarif.ReportingDescriptor {
	if run != nil && run.Tool.Driver != nil {
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
			if rule.Properties[property] != nil && rule.Properties[property] == value {
				count += 1
			}
		}
	}
	return
}

func GetResultFingerprint(result *sarif.Result) string {
	if result.Fingerprints != nil {
		if value, ok := result.Fingerprints[jasutils.SastFingerprintKey].(string); ok {
			return value
		}
	}
	return ""
}
