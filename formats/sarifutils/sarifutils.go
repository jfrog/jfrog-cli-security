package sarifutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils"
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

func ConvertSarifReportToString(report *sarif.Report) (sarifStr string, err error) {
	out, err := json.Marshal(report)
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	return utils.IndentJson(out), nil
}

func ReadScanRunsFromFile(fileName string) (sarifRuns []*sarif.Run, err error) {
	report, err := sarif.Open(fileName)
	if errorutils.CheckError(err) != nil {
		err = errors.New("can't read valid Sarif run from " + fileName + ": " + err.Error())
		return
	}
	sarifRuns = report.Runs
	return
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

func GetLocationId(location *sarif.Location) string {
	return fmt.Sprintf("%s:%s:%d:%d:%d:%d",
		GetLocationFileName(location),
		GetLocationSnippet(location),
		GetLocationStartLine(location),
		GetLocationStartColumn(location),
		GetLocationEndLine(location),
		GetLocationEndColumn(location),
	)
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

func GetLocationSnippet(location *sarif.Location) string {
	region := getLocationRegion(location)
	if region != nil && region.Snippet != nil {
		return *region.Snippet.Text
	}
	return ""
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

func GetRuleFullDescription(rule *sarif.ReportingDescriptor) string {
	if rule.FullDescription != nil && rule.FullDescription.Text != nil {
		return *rule.FullDescription.Text
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
