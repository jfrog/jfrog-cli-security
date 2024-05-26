package utils

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/commandsummary"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"
)

const (
	Build   SecuritySummarySection = "Builds"
	Binary  SecuritySummarySection = "Artifacts"
	Modules SecuritySummarySection = "Modules"
)

type SecuritySummarySection string

type ScanCommandSummaryResult struct {
	Section         SecuritySummarySection `json:"section"`
	Results         formats.SummaryResults `json:"results"`
}

type SecurityCommandsSummary struct {
	BuildScanCommands []formats.SummaryResults `json:"buildScanCommands"`
	ScanCommands      []formats.SummaryResults `json:"scanCommands"`
	AuditCommands     []formats.SummaryResults `json:"auditCommands"`
}

// Manage the job summary for security commands
func SecurityCommandsJobSummary() (js *commandsummary.CommandSummary, err error) {
	return commandsummary.New(&SecurityCommandsSummary{}, "security")
}

// Record the security command output
func RecordSecurityCommandOutput(content ScanCommandSummaryResult) (err error) {
	if !commandsummary.ShouldRecordSummary() {
		return
	}
	manager, err := SecurityCommandsJobSummary()
	if err != nil || manager == nil {
		return
	}
	return manager.Record(content)
}

func (scs *SecurityCommandsSummary) GenerateMarkdownFromFiles(dataFilePaths []string) (markdown string, err error) {
	if err = loadContentFromFiles(dataFilePaths, scs); err != nil {
		return "", fmt.Errorf("failed while creating security markdown: %w", err)
	}
	return ConvertSummaryToString(*scs)
}

func loadContentFromFiles(dataFilePaths []string, scs *SecurityCommandsSummary) (err error) {
	for _, dataFilePath := range dataFilePaths {
		// Load file content
		var cmdResults ScanCommandSummaryResult
		if err = commandsummary.UnmarshalFromFilePath(dataFilePath, &cmdResults); err != nil {
			return fmt.Errorf("failed while Unmarshal '%s': %w", dataFilePath, err)
		}
		// Append the new data
		switch cmdResults.Section {
		case Build:
			scs.BuildScanCommands = append(scs.BuildScanCommands, cmdResults.Results)
		case Binary:
			scs.ScanCommands = append(scs.ScanCommands, cmdResults.Results)
		case Modules:
			scs.AuditCommands = append(scs.AuditCommands, cmdResults.Results)
		}
	}
	return
}

func (scs *SecurityCommandsSummary) GetOrderedSectionsWithContent() (sections []SecuritySummarySection) {
	if len(scs.BuildScanCommands) > 0 {
		sections = append(sections, Build)
	}
	if len(scs.ScanCommands) > 0 {
		sections = append(sections, Binary)
	}
	if len(scs.AuditCommands) > 0 {
		sections = append(sections, Modules)
	}
	return

}

func (scs *SecurityCommandsSummary) GetSectionSummaries(section SecuritySummarySection) (summaries []formats.SummaryResults) {
	switch section {
	case Build:
		summaries = scs.BuildScanCommands
	case Binary:
		summaries = scs.ScanCommands
	case Modules:
		summaries = scs.AuditCommands
	}
	return
}

func ConvertSummaryToString(results SecurityCommandsSummary) (summary string, err error) {
	sectionsWithContent := results.GetOrderedSectionsWithContent()
	addSectionTitle := len(sectionsWithContent) > 1
	var sectionSummary string
	for i, section := range sectionsWithContent {
		if sectionSummary, err = GetSummaryString(results.GetSectionSummaries(section)...); err != nil {
			return
		}
		if addSectionTitle {
			if i > 0 {
				summary += "\n"
			}
			summary += fmt.Sprintf("#### %s\n", section)
		}
		summary += sectionSummary
	}
	return
}

func GetSummaryString(summaries ...formats.SummaryResults) (str string, err error) {
	parsed := 0
	singleScan := isSingleCommandAndScan(summaries...)
	wd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	if !singleScan {
		str += "| Status | Id | Details |\n|--------|----|---------|\n"
	}
	for i := range summaries {
		if !singleScan {
			updateSummaryNamesToRelativePath(&summaries[i], wd)
		}
		for _, scan := range summaries[i].Scans {
			if parsed > 0 {
				str += "\n"
			}
			str += GetScanSummaryString(scan, singleScan)
			parsed++
		}
	}
	return
}

func isSingleCommandAndScan(summaries ...formats.SummaryResults) bool {
	if len(summaries) != 1 {
		return false
	}
	if len(summaries[0].Scans) != 1 {
		return false
	}
	// One command and one scan
	return true
}

func GetScanSummaryString(summary formats.ScanSummaryResult, singleData bool) (content string) {
	// single data -> no table
	hasIssues := summary.HasIssues()
	if !hasIssues {
		if singleData {
			return "```\n✅ No issues were found\n```"
		}
		return fmt.Sprintf("| ✅ | %s |  |", summary.Target)
	}
	issueDetails := getDetailsString(summary)
	if singleData {
		return fmt.Sprintf("<pre>❌ %s</pre>", issueDetails)
	}
	return fmt.Sprintf("| ❌ | %s | <pre>%s</pre> |", summary.Target, issueDetails)
}

func getDetailsString(summary formats.ScanSummaryResult) (content string) {
	content = getMainSummaryString(summary)
	// Display sub scans with issues
	subScansWithIssues := summary.GetSubScansWithIssues()
	for i, subScanType := range subScansWithIssues {
		content += fmt.Sprintf("<br>%s", getListItemPrefix(i, len(subScansWithIssues)))
		subScanPrefix := fmt.Sprintf("%d ", summary.GetSubScanTotalIssueCount(subScanType))
		switch subScanType {
		case formats.ScaScan:
			subScanPrefix += "SCA "
		case formats.IacScan:
			subScanPrefix += "IAC "
		case formats.SecretsScan:
			subScanPrefix += "Secrets "
		case formats.SastScan:
			subScanPrefix += "SAST "
		}
		content += subScanPrefix + getSubScanSummaryCountsString(summary, subScanType, getPrefixPadding(subScanPrefix))
	}
	return
}

func getMainSummaryString(summary formats.ScanSummaryResult) (content string) {
	vulnerabilityCount := summary.GetTotalIssueCount()
	violationCount := 0
	if summary.ScaScanResults != nil {
		// Violations only relevant for SCA (XRAY) scans
		violationCount = summary.ScaScanResults.ViolationSummary.GetTotal()
	}
	if violationCount > 0 {
		content += fmt.Sprintf("%d violation", violationCount)
		if vulnerabilityCount > 0 {
			content += " found, "
		}
	}
	if vulnerabilityCount > 0 {
		content += fmt.Sprintf("%d unique vulnerabilities", vulnerabilityCount)
		if violationCount == 0 {
			content += " found"
		}
	}
	return
}

func getPrefixPadding(prefix string) int {
	// 4 spaces for the list item prefix (len not equal to actual length)
	return 4 + len(prefix)
}

func getListItemPrefix(index, total int) (content string) {
	if index == total-1 {
		content += "└── "
		return
	}
	content += "├── "
	return
}

func getSubScanSummaryCountsString(summary formats.ScanSummaryResult, subScanType formats.SummarySubScanType, padding int) (content string) {
	switch subScanType {
	case formats.ScaScan:
		content += GetScaSummaryCountString(summary.ScaScanResults.GetIssuesCount(), padding)
	case formats.IacScan:
		content += GetSeveritySummaryCountString(*summary.IacScanResults, padding)
	case formats.SecretsScan:
		content += GetSeveritySummaryCountString(*summary.SecretsScanResults, padding)
	case formats.SastScan:
		content += GetSeveritySummaryCountString(*summary.SastScanResults, padding)
	}
	return
}

func hasApplicableDataToDisplayInSummary(summary formats.ScaSummaryCount) bool {
	for _, statuses := range summary {
		sorted := getSummarySortedKeysToDisplay(maps.Keys(statuses)...)
		for _, status := range sorted {
			if _, ok := statuses[status]; ok && statuses[status] > 0 {
				return true
			}
		}
	}
	return false
}

func GetScaSummaryCountString(summary formats.ScaSummaryCount, padding int) (content string) {
	if summary.GetTotal() == 0 {
		return
	}
	if !hasApplicableDataToDisplayInSummary(summary) {
		return GetSeveritySummaryCountString(summary.GetSeverityCountsWithoutStatus(), padding)
	}
	// Display contextual-analysis details
	keys := getSummarySortedKeysToDisplay(maps.Keys(summary)...)
	for i, severity := range keys {
		if i > 0 {
			content += "<br>" + strings.Repeat(" ", padding)
		}
		statusCounts := summary[severity]
		content += fmt.Sprintf("%s%s",
			fmt.Sprintf(summaryContentToFormatString[severity], statusCounts.GetTotal()),
			GetSummaryContentString(statusCounts, ", ", true),
		)
	}
	return
}

var summaryContentToFormatString = map[string]string{
	"Critical":            `❗️ <span style="color:red">%d Critical</span>`,
	"High":                `🔴 <span style="color:red">%d High</span>`,
	"Medium":              `🟠 <span style="color:orange">%d Medium</span>`,
	"Low":                 `🟡 <span style="color:yellow">%d Low</span>`,
	"Unknown":             `⚪️ <span style="color:white">%d Unknown</span>`,
	string(Applicable):    "%d " + string(Applicable),
	string(NotApplicable): "%d " + string(NotApplicable),
}

func getSummarySortedKeysToDisplay(keys ...string) (sorted []string) {
	if len(keys) == 0 {
		return
	}
	keysSet := datastructures.MakeSetFromElements(keys...)
	allowedSorted := []string{
		"Critical", "High", "Medium", "Low", "Unknown",
		string(Applicable), string(NotApplicable),
	}
	for _, key := range allowedSorted {
		if keysSet.Exists(key) {
			sorted = append(sorted, key)
		}
	}
	return
}

func GetSeveritySummaryCountString(summary formats.SummaryCount, padding int) (content string) {
	return GetSummaryContentString(summary, "<br>"+strings.Repeat(" ", padding), false)
}

func GetSummaryContentString(summary formats.SummaryCount, delimiter string, wrap bool) (content string) {
	// sort and filter
	keys := getSummarySortedKeysToDisplay(maps.Keys(summary)...)
	if len(keys) == 0 {
		return
	}
	for i, key := range keys {
		if i > 0 {
			content += delimiter
		}
		content += fmt.Sprintf(summaryContentToFormatString[key], summary[key])
	}
	if wrap {
		content = fmt.Sprintf(" (%s)", content)
	}
	return
}

func updateSummaryNamesToRelativePath(summary *formats.SummaryResults, wd string) {
	for i, scan := range summary.Scans {
		if scan.Target == "" {
			continue
		}
		if !strings.HasPrefix(scan.Target, wd) {
			continue
		}
		if scan.Target == wd {
			summary.Scans[i].Target = filepath.Base(wd)
		}
		summary.Scans[i].Target = strings.TrimPrefix(scan.Target, wd)
	}
}

func getScanSummary(extendedScanResults *ExtendedScanResults, scaResults ...ScaScanResult) (summary formats.ScanSummaryResult) {
	if len(scaResults) == 1 {
		summary.Target = scaResults[0].Target
	}
	if extendedScanResults == nil {
		summary.ScaScanResults = getScaSummaryResults(&scaResults)
		return
	}
	summary.ScaScanResults = getScaSummaryResults(&scaResults, extendedScanResults.ApplicabilityScanResults...)
	summary.IacScanResults = getJASSummaryCount(extendedScanResults.IacScanResults...)
	summary.SecretsScanResults = getJASSummaryCount(extendedScanResults.SecretsScanResults...)
	summary.SastScanResults = getJASSummaryCount(extendedScanResults.SastScanResults...)
	return
}

type SeverityWithApplicable struct {
	SeverityInfo        *TableSeverity
	ApplicabilityStatus ApplicabilityStatus
}

func getCveId(cve services.Cve, defaultIssueId string) string {
	if cve.Id == "" {
		return defaultIssueId
	}
	return cve.Id
}

func getUniqueVulnerabilitiesInfo(cves []services.Cve, issueId, severity string, components map[string]services.Component, applicableRuns ...*sarif.Run) (uniqueFindings map[string]SeverityWithApplicable) {
	uniqueFindings = map[string]SeverityWithApplicable{}
	for _, cve := range cves {
		cveId := getCveId(cve, issueId)
		for compId := range components {
			applicableStatus := NotScanned
			if applicableInfo := getCveApplicabilityField(cveId, applicableRuns, components); applicableInfo != nil {
				applicableStatus = convertToApplicabilityStatus(applicableInfo.Status)
			}
			uniqueFindings[cveId+compId] = SeverityWithApplicable{SeverityInfo: GetSeverity(severity, applicableStatus), ApplicabilityStatus: applicableStatus}
		}
	}
	return
}

func getScaSummaryResults(scaScanResults *[]ScaScanResult, applicableRuns ...*sarif.Run) *formats.ScaScanSummaryResult {
	vulUniqueFindings := map[string]SeverityWithApplicable{}
	vioUniqueFindings := map[string]SeverityWithApplicable{}
	if len(*scaScanResults) == 0 {
		return nil
	}
	// Aggregate unique findings
	for _, scaResult := range *scaScanResults {
		for _, xrayResult := range scaResult.XrayResults {
			for _, vulnerability := range xrayResult.Vulnerabilities {
				vulUniqueFinding := getUniqueVulnerabilitiesInfo(vulnerability.Cves, vulnerability.IssueId, vulnerability.Severity, vulnerability.Components, applicableRuns...)
				for key, value := range vulUniqueFinding {
					vulUniqueFindings[key] = value
				}
			}
			for _, violation := range xrayResult.Violations {
				vioUniqueFinding := getUniqueVulnerabilitiesInfo(violation.Cves, violation.IssueId, violation.Severity, violation.Components, applicableRuns...)
				for key, value := range vioUniqueFinding {
					vioUniqueFindings[key] = value
				}
			}
		}
	}
	// Create summary
	return &formats.ScaScanSummaryResult{
		VulnerabilitiesSummary: toScaSummaryCount(vulUniqueFindings),
		ViolationSummary:       toScaSummaryCount(vioUniqueFindings),
	}
}

func toScaSummaryCount(uniqueFindings map[string]SeverityWithApplicable) formats.ScaSummaryCount {
	summary := formats.ScaSummaryCount{}
	for _, severityWithApplicable := range uniqueFindings {
		severity := severityWithApplicable.SeverityInfo.Severity
		status := severityWithApplicable.ApplicabilityStatus.String()
		if _, ok := summary[severity]; !ok {
			summary[severity] = formats.SummaryCount{}
		}
		summary[severity][status]++
	}
	return summary
}

func getJASSummaryCount(runs ...*sarif.Run) *formats.SummaryCount {
	if len(runs) == 0 {
		return nil
	}
	count := formats.SummaryCount{}
	issueToSeverity := map[string]string{}
	for _, run := range runs {
		for _, result := range run.Results {
			for _, location := range result.Locations {
				issueToSeverity[GetLocationId(location)] = GetResultSeverity(result)
			}
		}
	}
	for _, severity := range issueToSeverity {
		count[severity]++
	}
	return &count
}
