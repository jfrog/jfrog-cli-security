package utils

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/commandsummary"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"
)

const (
	Build    SecuritySummarySection = "Builds"
	Binary   SecuritySummarySection = "Artifacts"
	Modules  SecuritySummarySection = "Modules"
	Curation SecuritySummarySection = "Curation"
)

type SecuritySummarySection string

type ScanCommandSummaryResult struct {
	Section          SecuritySummarySection `json:"section"`
	WorkingDirectory string                 `json:"workingDirectory"`
	Results          formats.SummaryResults `json:"results"`
}

type SecurityCommandsSummary struct {
	BuildScanCommands []formats.SummaryResults `json:"buildScanCommands"`
	ScanCommands      []formats.SummaryResults `json:"scanCommands"`
	AuditCommands     []formats.SummaryResults `json:"auditCommands"`
	CurationCommands  []formats.SummaryResults `json:"curationCommands"`
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
	wd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	content.WorkingDirectory = wd
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
		results := cmdResults.Results
		// Update the working directory
		updateSummaryNamesToRelativePath(&results, cmdResults.WorkingDirectory)
		// Append the new data
		switch cmdResults.Section {
		case Build:
			scs.BuildScanCommands = append(scs.BuildScanCommands, results)
		case Binary:
			scs.ScanCommands = append(scs.ScanCommands, results)
		case Modules:
			scs.AuditCommands = append(scs.AuditCommands, results)
		case Curation:
			scs.CurationCommands = append(scs.CurationCommands, results)
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
	if len(scs.CurationCommands) > 0 {
		sections = append(sections, Curation)
	}
	return

}

func (scs *SecurityCommandsSummary) getSectionSummaries(section SecuritySummarySection) (summaries []formats.SummaryResults) {
	switch section {
	case Build:
		summaries = scs.BuildScanCommands
	case Binary:
		summaries = scs.ScanCommands
	case Modules:
		summaries = scs.AuditCommands
	case Curation:
		summaries = scs.CurationCommands
	}
	return
}

func ConvertSummaryToString(results SecurityCommandsSummary) (summary string, err error) {
	sectionsWithContent := results.GetOrderedSectionsWithContent()
	addSectionTitle := len(sectionsWithContent) > 1
	var sectionSummary string
	for i, section := range sectionsWithContent {
		sectionSummary = getSummaryString(results.getSectionSummaries(section)...)
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

func getSummaryString(summaries ...formats.SummaryResults) (str string) {
	parsed := 0
	singleScan := isSingleCommandAndScan(summaries...)
	if !singleScan {
		str += "| Status | Id | Details |\n|--------|----|---------|\n"
	}
	for i := range summaries {
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
		return fmt.Sprintf("<pre>%s</pre>", issueDetails)
	}
	return fmt.Sprintf("| ❌ | %s | <pre>%s</pre> |", summary.Target, issueDetails)
}

func getDetailsString(summary formats.ScanSummaryResult) string {
	// If summary includes curation issues, then it means only curation issues are in this summary, no need to continue
	if summary.HasBlockedCuration() {
		return getBlockedCurationSummaryString(summary)
	}
	violationContent := getViolationSummaryString(summary)
	vulnerabilitiesContent := getVulnerabilitiesSummaryString(summary)
	delimiter := ""
	if len(violationContent) > 0 && len(vulnerabilitiesContent) > 0 {
		delimiter = "<br>"
	}
	return violationContent + delimiter + vulnerabilitiesContent
}

func getBlockedCurationSummaryString(summary formats.ScanSummaryResult) (content string) {
	if !summary.HasBlockedCuration() {
		return
	}
	content += fmt.Sprintf("Total Number of Packages: <b>%d</b>", summary.CuratedPackages.GetTotalPackages())
	content += fmt.Sprintf("<br>🟢 Total Number of Approved Packages: <b>%d</b>", summary.CuratedPackages.Approved)
	content += fmt.Sprintf("<br>🔴 Total Number of Blocked Packages: <b>%d</b>", summary.CuratedPackages.Blocked.GetCountOfKeys(false))
	if summary.CuratedPackages.Blocked.GetTotal() > 0 {
		var blocked []struct {
			BlockedName  string
			BlockedValue formats.SummaryCount
		}
		// Sort the blocked packages by name
		for blockTypeName, blockTypeValue := range summary.CuratedPackages.Blocked {
			blocked = append(blocked, struct {
				BlockedName  string
				BlockedValue formats.SummaryCount
			}{BlockedName: blockTypeName, BlockedValue: blockTypeValue})
		}
		sort.Slice(blocked, func(i, j int) bool {
			return blocked[i].BlockedName > blocked[j].BlockedName
		})
		// Display the blocked packages
		for index, blockStruct := range blocked {
			subScanPrefix := fmt.Sprintf("<br>%s", getListItemPrefix(index, len(blocked)))
			subScanPrefix += blockStruct.BlockedName
			content += fmt.Sprintf("%s (%d)", subScanPrefix, blockStruct.BlockedValue.GetTotal())
		}
	}
	return
}

func getViolationSummaryString(summary formats.ScanSummaryResult) (content string) {
	if !summary.HasViolations() {
		return
	}
	content += fmt.Sprintf("Violations: <b>%d</b> -", summary.GetTotalViolationCount())
	content += GetSummaryContentString(summary.Violations.GetCombinedLowerLevel(), ", ", true)
	return
}

func getVulnerabilitiesSummaryString(summary formats.ScanSummaryResult) (content string) {
	if !summary.HasSecurityVulnerabilities() {
		return
	}
	content += fmt.Sprintf("Security Vulnerabilities: <b>%d</b> (%d unique)", summary.Vulnerabilities.GetTotalIssueCount(), summary.Vulnerabilities.GetTotalUniqueIssueCount())
	// Display sub scans with issues
	subScansWithIssues := summary.Vulnerabilities.GetSubScansWithIssues()
	for i, subScanType := range subScansWithIssues {
		content += fmt.Sprintf("<br>%s", getListItemPrefix(i, len(subScansWithIssues)))
		subScanPrefix := fmt.Sprintf("%d ", summary.Vulnerabilities.GetSubScanTotalIssueCount(subScanType))
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

func getPrefixPadding(prefix string) int {
	// 4 spaces for the list item prefix (len of symbol not equal to actual length)
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
		content += GetScaSummaryCountString(*summary.Vulnerabilities.ScaScanResults, padding)
	case formats.IacScan:
		content += GetSeveritySummaryCountString(*summary.Vulnerabilities.IacScanResults, padding)
	case formats.SecretsScan:
		content += GetSeveritySummaryCountString(*summary.Vulnerabilities.SecretsScanResults, padding)
	case formats.SastScan:
		content += GetSeveritySummaryCountString(*summary.Vulnerabilities.SastScanResults, padding)
	}
	return
}

func hasApplicableDataToDisplayInSummary(summary formats.TwoLevelSummaryCount) bool {
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

func GetScaSummaryCountString(summary formats.ScanScaResult, padding int) (content string) {
	if summary.SummaryCount.GetTotal() == 0 {
		return
	}
	if !hasApplicableDataToDisplayInSummary(summary.SummaryCount) {
		return GetSeveritySummaryCountString(summary.SummaryCount.GetCombinedLowerLevel(), padding)
	}
	// Display contextual-analysis details
	keys := getSummarySortedKeysToDisplay(maps.Keys(summary.SummaryCount)...)
	for i, severity := range keys {
		if i > 0 {
			content += "<br>" + strings.Repeat(" ", padding)
		}
		statusCounts := summary.SummaryCount[severity]
		content += fmt.Sprintf("%s%s",
			fmt.Sprintf(summaryContentToFormatString[severity], statusCounts.GetTotal()),
			GetSummaryContentString(statusCounts, ", ", true),
		)
	}
	return
}

var (
	// Convert summary of the given keys to the needed string
	summaryContentToFormatString = map[string]string{
		"Critical":                             `❗️ <span style="color:red">%d Critical</span>`,
		"High":                                 `🔴 <span style="color:red">%d High</span>`,
		"Medium":                               `🟠 <span style="color:orange">%d Medium</span>`,
		"Low":                                  `🟡 <span style="color:yellow">%d Low</span>`,
		"Unknown":                              `⚪️ <span style="color:white">%d Unknown</span>`,
		jasutils.Applicable.String():           "%d " + jasutils.Applicable.String(),
		jasutils.NotApplicable.String():        "%d " + jasutils.NotApplicable.String(),
		formats.ViolationTypeSecurity.String(): "%d Security",
		formats.ViolationTypeLicense.String():  "%d License",
		formats.ViolationTypeOperationalRisk.String(): "%d Operational",
	}
	// AllowedSorted is the order of the keys to display in the summary
	allowedSorted = []string{
		"Critical", "High", "Medium", "Low", "Unknown",
		jasutils.Applicable.String(), jasutils.NotApplicable.String(),
		formats.ViolationTypeSecurity.String(), formats.ViolationTypeLicense.String(), formats.ViolationTypeOperationalRisk.String(),
	}
)

func getSummarySortedKeysToDisplay(keys ...string) (sorted []string) {
	if len(keys) == 0 {
		return
	}
	keysSet := datastructures.MakeSetFromElements(keys...)
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

func GetSummaryContentString(summary formats.SummaryCount, delimiter string, wrapWithBracket bool) (content string) {
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
	if wrapWithBracket {
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

func getScanSummary(extendedScanResults *ExtendedScanResults, scaResults ...*ScaScanResult) (summary formats.ScanSummaryResult) {
	if len(scaResults) == 0 {
		return
	}
	if len(scaResults) == 1 {
		summary.Target = scaResults[0].Target
	}
	// Parse violations
	summary.Violations = getScanViolationsSummary(scaResults...)
	// Parse vulnerabilities
	summary.Vulnerabilities = getScanSecurityVulnerabilitiesSummary(extendedScanResults, scaResults...)
	return
}

func getScanViolationsSummary(scaResults ...*ScaScanResult) (violations formats.TwoLevelSummaryCount) {
	vioUniqueFindings := map[string]IssueDetails{}
	if len(scaResults) == 0 {
		return
	}
	// Parse unique findings
	for _, scaResult := range scaResults {
		for _, xrayResult := range scaResult.XrayResults {
			for _, violation := range xrayResult.Violations {
				details := IssueDetails{FirstLevelValue: violation.ViolationType, SecondLevelValue: severityutils.GetSeverity(violation.Severity).String()}
				for compId := range violation.Components {
					if violation.ViolationType == formats.ViolationTypeSecurity.String() {
						for _, cve := range violation.Cves {
							vioUniqueFindings[getCveId(cve, violation.IssueId)+compId] = details
						}
					} else {
						vioUniqueFindings[violation.IssueId+compId] = details
					}
				}
			}
		}
	}
	// Aggregate
	return issueDetailsToSummaryCount(vioUniqueFindings)
}

func getScanSecurityVulnerabilitiesSummary(extendedScanResults *ExtendedScanResults, scaResults ...*ScaScanResult) (summary *formats.ScanVulnerabilitiesSummary) {
	summary = &formats.ScanVulnerabilitiesSummary{}
	if extendedScanResults == nil {
		summary.ScaScanResults = getScaSummaryResults(scaResults)
		return
	}
	if len(scaResults) > 0 {
		summary.ScaScanResults = getScaSummaryResults(scaResults, extendedScanResults.ApplicabilityScanResults...)
	}
	summary.IacScanResults = getJASSummaryCount(extendedScanResults.IacScanResults...)
	summary.SecretsScanResults = getJASSummaryCount(extendedScanResults.SecretsScanResults...)
	summary.SastScanResults = getJASSummaryCount(extendedScanResults.SastScanResults...)
	return
}

type IssueDetails struct {
	FirstLevelValue  string
	SecondLevelValue string
}

func getCveId(cve services.Cve, defaultIssueId string) string {
	if cve.Id == "" {
		return defaultIssueId
	}
	return cve.Id
}

func getSecurityIssueFindings(cves []services.Cve, issueId string, severity severityutils.Severity, components map[string]services.Component, applicableRuns ...*sarif.Run) (findings, uniqueFindings map[string]IssueDetails) {
	findings = map[string]IssueDetails{}
	uniqueFindings = map[string]IssueDetails{}
	for _, cve := range cves {
		cveId := getCveId(cve, issueId)
		applicableStatus := jasutils.NotScanned
		if applicableInfo := getCveApplicabilityField(cveId, applicableRuns, components); applicableInfo != nil {
			applicableStatus = jasutils.ConvertToApplicabilityStatus(applicableInfo.Status)
		}
		uniqueFindings[cveId] = IssueDetails{
			FirstLevelValue:  severity.String(),
			SecondLevelValue: applicableStatus.String(),
		}
		for compId := range components {
			findings[cveId+compId] = uniqueFindings[cveId]
		}
	}
	return
}

func getScaSummaryResults(scaScanResults []*ScaScanResult, applicableRuns ...*sarif.Run) *formats.ScanScaResult {
	vulFindings := map[string]IssueDetails{}
	vulUniqueFindings := map[string]IssueDetails{}
	if len(scaScanResults) == 0 {
		return nil
	}
	// Aggregate unique findings
	for _, scaResult := range scaScanResults {
		for _, xrayResult := range scaResult.XrayResults {
			for _, vulnerability := range xrayResult.Vulnerabilities {
				vulFinding, vulUniqueFinding := getSecurityIssueFindings(vulnerability.Cves, vulnerability.IssueId, severityutils.GetSeverity(vulnerability.Severity), vulnerability.Components, applicableRuns...)
				for key, value := range vulFinding {
					vulFindings[key] = value
				}
				for key, value := range vulUniqueFinding {
					vulUniqueFindings[key] = value
				}
			}
		}
	}
	return &formats.ScanScaResult{
		SummaryCount:   issueDetailsToSummaryCount(vulFindings),
		UniqueFindings: issueDetailsToSummaryCount(vulUniqueFindings).GetTotal(),
	}
}

func issueDetailsToSummaryCount(uniqueFindings map[string]IssueDetails) formats.TwoLevelSummaryCount {
	summary := formats.TwoLevelSummaryCount{}
	for _, details := range uniqueFindings {
		if _, ok := summary[details.FirstLevelValue]; !ok {
			summary[details.FirstLevelValue] = formats.SummaryCount{}
		}
		summary[details.FirstLevelValue][details.SecondLevelValue]++
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
				resultLevel := sarifutils.GetResultLevel(result)
				severity, err := severityutils.ParseSeverity(resultLevel, true)
				if err != nil {
					log.Warn(fmt.Sprintf("Failed to parse Sarif level %s. %s", resultLevel, err.Error()))
					severity = severityutils.Unknown
				}
				severityutils.GetSeverity(sarifutils.GetResultLevel(result))
				issueToSeverity[sarifutils.GetLocationId(location)] = severity.String()
			}
		}
	}
	for _, severity := range issueToSeverity {
		count[severity]++
	}
	return &count
}
