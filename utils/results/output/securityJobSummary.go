package output

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/commandsummary"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"golang.org/x/exp/maps"
)

const (
	Build    SecuritySummarySection = "Builds"
	Binary   SecuritySummarySection = "Artifacts"
	Modules  SecuritySummarySection = "Modules"
	Curation SecuritySummarySection = "Curation"
)

var (
	// Convert summary of the given keys to the needed string
	summaryContentToFormatString = map[string]string{
		severityutils.Critical.String():               `❗️ <span style="color:red">%d ` + severityutils.Critical.String() + `</span>`,
		severityutils.High.String():                   `🔴 <span style="color:red">%d ` + severityutils.High.String() + `</span>`,
		severityutils.Medium.String():                 `🟠 <span style="color:orange">%d ` + severityutils.Medium.String() + `</span>`,
		severityutils.Low.String():                    `🟡 <span style="color:yellow">%d ` + severityutils.Low.String() + `</span>`,
		severityutils.Unknown.String():                `⚪️ <span style="color:white">%d ` + severityutils.Unknown.String() + `</span>`,
		jasutils.Applicable.String():                  "%d " + jasutils.Applicable.String(),
		jasutils.NotApplicable.String():               "%d " + jasutils.NotApplicable.String(),
		formats.ViolationTypeSecurity.String():        "%d Security",
		formats.ViolationTypeLicense.String():         "%d License",
		formats.ViolationTypeOperationalRisk.String(): "%d Operational",
	}
	// AllowedSorted is the order of the keys to display in the summary
	allowedSorted = []string{
		severityutils.Critical.String(), severityutils.High.String(), severityutils.Medium.String(), severityutils.Low.String(), severityutils.Unknown.String(),
		jasutils.Applicable.String(), jasutils.NotApplicable.String(),
		formats.ViolationTypeSecurity.String(), formats.ViolationTypeLicense.String(), formats.ViolationTypeOperationalRisk.String(),
	}
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

func CreateCommandSummaryResult(section SecuritySummarySection, cmdResults *results.SecurityCommandResults) (ScanCommandSummaryResult, error) {
	convertor := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{})
	summary, err := convertor.ConvertToSummary(cmdResults)
	if err != nil {
		return ScanCommandSummaryResult{Section: section}, err
	}
	return ScanCommandSummaryResult{
		Section: section,
		Results: summary,
	}, nil
}

// Record the security command output
func RecordSecurityCommandResultOutput(section SecuritySummarySection, cmdResults *results.SecurityCommandResults) (err error) {
	summary, err := CreateCommandSummaryResult(section, cmdResults)
	if err != nil {
		return
	}
	return RecordSecurityCommandOutput(summary)
}

func RecordSecurityCommandOutput(summary ScanCommandSummaryResult) (err error) {
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
	summary.WorkingDirectory = wd
	return manager.Record(summary)
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
		scs.addCommandSummaryResult(cmdResults)
	}
	return
}

func (scs *SecurityCommandsSummary) addCommandSummaryResult(cmdResults ...ScanCommandSummaryResult) {
	for _, cmdResult := range cmdResults {
		results := cmdResult.Results
		// Update the working directory
		updateSummaryNamesToRelativePath(&results, cmdResult.WorkingDirectory)
		// Append the new data
		switch cmdResult.Section {
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
