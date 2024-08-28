package utils

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils/commandsummary"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/resources"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

const (
	Build    SecuritySummarySection = "Build-info Scans"
	Binary   SecuritySummarySection = "Artifact Scans"
	Modules  SecuritySummarySection = "Source Code Scans"
	Docker   SecuritySummarySection = "Docker Image Scans"
	Curation SecuritySummarySection = "Curation Audit"

	PreFormat     HtmlTag = "<pre>%s</pre>"
	ImgTag        HtmlTag = "<img alt=\"%s\" src=%s>"
	CenterContent HtmlTag = "<div style=\"display: flex; align-items: center; text-align: center\">%s</div>"
	BoldTxt       HtmlTag = "<b>%s</b>"
	Link          HtmlTag = "<a href=\"%s\">%s</a>"
	NewLine       HtmlTag = "<br>%s"
	Details       HtmlTag = "<details><summary>%s</summary>%s</details>"
	DetailsOpen   HtmlTag = "<details open><summary><h3>%s</h3></summary>%s</details>"
	RedColor      HtmlTag = "<span style=\"color:red\">%s</span>"
	OrangeColor   HtmlTag = "<span style=\"color:orange\">%s</span>"
	GreenColor    HtmlTag = "<span style=\"color:green\">%s</span>"
	TabTag        HtmlTag = "&Tab;%s"

	ApplicableStatus    SeverityStatus = "%d Applicable"
	NotApplicableStatus SeverityStatus = "%d Not Applicable"
)

type SecuritySummarySection string
type HtmlTag string
type SeverityStatus string

func (c HtmlTag) Format(args ...any) string {
	return fmt.Sprintf(string(c), args...)
}

func (c HtmlTag) FormatInt(value int) string {
	return fmt.Sprintf(string(c), fmt.Sprintf("%d", value))
}

func (s SeverityStatus) Format(count int) string {
	return fmt.Sprintf(string(s), count)
}

func getStatusIcon(failed bool) string {
	statusIconPath := "passed.svg"
	if failed {
		statusIconPath = "failed.svg"
	}
	return ImgTag.Format(statusIconPath, fmt.Sprintf("%s/statusIcons/%s", resources.BaseResourcesUrl, statusIconPath))
}

type SecurityJobSummary struct{}

func NewCurationSummary(cmdResult formats.ResultsSummary) (summary ScanCommandResultSummary) {
	summary.ResultType = Curation
	summary.Summary = cmdResult
	return
}

func newResultSummary(cmdResults *Results, section SecuritySummarySection, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool) (summary ScanCommandResultSummary) {
	summary.ResultType = section
	summary.Args = &ResultSummaryArgs{BaseJfrogUrl: serverDetails.Url}
	summary.Summary = ToSummary(cmdResults, vulnerabilitiesReqested, violationsReqested)
	return
}

func NewBuildScanSummary(cmdResults *Results, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool, buildName, buildNumber string) (summary ScanCommandResultSummary) {
	summary = newResultSummary(cmdResults, Build, serverDetails, vulnerabilitiesReqested, violationsReqested)
	summary.Args.BuildName = buildName
	summary.Args.BuildNumbers = []string{buildNumber}
	return
}

func NewDockerScanSummary(cmdResults *Results, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool, dockerImage string) (summary ScanCommandResultSummary) {
	summary = newResultSummary(cmdResults, Docker, serverDetails, vulnerabilitiesReqested, violationsReqested)
	summary.Args.DockerImage = dockerImage
	return
}

func NewBinaryScanSummary(cmdResults *Results, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool) (summary ScanCommandResultSummary) {
	return newResultSummary(cmdResults, Binary, serverDetails, vulnerabilitiesReqested, violationsReqested)
}

func NewAuditScanSummary(cmdResults *Results, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool) (summary ScanCommandResultSummary) {
	return newResultSummary(cmdResults, Modules, serverDetails, vulnerabilitiesReqested, violationsReqested)
}

type ResultSummaryArgs struct {
	BaseJfrogUrl string `json:"base_jfrog_url,omitempty"`
	// Args to id the result
	DockerImage  string   `json:"docker_image,omitempty"`
	BuildName    string   `json:"build_name,omitempty"`
	BuildNumbers []string `json:"build_numbers,omitempty"`
}

func (rsa ResultSummaryArgs) GetUrl(index commandsummary.Index, scanIds ...string) string {
	if rsa.BaseJfrogUrl == "" {
		return ""
	}
	if index == commandsummary.BuildScan {
		return fmt.Sprintf("%sui/scans-list/builds-scans", rsa.BaseJfrogUrl)
	} else {
		baseUrl := fmt.Sprintf("%sui/onDemandScanning", rsa.BaseJfrogUrl)
		if len(scanIds) == 1 {
			return fmt.Sprintf("%s/%s", baseUrl, scanIds[0])
		}
		return fmt.Sprintf("%s/list", baseUrl)
	}
}

func (rsa ResultSummaryArgs) ToArgs(index commandsummary.Index) (args []string) {
	if index == commandsummary.BuildScan {
		args = append(args, rsa.BuildName)
		args = append(args, rsa.BuildNumbers...)
	} else if index == commandsummary.DockerScan {
		args = append(args, rsa.DockerImage)
	}
	return
}

type ScanCommandResultSummary struct {
	ResultType SecuritySummarySection `json:"resultType"`
	Args       *ResultSummaryArgs     `json:"args,omitempty"`
	Summary    formats.ResultsSummary `json:"summary"`
}

// Manage the job summary for security commands
func NewSecurityJobSummary() (js *commandsummary.CommandSummary, err error) {
	return commandsummary.New(&SecurityJobSummary{}, "security")
}

// Record the security command outputs
func RecordSecurityCommandSummary(content ScanCommandResultSummary) (err error) {
	if !commandsummary.ShouldRecordSummary() {
		return
	}
	manager, err := NewSecurityJobSummary()
	if err != nil || manager == nil {
		return
	}
	wd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	updateSummaryNamesToRelativePath(&content.Summary, wd)
	if index := getDataIndexFromSection(content.ResultType); index != "" {
		return recordIndexData(manager, content, index)
	}
	return manager.Record(content)
}

func updateSummaryNamesToRelativePath(summary *formats.ResultsSummary, wd string) {
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

func getDataIndexFromSection(section SecuritySummarySection) commandsummary.Index {
	switch section {
	case Build:
		return commandsummary.BuildScan
	case Binary:
		return commandsummary.BinariesScan
	case Modules:
		return commandsummary.BinariesScan
	case Docker:
		return commandsummary.DockerScan
	}
	// No index for the section
	return ""
}

func recordIndexData(manager *commandsummary.CommandSummary, content ScanCommandResultSummary, index commandsummary.Index) (err error) {
	if index == commandsummary.BinariesScan {
		for _, scan := range content.Summary.Scans {
			err = errors.Join(err, manager.RecordWithIndex(newScanCommandResultSummary(content.ResultType, content.Args, scan), index, scan.Target))
		}
	} else {
		// Save the results based on the index and the provided arguments (keys)
		// * Docker scan results are saved with the image tag as the key
		// * Build scan results are saved with the build name and number as the key
		err = manager.RecordWithIndex(content, index, content.Args.ToArgs(index)...)
	}
	return
}

func newScanCommandResultSummary(resultType SecuritySummarySection, args *ResultSummaryArgs, scans ...formats.ScanSummary) ScanCommandResultSummary {
	return ScanCommandResultSummary{ResultType: resultType, Args: args, Summary: formats.ResultsSummary{Scans: scans}}
}

func loadContent(dataFiles []string, filterSections ...SecuritySummarySection) ([]formats.ResultsSummary, ResultSummaryArgs, error) {
	data := []formats.ResultsSummary{}
	args := ResultSummaryArgs{}
	for _, dataFilePath := range dataFiles {
		// Load file content
		var cmdResults ScanCommandResultSummary
		if err := commandsummary.UnmarshalFromFilePath(dataFilePath, &cmdResults); err != nil {
			return nil, args, fmt.Errorf("failed while Unmarshal '%s': %w", dataFilePath, err)
		}
		if len(filterSections) == 0 || (slices.Contains(filterSections, cmdResults.ResultType)) {
			data = append(data, cmdResults.Summary)
			if cmdResults.Args == nil {
				continue
			}
			if args.BaseJfrogUrl == "" {
				args.BaseJfrogUrl = cmdResults.Args.BaseJfrogUrl
			}
			if args.DockerImage == "" {
				args.DockerImage = cmdResults.Args.DockerImage
			}
			if args.BuildName == "" {
				args.BuildName = cmdResults.Args.BuildName
			}
			args.BuildNumbers = append(args.BuildNumbers, cmdResults.Args.BuildNumbers...)
		}
	}
	return data, args, nil
}

func (js *SecurityJobSummary) BinaryScan(filePaths []string) (generator DynamicMarkdownGenerator, err error) {
	generator = DynamicMarkdownGenerator{index: commandsummary.BinariesScan, dataFiles: filePaths, extendedView: commandsummary.StaticMarkdownConfig.IsExtendedSummary()}
	err = generator.loadContentFromFiles()
	return
}

func (js *SecurityJobSummary) BuildScan(filePaths []string) (generator DynamicMarkdownGenerator, err error) {
	generator = DynamicMarkdownGenerator{index: commandsummary.BuildScan, dataFiles: filePaths, extendedView: commandsummary.StaticMarkdownConfig.IsExtendedSummary()}
	err = generator.loadContentFromFiles()
	return
}

func (js *SecurityJobSummary) DockerScan(filePaths []string) (generator DynamicMarkdownGenerator, err error) {
	generator = DynamicMarkdownGenerator{index: commandsummary.DockerScan, dataFiles: filePaths, extendedView: commandsummary.StaticMarkdownConfig.IsExtendedSummary()}
	err = generator.loadContentFromFiles()
	return
}

func (js *SecurityJobSummary) GetNonScannedResult() (generator EmptyMarkdownGenerator, _ error) {
	generator = EmptyMarkdownGenerator{}
	return
}

// Generate the Security section (Curation)
func (js *SecurityJobSummary) GenerateMarkdownFromFiles(dataFilePaths []string) (markdown string, err error) {
	curationData, _, err := loadContent(dataFilePaths, Curation)
	if err != nil {
		return
	}
	return GenerateSecuritySectionMarkdown(curationData)
}

func GenerateSecuritySectionMarkdown(curationData []formats.ResultsSummary) (markdown string, err error) {
	if !hasCurationCommand(curationData) {
		return
	}
	// Create the markdown content
	markdown += fmt.Sprintf("\n\n#### %s\n| Audit Summary | Project name | Audit Details |\n|--------|--------|---------|", Curation)
	for i := range curationData {
		for _, summary := range curationData[i].Scans {
			status := getStatusIcon(false)
			if summary.HasBlockedPackages() {
				status = getStatusIcon(true)
			}
			markdown += fmt.Sprintf("\n| %s | %s | %s |", status, summary.Target, PreFormat.Format(getCurationDetailsString(summary)))
		}
	}
	markdown = DetailsOpen.Format("🔒 Security Summary", markdown)
	return
}

func hasCurationCommand(data []formats.ResultsSummary) bool {
	for _, summary := range data {
		for _, scan := range summary.Scans {
			if scan.HasCuratedPackages() {
				return true
			}
		}
	}
	return false
}

type blockedPackageByType struct {
	BlockedType    string
	BlockedSummary map[string]int
}

func getCurationDetailsString(summary formats.ScanSummary) (content string) {
	if summary.CuratedPackages == nil {
		return
	}
	content += fmt.Sprintf("Total Number of resolved packages: %s", BoldTxt.FormatInt(summary.CuratedPackages.PackageCount))
	blockedPackages := summary.CuratedPackages.GetBlockedCount()
	if blockedPackages == 0 {
		return
	}
	content += NewLine.Format(fmt.Sprintf("🟢 Approved packages: %s", BoldTxt.FormatInt(summary.CuratedPackages.GetApprovedCount())))
	content += NewLine.Format(fmt.Sprintf("🔴 Blocked packages: %s", BoldTxt.FormatInt(blockedPackages)))
	// Display the blocked packages grouped by type
	var blocked []blockedPackageByType
	// Sort the blocked packages by name
	for _, blockTypeValue := range summary.CuratedPackages.Blocked {
		blocked = append(blocked, toBlockedPackgeByType(blockTypeValue))
	}
	sort.Slice(blocked, func(i, j int) bool {
		return blocked[i].BlockedType > blocked[j].BlockedType
	})
	// Display the blocked packages
	for _, blockStruct := range blocked {
		content += Details.Format(
			fmt.Sprintf("%s (%s)", blockStruct.BlockedType, BoldTxt.FormatInt(len(blockStruct.BlockedSummary))),
			getBlockedPackages(blockStruct.BlockedSummary),
		)
	}
	return
}

func toBlockedPackgeByType(blockTypeValue formats.BlockedPackages) blockedPackageByType {
	return blockedPackageByType{BlockedType: formatPolicyAndCond(blockTypeValue.Policy, blockTypeValue.Condition), BlockedSummary: blockTypeValue.Packages}
}

func formatPolicyAndCond(policy, cond string) string {
	return fmt.Sprintf("%s %s, %s %s", BoldTxt.Format("Violated Policy:"), policy, BoldTxt.Format("Condition:"), cond)
}

func getBlockedPackages(blockedSummary map[string]int) string {
	content := ""
	for blockedPackage := range blockedSummary {
		blockedPackageStr := fmt.Sprintf("📦 %s", blockedPackage)
		if len(content) > 0 {
			content += NewLine.Format(blockedPackageStr)
		} else {
			content += blockedPackageStr
		}
	}
	return content
}

type EmptyMarkdownGenerator struct{}

func (g EmptyMarkdownGenerator) GetViolations() (content string) {
	return PreFormat.Format("ℹ️ Not Scanned")
}

func (g EmptyMarkdownGenerator) GetVulnerabilities() (content string) {
	return PreFormat.Format("ℹ️ Not Scanned")
}

type DynamicMarkdownGenerator struct {
	index        commandsummary.Index
	extendedView bool
	dataFiles    []string
	content      []formats.ResultsSummary
	args         ResultSummaryArgs
}

func (mg *DynamicMarkdownGenerator) loadContentFromFiles() (err error) {
	if len(mg.content) > 0 {
		// Already loaded
		return
	}
	mg.content, mg.args, err = loadContent(mg.dataFiles)
	return
}

func (mg DynamicMarkdownGenerator) GetViolations() (content string) {
	summary := formats.GetViolationSummaries(mg.content...)
	if summary == nil {
		content = PreFormat.Format("No watch is defined")
		return
	}
	resultsMarkdown := generateResultsMarkdown(true, getJfrogUrl(mg.index, mg.args, &summary.ScanResultSummary, mg.extendedView), &summary.ScanResultSummary)
	if len(summary.Watches) == 0 {
		content = resultsMarkdown
		return
	}
	watches := "watch"
	if len(summary.Watches) > 1 {
		watches += "es"
	}
	watches += ": " + strings.Join(summary.Watches, ", ")
	content = PreFormat.Format(watches) + NewLine.Format(resultsMarkdown)
	return
}

func (mg DynamicMarkdownGenerator) GetVulnerabilities() (content string) {
	summary := formats.GetVulnerabilitiesSummaries(mg.content...)
	if summary == nil {
		// We are in violation mode and vulnerabilities are not requested (no info to show)
		return
	}
	content = generateResultsMarkdown(false, getJfrogUrl(mg.index, mg.args, summary, mg.extendedView), summary)
	return
}

func getJfrogUrl(index commandsummary.Index, args ResultSummaryArgs, summary *formats.ScanResultSummary, extendedView bool) (url string) {
	if !extendedView {
		return
	}
	if summary.ScaResults != nil {
		if moreInfoUrls := summary.ScaResults.MoreInfoUrls; len(moreInfoUrls) > 0 {
			return Link.Format(moreInfoUrls[0], "See the results of the scan in JFrog")
		}
	}
	if defaultUrl := args.GetUrl(index, summary.GetScanIds()...); defaultUrl != "" {
		return Link.Format(defaultUrl, "See the results of the scan in JFrog")
	}
	return
}

func generateResultsMarkdown(violations bool, moreInfoUrl string, content *formats.ScanResultSummary) (markdown string) {
	if !content.HasIssues() {
		markdown = getNoIssuesMarkdown(violations)
	} else {
		markdown = getResultsTypesSummaryString(violations, content)
		markdown += NewLine.Format(getResultsSeveritySummaryString(content))
		if moreInfoUrl != "" {
			markdown += NewLine.Format(moreInfoUrl)
		}
	}
	markdown = PreFormat.Format(markdown)
	return
}

func getNoIssuesMarkdown(violations bool) (markdown string) {
	noIssuesStr := "No security issues found"
	if violations {
		noIssuesStr = "No violations found"
	}
	return noIssuesStr
}

func getCenteredSvgWithText(svg, text string) (markdown string) {
	return CenterContent.Format(fmt.Sprintf("%s %s", svg, text))
}

func getResultsTypesSummaryString(violations bool, summary *formats.ScanResultSummary) (content string) {
	if violations {
		content = fmt.Sprintf("%d Policy Violations:", summary.GetTotal())
	} else {
		content = fmt.Sprintf("%d Security Issues:", summary.GetTotal())
	}
	if summary.ScaResults != nil {
		if violations {
			if count := summary.GetTotal(formats.ScaSecurityResult); count > 0 {
				content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.ScaSecurityResult.String()))
			}
			if count := summary.GetTotal(formats.ScaOperationalResult); count > 0 {
				content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.ScaOperationalResult.String()))
			}
			if count := summary.GetTotal(formats.ScaLicenseResult); count > 0 {
				content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.ScaLicenseResult.String()))
			}
		} else {
			if count := summary.GetTotal(formats.ScaSecurityResult); count > 0 {
				content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.ScaResult.String()))
			}
		}
	}
	if summary.SecretsResults != nil {
		if count := summary.GetTotal(formats.SecretsResult); count > 0 {
			content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.SecretsResult.String()))
		}
	}
	if summary.SastResults != nil {
		if count := summary.GetTotal(formats.SastResult); count > 0 {
			content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.SastResult.String()))
		}
	}
	if summary.IacResults != nil {
		if count := summary.GetTotal(formats.IacResult); count > 0 {
			content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.IacResult.String()))
		}
	}
	return
}

func getResultsSeveritySummaryString(summary *formats.ScanResultSummary) (markdown string) {
	details := summary.GetSummaryBySeverity()
	if details.GetTotal(severityutils.Critical.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.Critical, details))
	}
	if details.GetTotal(severityutils.High.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.High, details))
	}
	if details.GetTotal(severityutils.Medium.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.Medium, details))
	}
	if details.GetTotal(severityutils.Low.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.Low, details))
	}
	if details.GetTotal(severityutils.Unknown.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.Unknown, details))
	}
	return
}

func getSeverityMarkdown(severity severityutils.Severity, details formats.ResultSummary) (markdown string) {
	svg := getSeverityIcon(severity, false)
	severityStr := severity.String()
	totalSeverityIssues := details.GetTotal(severityStr)
	severityMarkdown := fmt.Sprintf("%d %s%s", totalSeverityIssues, severityStr, getSeverityStatusesCountString(details[severityStr]))
	return getCenteredSvgWithText(svg, severityMarkdown)
}

func getSeverityIcon(severity severityutils.Severity, svg bool) string {
	if svg {
		return ImgTag.Format(severity.String(), severityutils.GetSeverityIcon(severity, true))
	}
	return severityutils.GetSeverityIcon(severity, false)
}

func getSeverityStatusesCountString(statusCounts map[string]int) string {
	return generateSeverityStatusesCountString(getSeverityDisplayStatuses(statusCounts))
}

func getSeverityDisplayStatuses(statusCounts map[string]int) (displayData map[SeverityStatus]int) {
	displayData = map[SeverityStatus]int{}
	for status, count := range statusCounts {
		switch status {
		case jasutils.Applicability.String():
			displayData[ApplicableStatus] += count
		case jasutils.NotApplicable.String():
			displayData[NotApplicableStatus] += count
		}
	}
	return displayData
}

func generateSeverityStatusesCountString(displayData map[SeverityStatus]int) string {
	if len(displayData) == 0 {
		return ""
	}
	display := []string{}
	if count, ok := displayData[ApplicableStatus]; ok {
		display = append(display, ApplicableStatus.Format(count))
	}
	if count, ok := displayData[NotApplicableStatus]; ok {
		display = append(display, NotApplicableStatus.Format(count))
	}
	return fmt.Sprintf(" (%s)", strings.Join(display, ", "))
}
