package output

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils/commandsummary"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/resources"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	PreFormat              HtmlTag = "<pre>%s</pre>"
	ImgTag                 HtmlTag = "<img alt=\"%s\" src=%s>"
	CenterContent          HtmlTag = "<div style=\"display: flex; align-items: center; text-align: center\">%s</div>"
	BoldTxt                HtmlTag = "<b>%s</b>"
	Link                   HtmlTag = "<a href=\"%s\">%s</a>"
	NewLine                HtmlTag = "<br>%s"
	DetailsWithSummary     HtmlTag = "<details><summary>%s</summary>%s</details>"
	DetailsOpenWithSummary HtmlTag = "<details open><summary><h3>%s</h3></summary>%s\n</details>"
	TabTag                 HtmlTag = "&Tab;%s"

	ApplicableStatusCount    SeverityDisplayStatus = "%d Applicable"
	NotApplicableStatusCount SeverityDisplayStatus = "%d Not Applicable"

	maxWatchesInLine = 4
)

type HtmlTag string
type SeverityDisplayStatus string

func (c HtmlTag) Format(args ...any) string {
	return fmt.Sprintf(string(c), args...)
}

func (c HtmlTag) FormatInt(value int) string {
	return fmt.Sprintf(string(c), fmt.Sprintf("%d", value))
}

func (s SeverityDisplayStatus) Format(count int) string {
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

func newResultSummary(cmdResults *results.SecurityCommandResults, serverDetails *config.ServerDetails, vulnerabilitiesRequested, violationsRequested bool) (summary ScanCommandResultSummary, err error) {
	summary.ResultType = cmdResults.CmdType
	summary.Args = &ResultSummaryArgs{BaseJfrogUrl: serverDetails.Url}
	summary.Summary, err = conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeVulnerabilities: vulnerabilitiesRequested,
		HasViolationContext:    violationsRequested,
		Pretty:                 true,
	}).ConvertToSummary(cmdResults)
	return
}

func NewBuildScanSummary(cmdResults *results.SecurityCommandResults, serverDetails *config.ServerDetails, vulnerabilitiesRequested bool, buildName, buildNumber string) (summary ScanCommandResultSummary, err error) {
	if summary, err = newResultSummary(cmdResults, serverDetails, vulnerabilitiesRequested, true); err != nil {
		return
	}
	summary.Args.BuildName = buildName
	summary.Args.BuildNumbers = []string{buildNumber}
	return
}

func NewDockerScanSummary(cmdResults *results.SecurityCommandResults, serverDetails *config.ServerDetails, vulnerabilitiesRequested, violationsRequested bool, dockerImage string) (summary ScanCommandResultSummary, err error) {
	if summary, err = newResultSummary(cmdResults, serverDetails, vulnerabilitiesRequested, violationsRequested); err != nil {
		return
	}
	summary.Args.DockerImage = dockerImage
	return
}

func NewBinaryScanSummary(cmdResults *results.SecurityCommandResults, serverDetails *config.ServerDetails, vulnerabilitiesRequested, violationsRequested bool) (summary ScanCommandResultSummary, err error) {
	return newResultSummary(cmdResults, serverDetails, vulnerabilitiesRequested, violationsRequested)
}

func NewAuditScanSummary(cmdResults *results.SecurityCommandResults, serverDetails *config.ServerDetails, vulnerabilitiesRequested, violationsRequested bool) (summary ScanCommandResultSummary, err error) {
	return newResultSummary(cmdResults, serverDetails, vulnerabilitiesRequested, violationsRequested)
}

func NewCurationSummary(cmdResult formats.ResultsSummary) (summary ScanCommandResultSummary) {
	summary.ResultType = utils.Curation
	summary.Summary = cmdResult
	return
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
		rsa.BaseJfrogUrl = commandsummary.StaticMarkdownConfig.GetPlatformUrl()
	}
	if index == commandsummary.BuildScan {
		return fmt.Sprintf("%sui/scans-list/builds-scans", rsa.BaseJfrogUrl)
	} else {
		baseUrl := fmt.Sprintf("%sui/onDemandScanning", rsa.BaseJfrogUrl)
		if len(scanIds) > 0 && scanIds[0] != "" {
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
		image := rsa.DockerImage
		// if user did not provide image tag, add latest
		if !strings.Contains(image, ":") {
			image += ":latest"
		}
		args = append(args, image)
	}
	return
}

type ScanCommandResultSummary struct {
	ResultType utils.CommandType      `json:"resultType"`
	Args       *ResultSummaryArgs     `json:"args,omitempty"`
	Summary    formats.ResultsSummary `json:"summary"`
}

// Manage the job summary for security commands
func NewSecurityJobSummary() (js *commandsummary.CommandSummary, err error) {
	return commandsummary.New(&SecurityJobSummary{}, "security")
}

func getRecordManager() (manager *commandsummary.CommandSummary, err error) {
	if !commandsummary.ShouldRecordSummary() {
		return
	}
	return NewSecurityJobSummary()
}

// Record the security command outputs
func RecordSecurityCommandSummary(content ScanCommandResultSummary) (err error) {
	manager, err := getRecordManager()
	if err != nil || manager == nil {
		return
	}
	wd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	updateSummaryNamesToRelativePath(&content.Summary, wd)
	if index := getDataIndexFromCommandType(content.ResultType); index != "" {
		return recordIndexData(manager, content, index)
	}
	return manager.Record(content)
}

func RecordSarifOutput(cmdResults *results.SecurityCommandResults, serverDetails *config.ServerDetails, includeVulnerabilities, hasViolationContext bool, requestedScans ...utils.SubScanType) (err error) {
	// Verify if we should record the results
	manager, err := getRecordManager()
	if err != nil || manager == nil {
		return
	}
	record, err := ifNoJasNoGHAS(cmdResults, serverDetails)
	if err != nil {
		return
	}
	if !record {
		// No JAS no GHAS
		log.Info("Results can be uploaded to Github security tab automatically by upgrading your JFrog subscription.")
		return
	}
	// Convert the results to SARIF format
	sarifReport, err := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeVulnerabilities: includeVulnerabilities,
		HasViolationContext:    hasViolationContext,
		PatchBinaryPaths:       true,
		RequestedScans:         requestedScans,
		Pretty:                 true,
	}).ConvertToSarif(cmdResults)
	if err != nil {
		return err
	}
	// Record the SARIF report
	out, err := utils.GetAsJsonBytes(sarifReport, false, false)
	if err != nil {
		return errorutils.CheckError(err)
	}
	return manager.RecordWithIndex(out, commandsummary.SarifReport)
}

func ifNoJasNoGHAS(cmdResults *results.SecurityCommandResults, serverDetails *config.ServerDetails) (extended bool, err error) {
	if !cmdResults.EntitledForJas {
		return
	}
	return commandsummary.CheckExtendedSummaryEntitled(serverDetails.Url)
}

func CombineSarifOutputFiles(dataFilePaths []string) (data []byte, err error) {
	if len(dataFilePaths) == 0 {
		return
	}
	// Load the content of the files
	reports := []*sarif.Report{}
	for _, dataFilePath := range dataFilePaths {
		if report, e := loadSarifReport(dataFilePath); e != nil {
			err = errors.Join(err, e)
		} else {
			reports = append(reports, report)
		}
	}
	if err != nil {
		return
	}
	combined, err := sarifutils.CombineReports(reports...)
	if err != nil {
		return
	}
	return utils.GetAsJsonBytes(combined, false, false)
}

func loadSarifReport(dataFilePath string) (report *sarif.Report, err error) {
	fileData, err := os.ReadFile(dataFilePath)
	if err != nil {
		return
	}
	return sarif.FromBytes(fileData)
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

func getDataIndexFromCommandType(cmdType utils.CommandType) commandsummary.Index {
	switch cmdType {
	case utils.Build:
		return commandsummary.BuildScan
	case utils.Binary:
		return commandsummary.BinariesScan
	case utils.SourceCode:
		return commandsummary.BinariesScan
	case utils.DockerImage:
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

func newScanCommandResultSummary(resultType utils.CommandType, args *ResultSummaryArgs, scans ...formats.ScanSummary) ScanCommandResultSummary {
	return ScanCommandResultSummary{ResultType: resultType, Args: args, Summary: formats.ResultsSummary{Scans: scans}}
}

func loadContent(dataFiles []string, filterSections ...utils.CommandType) ([]formats.ResultsSummary, ResultSummaryArgs, error) {
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

func (js *SecurityJobSummary) GetNonScannedResult() (generator EmptyMarkdownGenerator) {
	return EmptyMarkdownGenerator{}
}

// Generate the Security section (Curation)
func (js *SecurityJobSummary) GenerateMarkdownFromFiles(dataFilePaths []string) (markdown string, err error) {
	curationData, _, err := loadContent(dataFilePaths, utils.Curation)
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
	markdown += "\n\n| Audit Summary | Project name | Audit Details |\n|--------|--------|---------|"
	for i := range curationData {
		for _, summary := range curationData[i].Scans {
			status := getStatusIcon(false)
			if summary.HasBlockedPackages() {
				status = getStatusIcon(true)
			}
			markdown += fmt.Sprintf("\n| %s | %s | %s |", status, summary.Target, PreFormat.Format(getCurationDetailsString(summary)))
		}
	}
	markdown = "\n" + DetailsOpenWithSummary.Format("🔒 Curation Audit", markdown)
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
		blocked = append(blocked, toBlockedPackageByType(blockTypeValue))
	}
	sort.Slice(blocked, func(i, j int) bool {
		return blocked[i].BlockedType > blocked[j].BlockedType
	})
	// Display the blocked packages
	for _, blockStruct := range blocked {
		content += DetailsWithSummary.Format(
			fmt.Sprintf("%s (%s)", blockStruct.BlockedType, BoldTxt.FormatInt(len(blockStruct.BlockedSummary))),
			getBlockedPackages(blockStruct.BlockedSummary),
		)
	}
	return
}

func toBlockedPackageByType(blockTypeValue formats.BlockedPackages) blockedPackageByType {
	return blockedPackageByType{BlockedType: formatPolicyAndCond(blockTypeValue.Policy, blockTypeValue.Condition), BlockedSummary: blockTypeValue.Packages}
}

func formatPolicyAndCond(policy, cond string) string {
	return fmt.Sprintf("%s %s, %s %s", BoldTxt.Format("Violated Policy:"), policy, BoldTxt.Format("Condition:"), cond)
}

func getBlockedPackages(blockedSummary map[string]int) (content string) {
	blocked := maps.Keys(blockedSummary)
	sort.Strings(blocked)
	for i, blockedPackage := range blocked {
		blockedPackageStr := fmt.Sprintf("📦 %s", blockedPackage)
		if i > 0 {
			blockedPackageStr = NewLine.Format(blockedPackageStr)
		}
		content += blockedPackageStr
	}
	return
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
	resultsMarkdown := mg.generateResultsMarkdown(true, getJfrogUrl(mg.index, mg.args, &summary.ScanResultSummary, mg.extendedView), &summary.ScanResultSummary)
	if len(summary.Watches) == 0 {
		content = resultsMarkdown
		return
	}
	content = getWatchesMarkdown(summary.Watches) + NewLine.Format(resultsMarkdown)
	return
}

// If more than maxWatchesInLine watches, put maxWatchesInLine at each line
func getWatchesMarkdown(watches []string) (content string) {
	sort.Strings(watches)
	watchesStr := ""
	multiLine := len(watches) > maxWatchesInLine
	for i := 0; i < len(watches); i += maxWatchesInLine {
		j := i + maxWatchesInLine
		if j > len(watches) {
			j = len(watches)
		}
		watchLine := strings.Join(watches[i:j], ", ")
		if multiLine {
			watchLine = NewLine.Format(watchLine)
		}
		watchesStr += watchLine
	}
	prefix := "watch"
	if len(watches) > 1 {
		prefix += "es"
	}
	content = PreFormat.Format(prefix + ": " + watchesStr)
	return
}

func (mg DynamicMarkdownGenerator) GetVulnerabilities() (content string) {
	summary := formats.GetVulnerabilitiesSummaries(mg.content...)
	if summary == nil {
		// We are in violation mode and vulnerabilities are not requested (no info to show)
		return
	}
	content = mg.generateResultsMarkdown(false, getJfrogUrl(mg.index, mg.args, summary, mg.extendedView), summary)
	return
}

func getJfrogUrl(index commandsummary.Index, args ResultSummaryArgs, summary *formats.ScanResultSummary, extendedView bool) (url string) {
	if !extendedView {
		return Link.Format(commandsummary.StaticMarkdownConfig.GetExtendedSummaryLangPage(), "🐸 Unlock detailed findings")
	}
	if moreInfoUrls := summary.GetMoreInfoUrls(); len(moreInfoUrls) > 0 {
		return Link.Format(moreInfoUrls[0], "See the results of the scan in JFrog")
	}
	if defaultUrl := args.GetUrl(index, summary.GetScanIds()...); defaultUrl != "" {
		return Link.Format(defaultUrl, "See the results of the scan in JFrog")
	}
	return
}

func (mg DynamicMarkdownGenerator) generateResultsMarkdown(violations bool, moreInfoUrl string, content *formats.ScanResultSummary) (markdown string) {
	if !content.HasIssues() {
		markdown = getNoIssuesMarkdown(violations)
	} else {
		markdown = getResultsTypesSummaryString(mg.index, violations, content)
		details := ""
		if mg.extendedView {
			details = getResultsSeveritySummaryString(content)
		}
		markdown += NewLine.Format(details)
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

func getResultsTypesSummaryString(index commandsummary.Index, violations bool, summary *formats.ScanResultSummary) (content string) {
	if violations {
		content = fmt.Sprintf("%d Policy Violations:", summary.GetTotal())
	} else {
		if index == commandsummary.DockerScan || index == commandsummary.BinariesScan {
			content = fmt.Sprintf("%d Security issues are grouped by CVE number:", summary.GetTotal())
		} else {
			content = fmt.Sprintf("%d Security Issues:", summary.GetTotal())
		}
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
	svg := getSeverityIcon(severity)
	severityStr := severity.String()
	totalSeverityIssues := details.GetTotal(severityStr)
	severityMarkdown := fmt.Sprintf("%d %s%s", totalSeverityIssues, severityStr, getSeverityStatusesCountString(details[severityStr]))
	return getCenteredSvgWithText(svg, severityMarkdown)
}

func getSeverityIcon(severity severityutils.Severity) string {
	return severityutils.GetSeverityIcon(severity)
}

func getSeverityStatusesCountString(statusCounts map[string]int) string {
	return generateSeverityStatusesCountString(getSeverityDisplayStatuses(statusCounts))
}

func getSeverityDisplayStatuses(statusCounts map[string]int) (displayData map[SeverityDisplayStatus]int) {
	displayData = map[SeverityDisplayStatus]int{}
	for status, count := range statusCounts {
		switch status {
		case jasutils.Applicability.String():
			displayData[ApplicableStatusCount] += count
		case jasutils.NotApplicable.String():
			displayData[NotApplicableStatusCount] += count
		}
	}
	return displayData
}

func generateSeverityStatusesCountString(displayData map[SeverityDisplayStatus]int) string {
	if len(displayData) == 0 {
		return ""
	}
	display := []string{}
	if count, ok := displayData[ApplicableStatusCount]; ok {
		display = append(display, ApplicableStatusCount.Format(count))
	}
	if count, ok := displayData[NotApplicableStatusCount]; ok {
		display = append(display, NotApplicableStatusCount.Format(count))
	}
	return fmt.Sprintf(" (%s)", strings.Join(display, ", "))
}
