package utils

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"
)

type Results struct {
	ScaResults  []ScaScanResult
	XrayVersion string
	ScaError    error

	ExtendedScanResults *ExtendedScanResults
	JasError            error

	MultiScanId string
}

func NewAuditResults() *Results {
	return &Results{ExtendedScanResults: &ExtendedScanResults{}}
}

func (r *Results) GetScaScansXrayResults() (results []services.ScanResponse) {
	for _, scaResult := range r.ScaResults {
		results = append(results, scaResult.XrayResults...)
	}
	return
}

func (r *Results) GetScaScannedTechnologies() []coreutils.Technology {
	technologies := datastructures.MakeSet[coreutils.Technology]()
	for _, scaResult := range r.ScaResults {
		technologies.Add(scaResult.Technology)
	}
	return technologies.ToSlice()
}

func (r *Results) IsMultipleProject() bool {
	if len(r.ScaResults) == 0 {
		return false
	}
	if len(r.ScaResults) == 1 {
		if r.ScaResults[0].IsMultipleRootProject == nil {
			return false
		}
		return *r.ScaResults[0].IsMultipleRootProject
	}
	return true
}

func (r *Results) IsScaIssuesFound() bool {
	for _, scan := range r.ScaResults {
		if scan.HasInformation() {
			return true
		}
	}
	return false
}

func (r *Results) getScaScanResultByTarget(target string) *ScaScanResult {
	for _, scan := range r.ScaResults {
		if scan.Target == target {
			return &scan
		}
	}
	return nil

}

func (r *Results) IsIssuesFound() bool {
	if r.IsScaIssuesFound() {
		return true
	}
	if r.ExtendedScanResults.IsIssuesFound() {
		return true
	}
	return false
}

// Counts the total number of unique findings in the provided results.
// A unique SCA finding is identified by a unique pair of vulnerability's/violation's issueId and component id or by a result returned from one of JAS scans.
func (r *Results) CountScanResultsFindings() (total int) {
	return formats.SummaryResults{Scans: r.getScanSummaryByTargets()}.GetTotalIssueCount()
}

func (r *Results) GetSummary() (summary formats.SummaryResults) {
	if len(r.ScaResults) <= 1 {
		summary.Scans = r.getScanSummaryByTargets()
		return
	}
	for _, scaScan := range r.ScaResults {
		summary.Scans = append(summary.Scans, r.getScanSummaryByTargets(scaScan.Target)...)
	}
	return
}

func (r *Results) getScanSummaryByTargets(targets ...string) (summaries []formats.ScanSummaryResult) {
	if len(targets) == 0 {
		// No filter, one scan summary for all targets
		summaries = append(summaries, getScanSummary(r.ExtendedScanResults, r.ScaResults...))
		return
	}
	for _, target := range targets {
		// Get target sca results
		targetScaResults := []ScaScanResult{}
		if targetScaResult := r.getScaScanResultByTarget(target); targetScaResult != nil {
			targetScaResults = append(targetScaResults, *targetScaResult)
		}
		// Get target extended results
		targetExtendedResults := r.ExtendedScanResults
		if targetExtendedResults != nil {
			targetExtendedResults = targetExtendedResults.GetResultsForTarget(target)
		}
		summaries = append(summaries, getScanSummary(targetExtendedResults, targetScaResults...))
	}
	return
}

type ScaScanResult struct {
	// Could be working directory (audit), file path (binary scan) or build name+number (build scan)
	Target                string                  `json:"Target"`
	Technology            coreutils.Technology    `json:"Technology,omitempty"`
	XrayResults           []services.ScanResponse `json:"XrayResults,omitempty"`
	Descriptors           []string                `json:"Descriptors,omitempty"`
	IsMultipleRootProject *bool                   `json:"IsMultipleRootProject,omitempty"`
}

func (s ScaScanResult) HasInformation() bool {
	for _, scan := range s.XrayResults {
		if len(scan.Vulnerabilities) > 0 || len(scan.Violations) > 0 || len(scan.Licenses) > 0 {
			return true
		}
	}
	return false
}

type ExtendedScanResults struct {
	ApplicabilityScanResults []*sarif.Run
	SecretsScanResults       []*sarif.Run
	IacScanResults           []*sarif.Run
	SastScanResults          []*sarif.Run
	EntitledForJas           bool
}

func (e *ExtendedScanResults) IsIssuesFound() bool {
	return GetResultsLocationCount(e.ApplicabilityScanResults...) > 0 ||
		GetResultsLocationCount(e.SecretsScanResults...) > 0 ||
		GetResultsLocationCount(e.IacScanResults...) > 0 ||
		GetResultsLocationCount(e.SastScanResults...) > 0
}

func (e *ExtendedScanResults) GetResultsForTarget(target string) (result *ExtendedScanResults) {
	return &ExtendedScanResults{
		ApplicabilityScanResults: GetRunsByWorkingDirectory(target, e.ApplicabilityScanResults...),
		SecretsScanResults:       GetRunsByWorkingDirectory(target, e.SecretsScanResults...),
		IacScanResults:           GetRunsByWorkingDirectory(target, e.IacScanResults...),
		SastScanResults:          GetRunsByWorkingDirectory(target, e.SastScanResults...),
	}
}

// Move to result writer

func GetSummaryString(summaries ...formats.SummaryResults) (str string, err error) {
	parsed := 0
	singleScan := isSingleCommandAndScan(summaries...)
	wd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	for _, summary := range summaries {
		if !singleScan {
			updateSummaryNameToRelativePath(&summary, wd)
		}
		for _, scan := range summary.Scans {
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
	if !summary.HasIssues() {
		if singleData {
			return "✅ No vulnerabilities were found"
		}
		return fmt.Sprintf("✅ %s", summary.Name)
	}
	// Handle display of issues
	content = "❌"
	if !singleData {
		content += fmt.Sprintf(" %s:", summary.Name)
	}
	content += " Found"
	subScansWithIssues := summary.GetSubScansWithIssues()
	if len(subScansWithIssues) == 1 {
		content += getSubScanSummaryString(summary, subScansWithIssues[0])
		return
	}
	// Multiple sub scans with issues
	content += fmt.Sprintf(" %d vulnerabilities\n", summary.GetTotalIssueCount())
	content += getSubScanSummaryString(summary, subScansWithIssues...)
	return
}

func getSummaryListItemPrefix(index, total, subListLevel int) (content string) {
	for i := 0; i < subListLevel; i++ {
		content += "    "
	}
	if subListLevel == 0 && total < 2 {
		return " "
	}
	if index == total-1 {
		// TODO: should get this for severity (only one) with applicable data (at least one)
		content += "└── "
		return
	}
	content += "├── "
	return
}

func getSubScanSummaryCountsString(summary formats.ScanSummaryResult, subScanType formats.SummarySubScanType) (content string) {
	switch subScanType {
	case formats.ScaScan:
		content += GetScaSummaryCountString(*summary.ScaScanResults)
	case formats.IacScan:
		content += GetSummaryCountString(*summary.IacScanResults)
	case formats.SecretsScan:
		content += GetSummaryCountString(*summary.SecretsScanResults)
	case formats.SastScan:
		content += GetSummaryCountString(*summary.SastScanResults)
	}
	return
}

func hasApplicableData(summary formats.ScaSummaryCount) bool {
	for _, statuses := range summary {
		sorted := getSortedKeysToDisplay(maps.Keys(statuses)...)
		for _, status := range sorted {
			if _, ok := statuses[status]; ok && statuses[status] > 0 {
				return true
			}
		}
	}
	return false
}

func GetScaSummaryCountString(summary formats.ScaSummaryCount) (content string) {
	severityCount := len(summary)
	if severityCount == 0 {
		return
	}
	if !hasApplicableData(summary) {
		return GetSummaryCountString(summary.GetSeverityCountsWithoutStatus())
	}
	// Display contextual-analysis details
	keys := getSortedKeysToDisplay(maps.Keys(summary)...)
	for i, severity := range keys {
		statusCounts := summary[severity]
		content += fmt.Sprintf("\n%s%d %s%s",
			getSummaryListItemPrefix(i, severityCount, 1),
			statusCounts.GetTotal(),
			severity,
			GetSummaryCountString(statusCounts),
		)
	}
	return
}

func getSortedKeysToDisplay(keys ...string) (sorted []string) {
	if len(keys) == 0 {
		return
	}
	keysSet := datastructures.MakeSetFromElements(keys...)
	allowedSorted := []string{"Critical", "High", "Medium", "Low", "Unknown", string(Applicable), string(NotApplicable)}
	for _, key := range allowedSorted {
		if keysSet.Exists(key) {
			sorted = append(sorted, key)
		}
	}
	return
}

func GetSummaryCountString(summary formats.SummaryCount) string {
	if len(summary) == 0 {
		return ""
	}
	// sort and filter
	keys := getSortedKeysToDisplay(maps.Keys(summary)...)
	if len(keys) == 0 {
		return ""
	}
	content := ""
	for i, key := range keys {
		if i > 0 {
			content += ", "
		}
		content += fmt.Sprintf("%d %s", summary[key], key)
	}
	return fmt.Sprintf(" (%s)", content)
}

func updateSummaryNameToRelativePath(summary *formats.SummaryResults, wd string) {
	for i, scan := range summary.Scans {
		if scan.Name == "" {
			continue
		}
		if !strings.HasPrefix(scan.Name, wd) {
			continue
		}
		if scan.Name == wd {
			summary.Scans[i].Name = filepath.Base(wd)
		}
		summary.Scans[i].Name = strings.TrimPrefix(scan.Name, wd)
	}
	return
}

func getSubScanSummaryString(summary formats.ScanSummaryResult, subScanTypes ...formats.SummarySubScanType) (content string) {
	totalSubScans := len(subScanTypes)
	for i, subScanType := range subScanTypes {
		// Prefix
		if i > 0 {
			content += "\n"
		}
		content += fmt.Sprintf("%s%d ", getSummaryListItemPrefix(i, totalSubScans, 0), summary.GetSubScanTotalIssueCount(subScanType))
		switch subScanType {
		case formats.ScaScan:
			content += "SCA vulnerabilities"
		case formats.IacScan:
			content += "IAC vulnerabilities"
		case formats.SecretsScan:
			content += "Secrets"
		case formats.SastScan:
			content += "SAST vulnerabilities"
		}
		content += getSubScanSummaryCountsString(summary, subScanType)
	}
	return
}

func getScanSummary(extendedScanResults *ExtendedScanResults, scaResults ...ScaScanResult) (summary formats.ScanSummaryResult) {
	if len(scaResults) == 1 {
		summary.Name = scaResults[0].Target
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
				applicableStatus = ConvertToApplicabilityStatus(applicableInfo.Status)
			}
			uniqueFindings[cveId+compId] = SeverityWithApplicable{SeverityInfo: GetSeverity(severity, applicableStatus), ApplicabilityStatus: applicableStatus}
		}
	}
	return
}

func getScaSummaryResults(scaScanResults *[]ScaScanResult, applicableRuns ...*sarif.Run) *formats.ScaSummaryCount {
	uniqueFindings := map[string]SeverityWithApplicable{}
	// hasApplicableRuns := len(applicableRuns) > 0
	if len(*scaScanResults) == 0 {
		return nil
	}
	// Aggregate unique findings
	for _, scaResult := range *scaScanResults {
		for _, xrayResult := range scaResult.XrayResults {
			for _, vulnerability := range xrayResult.Vulnerabilities {
				vulUniqueFindings := getUniqueVulnerabilitiesInfo(vulnerability.Cves, vulnerability.IssueId, vulnerability.Severity, vulnerability.Components, applicableRuns...)
				for key, value := range vulUniqueFindings {
					uniqueFindings[key] = value
				}
			}
			for _, violation := range xrayResult.Violations {
				vioUniqueFindings := getUniqueVulnerabilitiesInfo(violation.Cves, violation.IssueId, violation.Severity, violation.Components, applicableRuns...)
				for key, value := range vioUniqueFindings {
					uniqueFindings[key] = value
				}
			}
		}
	}
	// Create summary
	summary := formats.ScaSummaryCount{}
	for _, severityWithApplicable := range uniqueFindings {
		severity := severityWithApplicable.SeverityInfo.Severity
		status := severityWithApplicable.ApplicabilityStatus.String()
		// if status == NotScanned.String() {
		// 	status = "Not Scanned"
		// }
		if _, ok := summary[severity]; !ok {
			summary[severity] = formats.SummaryCount{}
		}
		summary[severity][status]++
	}
	return &summary
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
