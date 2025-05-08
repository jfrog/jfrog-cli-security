package formats

import (
	"github.com/jfrog/gofrog/datastructures"
	"golang.org/x/exp/slices"
)

const (
	IacResult            SummaryResultType = "IAC"
	SecretsResult        SummaryResultType = "Secrets"
	SastResult           SummaryResultType = "SAST"
	MaliciousResult      SummaryResultType = "MaliciousCode"
	ScaResult            SummaryResultType = "SCA"
	ScaSecurityResult    SummaryResultType = "Security"
	ScaLicenseResult     SummaryResultType = "License"
	ScaOperationalResult SummaryResultType = "Operational"

	NoStatus = ""
)

type SummaryResultType string

func (srt SummaryResultType) String() string {
	return string(srt)
}

type ResultsSummary struct {
	Scans []ScanSummary `json:"scans"`
}

type ScanSummary struct {
	Target          string                 `json:"target"`
	Name            string                 `json:"name,omitempty"`
	Vulnerabilities *ScanResultSummary     `json:"vulnerabilities,omitempty"`
	Violations      *ScanViolationsSummary `json:"violations,omitempty"`
	CuratedPackages *CuratedPackages       `json:"curated,omitempty"`
}

type ScanResultSummary struct {
	ScaResults       *ScaScanResultSummary `json:"sca,omitempty"`
	IacResults       *ResultSummary        `json:"iac,omitempty"`
	SecretsResults   *ResultSummary        `json:"secrets,omitempty"`
	SastResults      *ResultSummary        `json:"sast,omitempty"`
	MaliciousResults *ResultSummary        `json:"malicious_code,omitempty"`
}

type ScanViolationsSummary struct {
	Watches   []string `json:"watches,omitempty"`
	FailBuild bool     `json:"fail_build,omitempty"`
	ScanResultSummary
}

type ScaScanResultSummary struct {
	ScanIds         []string      `json:"scan_ids,omitempty"`
	MoreInfoUrls    []string      `json:"more_info_urls,omitempty"`
	Security        ResultSummary `json:"security,omitempty"`
	License         ResultSummary `json:"license,omitempty"`
	OperationalRisk ResultSummary `json:"operational_risk,omitempty"`
}

type CuratedPackages struct {
	Blocked      []BlockedPackages `json:"blocked,omitempty"`
	PackageCount int               `json:"num_packages,omitempty"`
}

type BlockedPackages struct {
	Policy    string         `json:"policy,omitempty"`
	Condition string         `json:"condition,omitempty"`
	Packages  map[string]int `json:"packages"`
}

func (cp *CuratedPackages) GetApprovedCount() int {
	return cp.PackageCount - cp.GetBlockedCount()
}

func (cp *CuratedPackages) GetBlockedCount() int {
	parsed := datastructures.MakeSet[string]()
	for _, blocked := range cp.Blocked {
		for packageId := range blocked.Packages {
			if parsed.Exists(packageId) {
				continue
			}
			parsed.Add(packageId)
		}
	}
	return parsed.Size()
}

// Severity -> status -> Count
type ResultSummary map[string]map[string]int

func (rs ResultSummary) GetTotal(filterSeverities ...string) (total int) {
	for severity, count := range rs {
		if len(filterSeverities) > 0 && !slices.Contains(filterSeverities, severity) {
			continue
		}
		for _, c := range count {
			total += c
		}
	}
	return
}

func (rs *ResultsSummary) HasViolations() bool {
	for _, scan := range rs.Scans {
		if scan.HasViolations() {
			return true
		}
	}
	return false
}

func (rs *ResultsSummary) GetTotalVulnerabilities(filterTypes ...SummaryResultType) (total int) {
	for _, scan := range rs.Scans {
		if scan.Vulnerabilities != nil {
			total += scan.Vulnerabilities.GetTotal(filterTypes...)
		}
	}
	return
}

func (rs *ResultsSummary) GetTotalViolations(filterTypes ...SummaryResultType) (total int) {
	for _, scan := range rs.Scans {
		if scan.Violations != nil {
			total += scan.Violations.GetTotal(filterTypes...)
		}
	}
	return
}

func (sc *ScanSummary) HasCuratedPackages() bool {
	return sc.CuratedPackages != nil
}

func (sc *ScanSummary) HasBlockedPackages() bool {
	return sc.CuratedPackages != nil && len(sc.CuratedPackages.Blocked) > 0
}

func (sc *ScanSummary) HasViolations() bool {
	return sc.Violations != nil && sc.Violations.GetTotal() > 0
}

func (sc *ScanSummary) HasVulnerabilities() bool {
	return sc.Vulnerabilities != nil && sc.Vulnerabilities.GetTotal() > 0
}

func (sc *ScanSummary) GetScanIds() (scanIds []string) {
	if sc.Vulnerabilities != nil {
		scanIds = append(scanIds, sc.Vulnerabilities.GetScanIds()...)
	}
	if sc.Violations != nil {
		scanIds = append(scanIds, sc.Violations.GetScanIds()...)
	}
	return
}

func (srs *ScanResultSummary) GetMoreInfoUrls() (urls []string) {
	if srs.ScaResults != nil {
		for _, url := range srs.ScaResults.MoreInfoUrls {
			if url != "" {
				urls = append(urls, url)
			}
		}
	}
	return
}

func (srs *ScanResultSummary) GetScanIds() (scanIds []string) {
	if srs.ScaResults != nil {
		scanIds = append(scanIds, srs.ScaResults.ScanIds...)
	}
	return
}

func (srs *ScanResultSummary) HasIssues() bool {
	return srs.GetTotal() > 0
}

func (srs *ScanResultSummary) GetTotal(filterTypes ...SummaryResultType) (total int) {
	if srs.IacResults != nil && isFilterApply(IacResult, filterTypes) {
		total += srs.IacResults.GetTotal()
	}
	if srs.SecretsResults != nil && isFilterApply(SecretsResult, filterTypes) {
		total += srs.SecretsResults.GetTotal()
	}
	if srs.SastResults != nil && isFilterApply(SastResult, filterTypes) {
		total += srs.SastResults.GetTotal()
	}
	if srs.MaliciousResults != nil && isFilterApply(MaliciousResult, filterTypes) {
		total += srs.MaliciousResults.GetTotal()
	}
	if srs.ScaResults == nil {
		return
	}
	if isFilterApply(ScaSecurityResult, filterTypes) {
		total += srs.ScaResults.Security.GetTotal()
	}
	if isFilterApply(ScaLicenseResult, filterTypes) {
		total += srs.ScaResults.License.GetTotal()
	}
	if isFilterApply(ScaOperationalResult, filterTypes) {
		total += srs.ScaResults.OperationalRisk.GetTotal()
	}
	return
}

func isFilterApply(key SummaryResultType, filterTypes []SummaryResultType) bool {
	if len(filterTypes) == 0 {
		return true
	}
	for _, filterType := range filterTypes {
		if key == filterType {
			return true
		}
	}
	return false
}

// Returns a ResultSummary with the counts described in the summary
// Severity -> status -> Count
func (ss *ScanResultSummary) GetSummaryBySeverity() (summary ResultSummary) {
	summary = ResultSummary{}
	if ss.ScaResults != nil {
		summary = MergeResultSummaries(summary, ss.ScaResults.Security)
		summary = MergeResultSummaries(summary, ss.ScaResults.License)
		summary = MergeResultSummaries(summary, ss.ScaResults.OperationalRisk)
	}
	if ss.IacResults != nil {
		summary = MergeResultSummaries(summary, *ss.IacResults)
	}
	if ss.SecretsResults != nil {
		summary = MergeResultSummaries(summary, *ss.SecretsResults)
	}
	if ss.SastResults != nil {
		summary = MergeResultSummaries(summary, *ss.SastResults)
	}
	if ss.MaliciousResults != nil {
		summary = MergeResultSummaries(summary, *ss.MaliciousResults)
	}
	return
}

func GetViolationSummaries(summaries ...ResultsSummary) *ScanViolationsSummary {
	if len(summaries) == 0 {
		return nil
	}
	violationsSummary := &ScanViolationsSummary{}
	watches := datastructures.MakeSet[string]()
	failBuild := false
	foundViolations := false
	for _, summary := range summaries {
		for i := range summary.Scans {
			if summary.Scans[i].Violations == nil {
				continue
			}
			foundViolations = true
			watches.AddElements(summary.Scans[i].Violations.Watches...)
			failBuild = failBuild || summary.Scans[i].Violations.FailBuild
			extractIssuesToSummary(&summary.Scans[i].Violations.ScanResultSummary, &violationsSummary.ScanResultSummary)
		}
	}
	if !foundViolations {
		return nil
	}
	violationsSummary.Watches = watches.ToSlice()
	violationsSummary.FailBuild = failBuild
	return violationsSummary
}

func GetVulnerabilitiesSummaries(summaries ...ResultsSummary) *ScanResultSummary {
	if len(summaries) == 0 {
		return nil
	}
	vulnerabilitiesSummary := &ScanResultSummary{}
	foundVulnerabilities := false
	for _, summary := range summaries {
		for i := range summary.Scans {
			if summary.Scans[i].Vulnerabilities == nil {
				continue
			}
			foundVulnerabilities = true
			extractIssuesToSummary(summary.Scans[i].Vulnerabilities, vulnerabilitiesSummary)
		}
	}
	if !foundVulnerabilities {
		return nil
	}
	return vulnerabilitiesSummary
}

func extractIssuesToSummary(issues *ScanResultSummary, destination *ScanResultSummary) {
	if issues.ScaResults != nil {
		if destination.ScaResults == nil {
			destination.ScaResults = &ScaScanResultSummary{}
		}
		destination.ScaResults.ScanIds = append(destination.ScaResults.ScanIds, issues.ScaResults.ScanIds...)
		destination.ScaResults.MoreInfoUrls = append(destination.ScaResults.MoreInfoUrls, issues.ScaResults.MoreInfoUrls...)
		if issues.ScaResults.Security.GetTotal() > 0 {
			destination.ScaResults.Security = MergeResultSummaries(destination.ScaResults.Security, issues.ScaResults.Security)
		}
		if issues.ScaResults.License.GetTotal() > 0 {
			destination.ScaResults.License = MergeResultSummaries(destination.ScaResults.License, issues.ScaResults.License)
		}
		if issues.ScaResults.OperationalRisk.GetTotal() > 0 {
			destination.ScaResults.OperationalRisk = MergeResultSummaries(destination.ScaResults.OperationalRisk, issues.ScaResults.OperationalRisk)
		}
	}
	if issues.IacResults != nil {
		destination.IacResults = mergeResultSummariesPointers(destination.IacResults, issues.IacResults)
	}
	if issues.SecretsResults != nil {
		destination.SecretsResults = mergeResultSummariesPointers(destination.SecretsResults, issues.SecretsResults)
	}
	if issues.SastResults != nil {
		destination.SastResults = mergeResultSummariesPointers(destination.SastResults, issues.SastResults)
	}
	if issues.MaliciousResults != nil {
		destination.MaliciousResults = mergeResultSummariesPointers(destination.MaliciousResults, issues.MaliciousResults)
	}
}

func mergeResultSummariesPointers(summaries ...*ResultSummary) (merged *ResultSummary) {
	toMerge := []ResultSummary{}
	for _, summary := range summaries {
		if summary != nil {
			toMerge = append(toMerge, *summary)
		}
	}
	result := MergeResultSummaries(toMerge...)
	return &result
}

func MergeResultSummaries(summaries ...ResultSummary) (merged ResultSummary) {
	merged = ResultSummary{}
	for _, summary := range summaries {
		for severity, statusCount := range summary {
			if _, ok := merged[severity]; !ok {
				merged[severity] = statusCount
			} else {
				for status, count := range statusCount {
					merged[severity][status] += count
				}
			}
		}
	}
	return
}
