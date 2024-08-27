package formats

import (
	"github.com/jfrog/gofrog/datastructures"
	"golang.org/x/exp/slices"
)

const (
	IacResult            SummaryResultType = "IAC"
	SecretsResult        SummaryResultType = "Secrets"
	SastResult           SummaryResultType = "SAST"
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
	Vulnerabilities *ScanResultSummary     `json:"vulnerabilities,omitempty"`
	Violations      *ScanViolationsSummary `json:"violations,omitempty"`
	CuratedPackages *CuratedPackages       `json:"curated,omitempty"`
}

type ScanResultSummary struct {
	ScaResults     *ScaScanResultSummary `json:"sca,omitempty"`
	IacResults     *ResultSummary        `json:"iac,omitempty"`
	SecretsResults *ResultSummary        `json:"secrets,omitempty"`
	SastResults    *ResultSummary        `json:"sast,omitempty"`
}

type ScanViolationsSummary struct {
	Watches []string `json:"watches,omitempty"`
	FailBuild bool `json:"fail_build,omitempty"`
	ScanResultSummary
}

type ScaScanResultSummary struct {
	ScanIds         []string        `json:"scan_ids,omitempty"`
	MoreInfoUrls   	[]string        `json:"more_info_urls,omitempty"`
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
	count := 0
	for _, blocked := range cp.Blocked {
		for _, c := range blocked.Packages {
			count += c
		}
	}
	return count
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
		urls = append(urls, srs.ScaResults.MoreInfoUrls...)
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
	return
}

func GetViolationSummaries(summaries ...ResultsSummary) (*ScanViolationsSummary) {
	if len(summaries) == 0 {
		return nil
	}
	violationsSummary := &ScanViolationsSummary{}
	watches := datastructures.MakeSet[string]()
	failBuild := false
	foundViolations := false
	for _, summary := range summaries {
		for _, scan := range summary.Scans {
			if scan.Violations == nil {
				continue
			}
			foundViolations = true
			watches.AddElements(scan.Violations.Watches...)
			failBuild = failBuild || scan.Violations.FailBuild
			extractIssuesToSummary(&scan.Violations.ScanResultSummary, &violationsSummary.ScanResultSummary)
		}
	}
	if !foundViolations {
		return nil
	}
	violationsSummary.Watches = watches.ToSlice()
	violationsSummary.FailBuild = failBuild
	return violationsSummary
}

func GetVulnerabilitiesSummaries(summaries ...ResultsSummary) (*ScanResultSummary) {
	if len(summaries) == 0 {
		return nil
	}
	vulnerabilitiesSummary := &ScanResultSummary{}
	foundVulnerabilities := false
	for _, summary := range summaries {
		for _, scan := range summary.Scans {
			if scan.Vulnerabilities == nil {
				continue
			}
			foundVulnerabilities = true
			extractIssuesToSummary(scan.Vulnerabilities, vulnerabilitiesSummary)
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





// const (
// 	ScaScan     SummarySubScanType = "SCA"
// 	IacScan     SummarySubScanType = "IAC"
// 	SecretsScan SummarySubScanType = "Secrets"
// 	SastScan    SummarySubScanType = "SAST"
// )

// type SummarySubScanType string

// type SummaryResults struct {
// 	BaseJfrogUrl string              `json:"base_jfrog_url,omitempty"`
// 	Scans        []ScanSummaryResult `json:"scans"`
// }

// func (sr SummaryResults) GetTotalIssueCount() (total int) {
// 	for _, scan := range sr.Scans {
// 		total += scan.GetTotalIssueCount()
// 	}
// 	return
// }

// // Severity -> Status -> Count
// type SeverityCount map[severityutils.Severity]map[string]int

// func GetVulnerabilitiesSummaries(summaries ...SummaryResults) (vulnerabilitiesSummary *ScanVulnerabilitiesSummary) {
// 	scaResults := &ScanScaResult{}
// 	iacResults := &SummaryCount{}
// 	secretsResults := &SummaryCount{}
// 	sastResults := &SummaryCount{}
// 	for _, summary := range summaries {
// 		for _, scan := range summary.Scans {
// 			if scan.Vulnerabilities != nil {
// 				vulnerabilitiesSummaries = append(vulnerabilitiesSummaries, *scan.Vulnerabilities)
// 			}
// 		}
// 	}
// 	vulnerabilitiesSummary = &ScanVulnerabilitiesSummary{}

// 	return
// }

// func GetViolationSummaries(summaries ...SummaryResults) (violationsSummary *ScanSummaryViolations) {
// 	watches := []string{}
// 	scaResults := &ScanScaResult{}
// 	iacResults := &SummaryCount{}
// 	secretsResults := &SummaryCount{}
// 	sastResults := &SummaryCount{}
// 	for _, summary := range summaries {
// 		for _, scan := range summary.Scans {
// 			if scan.Violations != nil {
// 				violationsSummary = append(violationsSummary, *scan.Violations)
// 			}
// 		}
// 	}
// 	violationsSummary = &ScanSummaryViolations{Watches: watches}
// 	return
// }

// type ScanSummaryResult struct {
// 	Target          string                      `json:"target,omitempty"`
// 	CuratedPackages *CuratedPackages            `json:"curated,omitempty"`
// 	Violations      *ScanSummaryViolations      `json:"violations,omitempty"`
// 	Vulnerabilities *ScanVulnerabilitiesSummary `json:"vulnerabilities,omitempty"`
// }

// // type CuratedPackages struct {
// // 	Blocked  TwoLevelSummaryCount `json:"blocked,omitempty"`
// // 	Approved int                  `json:"approved,omitempty"`
// // }

// type ScanSummaryViolations struct {
// 	Watches []string `json:"watches,omitempty"`
// 	ScanVulnerabilitiesSummary
// }

// type ScanVulnerabilitiesSummary struct {
// 	ScaScanResults     *ScanScaResult `json:"sca,omitempty"`
// 	IacScanResults     *SummaryCount  `json:"iac,omitempty"`
// 	SecretsScanResults *SummaryCount  `json:"secrets,omitempty"`
// 	SastScanResults    *SummaryCount  `json:"sast,omitempty"`
// }

// // Returns a TwoLevelSummaryCount with the counts described in the summary
// // Severity -> status -> Count
// func (ss *ScanVulnerabilitiesSummary) GetSummaryDetails() (summary TwoLevelSummaryCount) {
// 	summary = TwoLevelSummaryCount{}
// 	if ss.ScaScanResults != nil {
// 		for severity, statusCount := range ss.ScaScanResults.SecurityFindings {
// 			if summary[severity] == nil {
// 				summary[severity] = statusCount
// 			} else {
// 				for status, count := range statusCount {
// 					summary[severity][status] += count
// 				}
// 			}
// 		}
// 		if ss.ScaScanResults.LicenseFindings != nil {
// 			for severity, count := range *ss.ScaScanResults.LicenseFindings {
// 				if summary[severity] == nil {
// 					summary[severity] = SummaryCount{NoStatus: count}
// 				} else {
// 					summary[severity][NoStatus] += count
// 				}
// 			}
// 		}
// 		if ss.ScaScanResults.OperationalRiskFindings != nil {
// 			for severity, count := range *ss.ScaScanResults.OperationalRiskFindings {
// 				if summary[severity] == nil {
// 					summary[severity] = SummaryCount{NoStatus: count}
// 				} else {
// 					summary[severity][NoStatus] += count
// 				}
// 			}
// 		}
// 	}
// 	if ss.IacScanResults != nil {
// 		for severity, count := range *ss.IacScanResults {
// 			if summary[severity] == nil {
// 				summary[severity] = SummaryCount{NoStatus: count}
// 			} else {
// 				summary[severity][NoStatus] += count
// 			}
// 		}
// 	}
// 	if ss.SecretsScanResults != nil {
// 		for severity, count := range *ss.SecretsScanResults {
// 			if summary[severity] == nil {
// 				summary[severity] = SummaryCount{NoStatus: count}
// 			} else {
// 				summary[severity][NoStatus] += count
// 			}
// 		}
// 	}
// 	return
// }

// type ScanScaResult struct {
// 	ScanIds []string `json:"scan_ids,omitempty"`
// 	// Severity -> Applicable status -> Count
// 	SecurityFindings TwoLevelSummaryCount `json:"security_findings,omitempty"`
// 	// Severity -> Count
// 	LicenseFindings *SummaryCount `json:"license_findings,omitempty"`
// 	// Severity -> Count
// 	OperationalRiskFindings *SummaryCount `json:"operational_risk_findings,omitempty"`
// }

// func (s *ScanSummaryResult) HasIssues() bool {
// 	return s.HasViolations() || s.HasSecurityVulnerabilities() || s.HasBlockedCuration()
// }

// func (s *ScanSummaryResult) HasViolations() bool {
// 	return s.Violations.GetTotal() > 0
// }

// func (s *ScanSummaryResult) HasSecurityVulnerabilities() bool {
// 	return s.Vulnerabilities != nil && s.Vulnerabilities.GetTotalIssueCount() > 0
// }

// func (s *ScanSummaryResult) HasBlockedCuration() bool {
// 	return s.CuratedPackages != nil && s.CuratedPackages.Blocked.GetTotal() > 0
// }

// func (s *ScanSummaryResult) GetTotalIssueCount() (total int) {
// 	if s.Vulnerabilities != nil {
// 		total += s.Vulnerabilities.GetTotalIssueCount()
// 	}
// 	total += s.Violations.GetTotal()
// 	return

// }

// func (s *ScanSummaryResult) GetTotalViolationCount() (total int) {
// 	return s.Violations.GetTotal()
// }

// func (s *ScanVulnerabilitiesSummary) GetTotalUniqueIssueCount() (total int) {
// 	return s.getTotalIssueCount(true)
// }

// func (s *ScanVulnerabilitiesSummary) GetTotalIssueCount() (total int) {
// 	return s.getTotalIssueCount(false)
// }

// func (s *CuratedPackages) GetTotalPackages() int {
// 	return s.Approved + s.Blocked.GetCountOfKeys(false)
// }

// func (s *ScanVulnerabilitiesSummary) getTotalIssueCount(unique bool) (total int) {
// 	if s.ScaScanResults != nil {
// 		if unique {
// 			total += s.ScaScanResults.UniqueFindings
// 		} else {
// 			total += s.ScaScanResults.SummaryCount.GetTotal()
// 		}
// 	}
// 	if s.IacScanResults != nil {
// 		total += s.IacScanResults.GetTotal()
// 	}
// 	if s.SecretsScanResults != nil {
// 		total += s.SecretsScanResults.GetTotal()
// 	}
// 	if s.SastScanResults != nil {
// 		total += s.SastScanResults.GetTotal()
// 	}
// 	return
// }

// func (s *ScanVulnerabilitiesSummary) GetSubScansWithIssues() []SummarySubScanType {
// 	subScans := []SummarySubScanType{}
// 	if s.SecretsScanResults != nil && s.SecretsScanResults.GetTotal() > 0 {
// 		subScans = append(subScans, SecretsScan)
// 	}
// 	if s.SastScanResults != nil && s.SastScanResults.GetTotal() > 0 {
// 		subScans = append(subScans, SastScan)
// 	}
// 	if s.IacScanResults != nil && s.IacScanResults.GetTotal() > 0 {
// 		subScans = append(subScans, IacScan)
// 	}
// 	if s.ScaScanResults != nil && s.ScaScanResults.SummaryCount.GetTotal() > 0 {
// 		subScans = append(subScans, ScaScan)
// 	}
// 	return subScans
// }

// func (svs *ScanVulnerabilitiesSummary) GetSubScanTotalIssueCount(subScanType SummarySubScanType) (count int) {
// 	switch subScanType {
// 	case ScaScan:
// 		count = svs.ScaScanResults.SummaryCount.GetTotal()
// 	case IacScan:
// 		count = svs.IacScanResults.GetTotal()
// 	case SecretsScan:
// 		count = svs.SecretsScanResults.GetTotal()
// 	case SastScan:
// 		count = svs.SastScanResults.GetTotal()
// 	}
// 	return
// }

// // Severity -> Count
// type SummaryCount map[string]int

// func (sc SummaryCount) GetTotal() int {
// 	total := 0
// 	for _, count := range sc {
// 		total += count
// 	}
// 	return total
// }

// // Severity -> Applicable status -> Count
// type TwoLevelSummaryCount map[string]SummaryCount

// func (sc TwoLevelSummaryCount) GetTotal() (total int) {
// 	for _, count := range sc {
// 		total += count.GetTotal()
// 	}
// 	return
// }

// func (sc TwoLevelSummaryCount) GetCombinedLowerLevel() (oneLvlCounts SummaryCount) {
// 	oneLvlCounts = SummaryCount{}
// 	for firstLvl, secondLvl := range sc {
// 		for _, count := range secondLvl {
// 			oneLvlCounts[firstLvl] += count
// 		}
// 	}
// 	return
// }

// func (sc TwoLevelSummaryCount) GetCountOfKeys(firstLevel bool) int {
// 	if firstLevel {
// 		return len(sc)
// 	}
// 	count := datastructures.MakeSet[string]()
// 	for _, value := range sc {
// 		for key := range value {
// 			count.Add(key)
// 		}
// 	}
// 	return count.Size()
// }
