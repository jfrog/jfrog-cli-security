package formats

import (
	"github.com/jfrog/gofrog/datastructures"
)

const (
	IacResult   SummaryResultType = "IAC"
	SecretsResult SummaryResultType = "Secrets"
	SastResult  SummaryResultType = "SAST"
	ScaSecurityResult SummaryResultType = "SCA"
	ScaLicenseResult SummaryResultType = "License"
	ScaOperationalResult SummaryResultType = "Operational"

	NoStatus = ""
)
type SummaryResultType string

func (srt SummaryResultType) String() string {
	return string(srt)
}

type ResultsSummary struct {
	BaseJfrogUrl string			 `json:"base_jfrog_url,omitempty"`
	Scans []ScanSummary `json:"scans"`
}

type ScanSummary struct {
	Target          string                      `json:"target"`
	Vulnerabilities *ScanResultSummary		  `json:"vulnerabilities,omitempty"`
	Violations      *ScanViolationsSummary		  `json:"violations,omitempty"`
	CuratedPackages *CuratedPackages            `json:"curated,omitempty"`
}

type ScanResultSummary struct {
	ScaResults    *ScaScanResultSummary `json:"sca,omitempty"`
	IacResults    *ResultSummary  `json:"iac,omitempty"`
	SecretsResults *ResultSummary  `json:"secrets,omitempty"`
	SastResults   *ResultSummary  `json:"sast,omitempty"`
}

type ScanViolationsSummary struct {
	Watches []string `json:"watches,omitempty"`
	ScanResultSummary
}

type ScaScanResultSummary struct {
	Security ResultSummary `json:"security,omitempty"`
	License  ResultSummary `json:"license,omitempty"`
	OperationalRisk ResultSummary `json:"operational_risk,omitempty"`
}

type CuratedPackages struct {
	Blocked  []BlockedPackages `json:"blocked,omitempty"`
	Approved int                  `json:"approved,omitempty"`
}

type BlockedPackages struct {
	Policy string `json:"policy,omitempty"`
	Condition string `json:"condition,omitempty"`
	Packages []string `json:"packages"`
}

type ResultSummary map[string]map[string]int

func (rs ResultSummary) GetTotal() (total int) {
	for _, count := range rs {
		for _, c := range count {
			total += c
		}
	}
	return
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

func (rs *ResultsSummary) getTotalVulnerabilities(filterTypes ...SummaryResultType) (total int) {
	for _, scan := range rs.Scans {
		if scan.Vulnerabilities != nil {
			total += getTotalIssues(scan.Vulnerabilities, filterTypes...)
		}
	}
	return
}

func (rs *ResultsSummary) getTotalViolations(filterTypes ...SummaryResultType) (total int) {
	for _, scan := range rs.Scans {
		if scan.Violations != nil {
			total += getTotalIssues(&scan.Violations.ScanResultSummary, filterTypes...)
		}
	}
	return
}

func getTotalIssues(summary *ScanResultSummary, filterTypes ...SummaryResultType) (total int) {
	if summary == nil {
		return
	}
	return summary.GetTotal(filterTypes...)
}

































const (
	ScaScan     SummarySubScanType = "SCA"
	IacScan     SummarySubScanType = "IAC"
	SecretsScan SummarySubScanType = "Secrets"
	SastScan    SummarySubScanType = "SAST"

)
type SummarySubScanType string

type SummaryResults struct {
	BaseJfrogUrl string             `json:"base_jfrog_url,omitempty"`
	Scans []ScanSummaryResult `json:"scans"`
}

func (sr SummaryResults) GetTotalIssueCount() (total int) {
	for _, scan := range sr.Scans {
		total += scan.GetTotalIssueCount()
	}
	return
}

// Severity -> Status -> Count
type SeverityCount map[severityutils.Severity]map[string]int

func GetVulnerabilitiesSummaries(summaries ...SummaryResults) (vulnerabilitiesSummary *ScanVulnerabilitiesSummary) {
	scaResults := &ScanScaResult{}
	iacResults := &SummaryCount{}
	secretsResults := &SummaryCount{}
	sastResults := &SummaryCount{}
	for _, summary := range summaries {
		for _, scan := range summary.Scans {
			if scan.Vulnerabilities != nil {
				vulnerabilitiesSummaries = append(vulnerabilitiesSummaries, *scan.Vulnerabilities)
			}
		}
	}
	vulnerabilitiesSummary = &ScanVulnerabilitiesSummary{}
	
	return
}

func GetViolationSummaries(summaries ...SummaryResults) (violationsSummary *ScanSummaryViolations) {
	watches := []string{}
	scaResults := &ScanScaResult{}
	iacResults := &SummaryCount{}
	secretsResults := &SummaryCount{}
	sastResults := &SummaryCount{}
	for _, summary := range summaries {
		for _, scan := range summary.Scans {
			if scan.Violations != nil {
				violationsSummary = append(violationsSummary, *scan.Violations)
			}
		}
	}
	violationsSummary = &ScanSummaryViolations{Watches: watches}
	return
}

type ScanSummaryResult struct {
	Target          string                      `json:"target,omitempty"`
	CuratedPackages *CuratedPackages            `json:"curated,omitempty"`
	Violations      *ScanSummaryViolations        `json:"violations,omitempty"`
	Vulnerabilities *ScanVulnerabilitiesSummary `json:"vulnerabilities,omitempty"`
}

// type CuratedPackages struct {
// 	Blocked  TwoLevelSummaryCount `json:"blocked,omitempty"`
// 	Approved int                  `json:"approved,omitempty"`
// }

type ScanSummaryViolations struct {
	Watches []string `json:"watches,omitempty"`
	ScanVulnerabilitiesSummary
}

type ScanVulnerabilitiesSummary struct {
	ScaScanResults     *ScanScaResult `json:"sca,omitempty"`
	IacScanResults     *SummaryCount  `json:"iac,omitempty"`
	SecretsScanResults *SummaryCount  `json:"secrets,omitempty"`
	SastScanResults    *SummaryCount  `json:"sast,omitempty"`
}

// Returns a TwoLevelSummaryCount with the counts described in the summary
// Severity -> status -> Count
func (ss *ScanVulnerabilitiesSummary) GetSummaryDetails() (summary TwoLevelSummaryCount) {
	summary = TwoLevelSummaryCount{}
	if ss.ScaScanResults != nil {
		for severity, statusCount := range ss.ScaScanResults.SecurityFindings {
			if summary[severity] == nil {
				summary[severity] = statusCount
			} else {
				for status, count := range statusCount {	
					summary[severity][status] += count
				}
			}
		}
		if ss.ScaScanResults.LicenseFindings != nil {
			for severity, count := range *ss.ScaScanResults.LicenseFindings {
				if summary[severity] == nil {
					summary[severity] = SummaryCount{NoStatus: count}
				} else {
					summary[severity][NoStatus] += count
				}
			}
		}
		if ss.ScaScanResults.OperationalRiskFindings != nil {
			for severity, count := range *ss.ScaScanResults.OperationalRiskFindings {
				if summary[severity] == nil {
					summary[severity] = SummaryCount{NoStatus: count}
				} else {
					summary[severity][NoStatus] += count
				}
			}
		}
	}
	if ss.IacScanResults != nil {
		for severity, count := range *ss.IacScanResults {
			if summary[severity] == nil {
				summary[severity] = SummaryCount{NoStatus: count}
			} else {
				summary[severity][NoStatus] += count
			}
		}
	}
	if ss.SecretsScanResults != nil {
		for severity, count := range *ss.SecretsScanResults {
			if summary[severity] == nil {
				summary[severity] = SummaryCount{NoStatus: count}
			} else {
				summary[severity][NoStatus] += count
			}
		}
	}
	return
}

type ScanScaResult struct {
	ScanIds []string `json:"scan_ids,omitempty"`
	// Severity -> Applicable status -> Count
	SecurityFindings TwoLevelSummaryCount `json:"security_findings,omitempty"`
	// Severity -> Count
	LicenseFindings *SummaryCount `json:"license_findings,omitempty"`
	// Severity -> Count
	OperationalRiskFindings *SummaryCount `json:"operational_risk_findings,omitempty"`
}

func (s *ScanSummaryResult) HasIssues() bool {
	return s.HasViolations() || s.HasSecurityVulnerabilities() || s.HasBlockedCuration()
}

func (s *ScanSummaryResult) HasViolations() bool {
	return s.Violations.GetTotal() > 0
}

func (s *ScanSummaryResult) HasSecurityVulnerabilities() bool {
	return s.Vulnerabilities != nil && s.Vulnerabilities.GetTotalIssueCount() > 0
}

func (s *ScanSummaryResult) HasBlockedCuration() bool {
	return s.CuratedPackages != nil && s.CuratedPackages.Blocked.GetTotal() > 0
}

func (s *ScanSummaryResult) GetTotalIssueCount() (total int) {
	if s.Vulnerabilities != nil {
		total += s.Vulnerabilities.GetTotalIssueCount()
	}
	total += s.Violations.GetTotal()
	return

}

func (s *ScanSummaryResult) GetTotalViolationCount() (total int) {
	return s.Violations.GetTotal()
}

func (s *ScanVulnerabilitiesSummary) GetTotalUniqueIssueCount() (total int) {
	return s.getTotalIssueCount(true)
}

func (s *ScanVulnerabilitiesSummary) GetTotalIssueCount() (total int) {
	return s.getTotalIssueCount(false)
}

func (s *CuratedPackages) GetTotalPackages() int {
	return s.Approved + s.Blocked.GetCountOfKeys(false)
}

func (s *ScanVulnerabilitiesSummary) getTotalIssueCount(unique bool) (total int) {
	if s.ScaScanResults != nil {
		if unique {
			total += s.ScaScanResults.UniqueFindings
		} else {
			total += s.ScaScanResults.SummaryCount.GetTotal()
		}
	}
	if s.IacScanResults != nil {
		total += s.IacScanResults.GetTotal()
	}
	if s.SecretsScanResults != nil {
		total += s.SecretsScanResults.GetTotal()
	}
	if s.SastScanResults != nil {
		total += s.SastScanResults.GetTotal()
	}
	return
}

func (s *ScanVulnerabilitiesSummary) GetSubScansWithIssues() []SummarySubScanType {
	subScans := []SummarySubScanType{}
	if s.SecretsScanResults != nil && s.SecretsScanResults.GetTotal() > 0 {
		subScans = append(subScans, SecretsScan)
	}
	if s.SastScanResults != nil && s.SastScanResults.GetTotal() > 0 {
		subScans = append(subScans, SastScan)
	}
	if s.IacScanResults != nil && s.IacScanResults.GetTotal() > 0 {
		subScans = append(subScans, IacScan)
	}
	if s.ScaScanResults != nil && s.ScaScanResults.SummaryCount.GetTotal() > 0 {
		subScans = append(subScans, ScaScan)
	}
	return subScans
}

func (svs *ScanVulnerabilitiesSummary) GetSubScanTotalIssueCount(subScanType SummarySubScanType) (count int) {
	switch subScanType {
	case ScaScan:
		count = svs.ScaScanResults.SummaryCount.GetTotal()
	case IacScan:
		count = svs.IacScanResults.GetTotal()
	case SecretsScan:
		count = svs.SecretsScanResults.GetTotal()
	case SastScan:
		count = svs.SastScanResults.GetTotal()
	}
	return
}

// Severity -> Count
type SummaryCount map[string]int

func (sc SummaryCount) GetTotal() int {
	total := 0
	for _, count := range sc {
		total += count
	}
	return total
}

// Severity -> Applicable status -> Count
type TwoLevelSummaryCount map[string]SummaryCount

func (sc TwoLevelSummaryCount) GetTotal() (total int) {
	for _, count := range sc {
		total += count.GetTotal()
	}
	return
}

func (sc TwoLevelSummaryCount) GetCombinedLowerLevel() (oneLvlCounts SummaryCount) {
	oneLvlCounts = SummaryCount{}
	for firstLvl, secondLvl := range sc {
		for _, count := range secondLvl {
			oneLvlCounts[firstLvl] += count
		}
	}
	return
}

func (sc TwoLevelSummaryCount) GetCountOfKeys(firstLevel bool) int {
	if firstLevel {
		return len(sc)
	}
	count := datastructures.MakeSet[string]()
	for _, value := range sc {
		for key := range value {
			count.Add(key)
		}
	}
	return count.Size()
}
