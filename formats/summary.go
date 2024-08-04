package formats

import (
	"github.com/jfrog/gofrog/datastructures"
)

const (
	ScaScan     SummarySubScanType = "SCA"
	IacScan     SummarySubScanType = "IAC"
	SecretsScan SummarySubScanType = "Secrets"
	SastScan    SummarySubScanType = "SAST"

	ViolationTypeSecurity        ViolationIssueType = "security"
	ViolationTypeLicense         ViolationIssueType = "license"
	ViolationTypeOperationalRisk ViolationIssueType = "operational_risk"
)

type SummarySubScanType string
type ViolationIssueType string

func (v ViolationIssueType) String() string {
	return string(v)
}

type SummaryResults struct {
	Scans []ScanSummaryResult `json:"scans"`
}

func (sr SummaryResults) GetTotalIssueCount() (total int) {
	for _, scan := range sr.Scans {
		total += scan.GetTotalIssueCount()
	}
	return
}

type ScanSummaryResult struct {
	Target          string                      `json:"target,omitempty"`
	Vulnerabilities *ScanVulnerabilitiesSummary `json:"vulnerabilities,omitempty"`
	Violations      TwoLevelSummaryCount        `json:"violations,omitempty"`
	CuratedPackages *CuratedPackages            `json:"curated,omitempty"`
}

type CuratedPackages struct {
	Blocked  TwoLevelSummaryCount `json:"blocked,omitempty"`
	Approved int                  `json:"approved,omitempty"`
}

type ScanVulnerabilitiesSummary struct {
	ScaScanResults     *ScanScaResult `json:"sca,omitempty"`
	IacScanResults     *SummaryCount  `json:"iac,omitempty"`
	SecretsScanResults *SummaryCount  `json:"secrets,omitempty"`
	SastScanResults    *SummaryCount  `json:"sast,omitempty"`
}

type ScanScaResult struct {
	SummaryCount   TwoLevelSummaryCount `json:"sca,omitempty"`
	UniqueFindings int                  `json:"unique_findings,omitempty"`
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
