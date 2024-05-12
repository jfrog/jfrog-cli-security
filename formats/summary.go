package formats

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
	Name               string           `json:"name,omitempty"`
	ScaScanResults     *ScaSummaryCount `json:"sca,omitempty"`
	IacScanResults     *SummaryCount    `json:"iac,omitempty"`
	SecretsScanResults *SummaryCount    `json:"secrets,omitempty"`
	SastScanResults    *SummaryCount    `json:"sast,omitempty"`
}

type SummarySubScanType string

const (
	ScaScan     SummarySubScanType = "SCA vulnerabilities"
	IacScan     SummarySubScanType = "IAC vulnerabilities"
	SecretsScan SummarySubScanType = "Secrets"
	SastScan    SummarySubScanType = "SAST vulnerabilities"
)

type SummaryCount map[string]int

func (sc SummaryCount) GetTotal() int {
	total := 0
	for _, count := range sc {
		total += count
	}
	return total
}

type ScaSummaryCount map[string]SummaryCount

func (sc ScaSummaryCount) GetTotal() (total int) {
	for _, count := range sc {
		total += count.GetTotal()
	}
	return
}

func (sc ScaSummaryCount) GetSeverityCountsWithoutStatus() (severityCounts SummaryCount) {
	severityCounts = SummaryCount{}
	for severity, statusCounts := range sc {
		for _, count := range statusCounts {
			severityCounts[severity] += count
		}
	}
	return
}

func (s *ScanSummaryResult) HasIssues() bool {
	return s.GetTotalIssueCount() > 0
}

func (s *ScanSummaryResult) GetTotalIssueCount() (total int) {
	if s.ScaScanResults != nil {
		total += s.ScaScanResults.GetTotal()
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

func (s *ScanSummaryResult) GetSubScansWithIssues() (subScans []SummarySubScanType) {
	if s.SecretsScanResults != nil && s.SecretsScanResults.GetTotal() > 0 {
		subScans = append(subScans, SecretsScan)
	}
	if s.SastScanResults != nil && s.SastScanResults.GetTotal() > 0 {
		subScans = append(subScans, SastScan)
	}
	if s.IacScanResults != nil && s.IacScanResults.GetTotal() > 0 {
		subScans = append(subScans, IacScan)
	}
	// Must be last for GUI to display contexual-analysis details as well
	if s.ScaScanResults != nil && s.ScaScanResults.GetTotal() > 0 {
		subScans = append(subScans, ScaScan)
	}
	return
}

func (s *ScanSummaryResult) GetSubScanTotalIssueCount(subScanType SummarySubScanType) (count int) {
	switch subScanType {
	case ScaScan:
		count = s.ScaScanResults.GetTotal()
	case IacScan:
		count = s.IacScanResults.GetTotal()
	case SecretsScan:
		count = s.SecretsScanResults.GetTotal()
	case SastScan:
		count = s.SastScanResults.GetTotal()
	}
	return
}

// type ScaScanResult struct {
// 	BySeverity           SummaryCount            `json:"summaryBySeverity"`
// 	ByContextualAnalysis map[string]SummaryCount `json:"summaryByContextualAnalysis,omitempty"`
// }

// func (s *ScaScanResult) GetTotalIssueCount() (total int) {
// 	return s.BySeverity.GetTotal()
// }
