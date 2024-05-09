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
	Name               string         `json:"name,omitempty"`
	ScaScanResults     *ScaScanResult `json:"sca,omitempty"`
	IacScanResults     *SummaryCount  `json:"iac,omitempty"`
	SecretsScanResults *SummaryCount  `json:"secrets,omitempty"`
	SastScanResults    *SummaryCount  `json:"sast,omitempty"`
}

type SummaryCount map[string]int

func (sc SummaryCount) GetTotal() int {
	total := 0
	for _, count := range sc {
		total += count
	}
	return total
}

func (s *ScanSummaryResult) HasIssues() bool {
	return s.GetTotalIssueCount() > 0
}

func (s *ScanSummaryResult) GetTotalIssueCount() (total int) {
	if s.ScaScanResults != nil {
		total += s.ScaScanResults.GetTotalIssueCount()
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

func (s *ScanSummaryResult) GetSubScansCountWithIssues() (count int) {
	if s.ScaScanResults != nil && s.ScaScanResults.GetTotalIssueCount() > 0 {
		count++
	}
	if s.IacScanResults != nil && s.IacScanResults.GetTotal() > 0 {
		count++
	}
	if s.SecretsScanResults != nil && s.SecretsScanResults.GetTotal() > 0 {
		count++
	}
	if s.SastScanResults != nil && s.SastScanResults.GetTotal() > 0 {
		count++
	}
	return
}

type ScaScanResult struct {
	BySeverity           SummaryCount            `json:"summaryBySeverity"`
	ByContextualAnalysis map[string]SummaryCount `json:"summaryByContextualAnalysis,omitempty"`
}

func (s *ScaScanResult) GetTotalIssueCount() (total int) {
	return s.BySeverity.GetTotal()
}
