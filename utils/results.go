package utils

import (
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type Results struct {
	ResultType  CommandType
	ScaResults  []*ScaScanResult
	XrayVersion string
	ScansErr    error

	ExtendedScanResults *ExtendedScanResults

	MultiScanId string
}

func NewAuditResults(resultType CommandType) *Results {
	return &Results{ResultType: resultType, ExtendedScanResults: &ExtendedScanResults{}}
}

func (r *Results) GetScaScansXrayResults() (results []services.ScanResponse) {
	for _, scaResult := range r.ScaResults {
		results = append(results, scaResult.XrayResults...)
	}
	return
}

func (r *Results) GetScaScannedTechnologies() []techutils.Technology {
	technologies := datastructures.MakeSet[techutils.Technology]()
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
			return scan
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
func (r *Results) CountScanResultsFindings(includeVulnerabilities, includeViolations bool) (total int) {
	summary := formats.ResultsSummary{Scans: GetScanSummaryByTargets(r, includeVulnerabilities, includeViolations)}
	if summary.HasViolations() {
		return summary.GetTotalViolations()
	}
	return summary.GetTotalVulnerabilities()
}

type ScaScanResult struct {
	// Could be working directory (audit), file path (binary scan) or build name+number (build scan)
	Target                string                  `json:"Target"`
	Name                  string                  `json:"Name,omitempty"`
	Technology            techutils.Technology    `json:"Technology,omitempty"`
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
	return sarifutils.GetResultsLocationCount(e.ApplicabilityScanResults...) > 0 ||
		sarifutils.GetResultsLocationCount(e.SecretsScanResults...) > 0 ||
		sarifutils.GetResultsLocationCount(e.IacScanResults...) > 0 ||
		sarifutils.GetResultsLocationCount(e.SastScanResults...) > 0
}

func (e *ExtendedScanResults) GetResultsForTarget(target string) (result *ExtendedScanResults) {
	return &ExtendedScanResults{
		ApplicabilityScanResults: sarifutils.GetRunsByWorkingDirectory(target, e.ApplicabilityScanResults...),
		SecretsScanResults:       sarifutils.GetRunsByWorkingDirectory(target, e.SecretsScanResults...),
		IacScanResults:           sarifutils.GetRunsByWorkingDirectory(target, e.IacScanResults...),
		SastScanResults:          sarifutils.GetRunsByWorkingDirectory(target, e.SastScanResults...),
	}
}
