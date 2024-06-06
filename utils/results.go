package utils

import (
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type Results struct {
	ScaResults  []*ScaScanResult
	XrayVersion string
	ScansErr    error

	ExtendedScanResults *ExtendedScanResults

	MultiScanId string
}

func NewAuditResults() *Results {
	return &Results{ExtendedScanResults: &ExtendedScanResults{}}
}

func (r *Results) GetScaScansXrayResults() (results []*services.ScanResponse) {
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

// Returns a summary for the provided targets. If no targets are provided, a summary for all targets is returned.
func (r *Results) getScanSummaryByTargets(targets ...string) (summaries []formats.ScanSummaryResult) {
	if len(targets) == 0 {
		// No filter, one scan summary for all targets
		summaries = append(summaries, getScanSummary(r.ExtendedScanResults, r.ScaResults...))
		return
	}
	for _, target := range targets {
		// Get target sca results
		targetScaResults := []*ScaScanResult{}
		if targetScaResult := r.getScaScanResultByTarget(target); targetScaResult != nil {
			targetScaResults = append(targetScaResults, targetScaResult)
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
	Target                string                   `json:"Target"`
	Technology            techutils.Technology     `json:"Technology,omitempty"`
	XrayResults           []*services.ScanResponse `json:"XrayResults,omitempty"`
	Descriptors           []string                 `json:"Descriptors,omitempty"`
	IsMultipleRootProject *bool                    `json:"IsMultipleRootProject,omitempty"`
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
