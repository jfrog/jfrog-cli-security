package utils

import (
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
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
func (r *Results) CountScanResultsFindings() int {
	var totalFindings int
	totalFindings += getScaResultsUniqueFindingsAmount(&r.ScaResults)

	if r.ExtendedScanResults != nil {
		totalFindings += len(r.ExtendedScanResults.SastScanResults)
		totalFindings += len(r.ExtendedScanResults.IacScanResults)
		totalFindings += len(r.ExtendedScanResults.SecretsScanResults)
	}

	return totalFindings
}

func getScaResultsUniqueFindingsAmount(scaScanResults *[]ScaScanResult) int {
	uniqueXrayFindings := datastructures.MakeSet[string]()

	for _, scaResult := range *scaScanResults {
		for _, xrayResult := range scaResult.XrayResults {
			// XrayResults may contain Vulnerabilities OR Violations, but not both. Therefore, only one of them will be counted
			for _, vulnerability := range xrayResult.Vulnerabilities {
				for compId := range vulnerability.Components {
					uniqueXrayFindings.Add(vulnerability.IssueId + compId)
				}
			}

			for _, violation := range xrayResult.Violations {
				for compId := range violation.Components {
					uniqueXrayFindings.Add(violation.IssueId + compId)
				}
			}
		}
	}
	return uniqueXrayFindings.Size()
}

type ScaScanResult struct {
	Technology            coreutils.Technology    `json:"Technology"`
	WorkingDirectory      string                  `json:"WorkingDirectory"`
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
