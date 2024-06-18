package results

import (
	"errors"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/scanconfig"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// ScanCommandResults is a struct that holds the results of a security scan/audit command.
type ScanCommandResults struct {
	// ScaResults  []ScaScanResult
	// XrayVersion string
	// ScaError    error

	// ExtendedScanResults *ExtendedScanResults
	// JasError            error

	// TODO: remove above fields and use the below fields

	// General fields describing the command metadata
	XrayVersion    string `json:"xray_version"`
	EntitledForJas bool   `json:"entitledForJas"`
	// MultiScanId is a unique identifier that is used to group multiple scans together.
	MultiScanId string `json:"multi_scan_id,omitempty"`
	// Results for each target in the command
	Scans  []*ScanResults `json:"scans"`
	Errors error          `json:"errors,omitempty"`
}

type ScanResults struct {
	// // Could be working directory (audit), file path (binary scan), imageTag (docker scan) or build name+number (build scan)
	// // Physical location of the target: Working directory (audit) / binary to scan (scan / docker scan)
	// Target string `json:"target"`
	// // Logical name of the target
	// Name  string `json:"name,omitempty"`

	scanconfig.ScanTarget `json:",inline"`

	Errors error `json:"errors,omitempty"`
	// All scan results for the target
	ScaResults []ScaScanResults `json:"sca_scans"`
	JasResults *JasScansResults `json:"Jas_scans,omitempty"`
}

type ScaScanResults struct {
	scanconfig.ScanTarget `json:",inline"`

	XrayResult services.ScanResponse `json:"XrayScan"`

	// Optional field (not used only in build scan) to provide the technology of the scan
	// Technology techutils.Technology `json:"Technology,omitempty"`
	// Optional field (used in audit) to provide the descriptor path that provided the dependencies for the scan
	// If not exists (binary / docker scan) the field should be empty and the data is in `Target`
	// Target string `json:"Target,omitempty"`
}

type JasScansResults struct {
	ApplicabilityScanResults []*sarif.Run `json:"ContextualAnalysis,omitempty"`
	SecretsScanResults       []*sarif.Run `json:"Secrets,omitempty"`
	IacScanResults           []*sarif.Run `json:"Iac,omitempty"`
	SastScanResults          []*sarif.Run `json:"Sast,omitempty"`
}

func NewCommandResults(xrayVersion string, entitledForJas bool) *ScanCommandResults {
	return &ScanCommandResults{XrayVersion: xrayVersion, EntitledForJas: entitledForJas}
}

func (r *ScanCommandResults) SetMultiScanId(multiScanId string) *ScanCommandResults {
	r.MultiScanId = multiScanId
	return r
}

// --- Aggregated results for all targets ---

func (r *ScanCommandResults) GetScaScansXrayResults() (results []services.ScanResponse) {
	for _, scan := range r.Scans {
		results = append(results, scan.GetScaScansXrayResults()...)
	}
	return
}

func (r *ScanCommandResults) GetJasScansResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	if !r.EntitledForJas {
		return
	}
	for _, scan := range r.Scans {
		results = append(results, scan.GetJasScansResults(scanType)...)
	}
	return
}

func (r *ScanCommandResults) GetErrors() (err error) {
	err = r.Errors
	for _, scan := range r.Scans {
		if scan.Errors != nil {
			err = errors.Join(err, scan.Errors)
		}
	}
	return
}

func (r *ScanCommandResults) GetTechnologyScaScans(technology techutils.Technology) (scans []*ScaScanResults) {
	for _, scan := range r.Scans {
		for _, scaResult := range scan.ScaResults {
			if scaResult.Technology == technology {
				scans = append(scans, &scaResult)
			}
		}
	}
	return
}

func (r *ScanCommandResults) GetTechnologies() []techutils.Technology {
	technologies := datastructures.MakeSet[techutils.Technology]()
	for _, scan := range r.Scans {
		for _, scaResult := range scan.ScaResults {
			technologies.Add(scaResult.Technology)
		}
	}
	return technologies.ToSlice()
}

// In case multipleRoots is true, the field Component will show the root of each impact path, otherwise it will show the root's child.
// Set multipleRoots to true in case the given vulnerabilities array contains (or may contain) results of several projects or files (like in binary scan).
func (r *ScanCommandResults) HasMultipleTargets() bool {
	if len(r.Scans) > 1 {
		return true
	}
	for _, scan := range r.Scans {
		// If there is more than one SCA scan target (i.e multiple files with dependencies information)
		if len(scan.ScaResults) > 1 {
			return true
		}
	}
	return false
}

func (r *ScanCommandResults) HasInformation() bool {
	for _, scan := range r.Scans {
		if scan.HasInformation() {
			return true
		}
	}
	return false
}

func (r *ScanCommandResults) HasFindings() bool {
	for _, scan := range r.Scans {
		if scan.HasFindings() {
			return true
		}
	}
	return false
}

// func (r *Results) GetScanResult(target string) *ScanResults {
// 	for _, scan := range r.Scans {
// 		if scan.Target == target {
// 			return scan
// 		}
// 	}
// 	return nil
// }

// --- Scan on a target ---

func (r *ScanCommandResults) NewScanResults(target string) *ScanResults {
	scanResults := &ScanResults{Target: target}
	if r.EntitledForJas {
		scanResults.JasResults = &JasScansResults{}
	}
	r.Scans = append(r.Scans, scanResults)
	return scanResults
}

func (sr *ScanResults) GetScaScansXrayResults() (results []services.ScanResponse) {
	for _, scaResult := range sr.ScaResults {
		results = append(results, scaResult.XrayResult)
	}
	return
}

func (sr *ScanResults) GetTechnologies() []techutils.Technology {
	technologies := datastructures.MakeSet[techutils.Technology]()
	for _, scaResult := range sr.ScaResults {
		technologies.Add(scaResult.Technology)
	}
	return technologies.ToSlice()
}

func (sr *ScanResults) GetJasScansResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	if sr.JasResults == nil {
		return
	}
	return sr.JasResults.GetResults(scanType)
}

func (sr *ScanResults) HasInformation() bool {
	for _, scaResult := range sr.ScaResults {
		if scaResult.HasInformation() {
			return true
		}
	}
	return false
}

func (sr *ScanResults) HasFindings() bool {
	for _, scaResult := range sr.ScaResults {
		if scaResult.HasFindings() {
			return true
		}
	}
	return false
}

func (sr *ScanResults) NewScaScanResults(response *services.ScanResponse) *ScaScanResults {
	scaScanResults := NewScaScanResults(response)
	sr.ScaResults = append(sr.ScaResults, *scaScanResults)
	return scaScanResults
}

func (sr *ScanResults) NewScaScan(Target string, Technology techutils.Technology) *ScaScanResults {
	scaScanResults := &ScaScanResults{ScanTarget: scanconfig.ScanTarget{Target: Target, Technology: Technology}}
	sr.ScaResults = append(sr.ScaResults, *scaScanResults)
	return scaScanResults
}

func NewScaScanResults(response *services.ScanResponse) *ScaScanResults {
	return &ScaScanResults{XrayResult: *response}
}

func (ssr *ScaScanResults) SetDescriptor(descriptor string) *ScaScanResults {
	ssr.Target = descriptor
	return ssr
}

func (ssr *ScaScanResults) SetTechnology(technology techutils.Technology) *ScaScanResults {
	ssr.Technology = technology
	return ssr
}

func (ssr *ScaScanResults) SetXrayScanResults(response *services.ScanResponse) *ScaScanResults {
	ssr.XrayResult = *response
	return ssr
}

func (ssr *ScaScanResults) HasInformation() bool {
	return ssr.HasFindings() || len(ssr.XrayResult.Licenses) > 0
}

func (ssr *ScaScanResults) HasFindings() bool {
	return len(ssr.XrayResult.Vulnerabilities) > 0 || len(ssr.XrayResult.Violations) > 0
}

func (jsr *JasScansResults) GetResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	switch scanType {
	case jasutils.Applicability:
		results = jsr.ApplicabilityScanResults
	case jasutils.Secrets:
		results = jsr.SecretsScanResults
	case jasutils.IaC:
		results = jsr.IacScanResults
	case jasutils.Sast:
		results = jsr.SastScanResults
	}
	return
}

// -------------- Deprecated --------------

// func NewAuditResults() *Results {
// 	return &Results{ExtendedScanResults: &ExtendedScanResults{}}
// }

// func (r *Results) GetScaScansXrayResults() (results []services.ScanResponse) {
// 	for _, scaResult := range r.ScaResults {
// 		results = append(results, scaResult.XrayResults...)
// 	}
// 	return
// }

// func (r *Results) GetScaScannedTechnologies() []techutils.Technology {
// 	technologies := datastructures.MakeSet[techutils.Technology]()
// 	for _, scaResult := range r.ScaResults {
// 		technologies.Add(scaResult.Technology)
// 	}
// 	return technologies.ToSlice()
// }

// func (r *Results) IsMultipleProject() bool {
// 	if len(r.ScaResults) == 0 {
// 		return false
// 	}
// 	if len(r.ScaResults) == 1 {
// 		if r.ScaResults[0].IsMultipleRootProject == nil {
// 			return false
// 		}
// 		return *r.ScaResults[0].IsMultipleRootProject
// 	}
// 	return true
// }

// func (r *Results) IsScaIssuesFound() bool {
// 	for _, scan := range r.ScaResults {
// 		if scan.HasInformation() {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (r *Results) getScaScanResultByTarget(target string) *ScaScanResult {
// 	for _, scan := range r.ScaResults {
// 		if scan.Target == target {
// 			return &scan
// 		}
// 	}
// 	return nil
// }

// func (r *Results) IsIssuesFound() bool {
// 	if r.IsScaIssuesFound() {
// 		return true
// 	}
// 	if r.ExtendedScanResults.IsIssuesFound() {
// 		return true
// 	}
// 	return false
// }

// // Counts the total number of unique findings in the provided results.
// // A unique SCA finding is identified by a unique pair of vulnerability's/violation's issueId and component id or by a result returned from one of JAS scans.
// func (r *Results) CountScanResultsFindings() (total int) {
// 	return formats.SummaryResults{Scans: r.getScanSummaryByTargets()}.GetTotalIssueCount()
// }

// func (r *Results) GetSummary() (summary formats.SummaryResults) {
// 	if len(r.ScaResults) <= 1 {
// 		summary.Scans = r.getScanSummaryByTargets()
// 		return
// 	}
// 	for _, scaScan := range r.ScaResults {
// 		summary.Scans = append(summary.Scans, r.getScanSummaryByTargets(scaScan.Target)...)
// 	}
// 	return
// }

// // Returns a summary for the provided targets. If no targets are provided, a summary for all targets is returned.
// func (r *Results) getScanSummaryByTargets(targets ...string) (summaries []formats.ScanSummaryResult) {
// 	if len(targets) == 0 {
// 		// No filter, one scan summary for all targets
// 		summaries = append(summaries, getScanSummary(r.ExtendedScanResults, r.ScaResults...))
// 		return
// 	}
// 	for _, target := range targets {
// 		// Get target sca results
// 		targetScaResults := []ScaScanResult{}
// 		if targetScaResult := r.getScaScanResultByTarget(target); targetScaResult != nil {
// 			targetScaResults = append(targetScaResults, *targetScaResult)
// 		}
// 		// Get target extended results
// 		targetExtendedResults := r.ExtendedScanResults
// 		if targetExtendedResults != nil {
// 			targetExtendedResults = targetExtendedResults.GetResultsForTarget(target)
// 		}
// 		summaries = append(summaries, getScanSummary(targetExtendedResults, targetScaResults...))
// 	}
// 	return
// }

// type ScaScanResult struct {
// 	// Could be working directory (audit), file path (binary scan) or build name+number (build scan)
// 	Target                string                  `json:"Target"`
// 	Technology            techutils.Technology    `json:"Technology,omitempty"`
// 	XrayResults           []services.ScanResponse `json:"XrayResults,omitempty"`
// 	Descriptors           []string                `json:"Descriptors,omitempty"`
// 	IsMultipleRootProject *bool                   `json:"IsMultipleRootProject,omitempty"`
// }

// func (s ScaScanResult) HasInformation() bool {
// 	for _, scan := range s.XrayResults {
// 		if len(scan.Vulnerabilities) > 0 || len(scan.Violations) > 0 || len(scan.Licenses) > 0 {
// 			return true
// 		}
// 	}
// 	return false
// }

// type ExtendedScanResults struct {
// 	ApplicabilityScanResults []*sarif.Run
// 	SecretsScanResults       []*sarif.Run
// 	IacScanResults           []*sarif.Run
// 	SastScanResults          []*sarif.Run
// 	EntitledForJas           bool
// }

// func (e *ExtendedScanResults) IsIssuesFound() bool {
// 	return GetResultsLocationCount(e.ApplicabilityScanResults...) > 0 ||
// 		GetResultsLocationCount(e.SecretsScanResults...) > 0 ||
// 		GetResultsLocationCount(e.IacScanResults...) > 0 ||
// 		GetResultsLocationCount(e.SastScanResults...) > 0
// }

// func (e *ExtendedScanResults) GetResultsForTarget(target string) (result *ExtendedScanResults) {
// 	return &ExtendedScanResults{
// 		ApplicabilityScanResults: GetRunsByWorkingDirectory(target, e.ApplicabilityScanResults...),
// 		SecretsScanResults:       GetRunsByWorkingDirectory(target, e.SecretsScanResults...),
// 		IacScanResults:           GetRunsByWorkingDirectory(target, e.IacScanResults...),
// 		SastScanResults:          GetRunsByWorkingDirectory(target, e.SastScanResults...),
// 	}
// }
