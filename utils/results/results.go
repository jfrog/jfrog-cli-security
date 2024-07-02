package results

import (
	"errors"
	"sync"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// SecurityCommandResults is a struct that holds the results of a security scan/audit command.
type SecurityCommandResults struct {
	// General fields describing the command metadata
	XrayVersion    string `json:"xray_version"`
	EntitledForJas bool   `json:"jas_entitled"`
	// MultiScanId is a unique identifier that is used to group multiple scans together.
	MultiScanId string `json:"multi_scan_id,omitempty"`
	// Results for each target in the command
	Targets    []*TargetResults `json:"targets"`
	scansMutex sync.Mutex       `json:"-"`
	// Error that occurred during the command execution
	Error error `json:"error,omitempty"`
}

type ScanTarget struct {
	// Physical location of the target: Working directory (audit) / binary to scan (scan / docker scan)
	Target string `json:"target,omitempty"`
	// Logical name of the target (build name / module name / docker image name...)
	Name string `json:"name,omitempty"`
	// Optional field (not used only in build scan) to provide the technology of the target
	Technology techutils.Technology `json:"technology,omitempty"`
}

type TargetResults struct {
	ScanTarget
	// All scan results for the target
	ScaResults *ScaScanResults  `json:"sca_scans,omitempty"`
	JasResults *JasScansResults `json:"jas_scans,omitempty"`
	// Errors that occurred during the scans
	Errors      []error    `json:"errors,omitempty"`
	// TODO: move to funcs...
	errorsMutex sync.Mutex `json:"-"`
}

type ScaScanResults struct {
	IsMultipleRootProject *bool `json:"is_multiple_root_project,omitempty"`
	// Target of the scan
	Descriptors []string `json:"descriptors,omitempty"`
	// Sca scan results
	XrayResults []services.ScanResponse `json:"xray_scan"`
}

type JasScansResults struct {
	ApplicabilityScanResults []*sarif.Run `json:"contextual_analysis,omitempty"`
	SecretsScanResults       []*sarif.Run `json:"secrets,omitempty"`
	IacScanResults           []*sarif.Run `json:"iac,omitempty"`
	SastScanResults          []*sarif.Run `json:"sast,omitempty"`
}

func NewCommandResults(xrayVersion string, entitledForJas bool) *SecurityCommandResults {
	return &SecurityCommandResults{XrayVersion: xrayVersion, EntitledForJas: entitledForJas, scansMutex: sync.Mutex{}}
}

func (r *SecurityCommandResults) SetMultiScanId(multiScanId string) *SecurityCommandResults {
	r.MultiScanId = multiScanId
	return r
}

// --- Aggregated results for all targets ---

func (r *SecurityCommandResults) GetScaScansXrayResults() (results []services.ScanResponse) {
	for _, scan := range r.Targets {
		results = append(results, scan.GetScaScansXrayResults()...)
	}
	return
}

func (r *SecurityCommandResults) GetJasScansResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	if !r.EntitledForJas {
		return
	}
	for _, scan := range r.Targets {
		results = append(results, scan.GetJasScansResults(scanType)...)
	}
	return
}

func (r *SecurityCommandResults) GetErrors() (err error) {
	err = r.Errors
	for _, scan := range r.Targets {
		if scan.Error != nil {
			err = errors.Join(err, scan.Error)
		}
	}
	return
}

func (r *SecurityCommandResults) GetTechnologyScaScans(technology techutils.Technology) (scans []*ScaScanResults) {
	for _, scan := range r.Targets {
		for _, scaResult := range scan.ScaResults {
			if scaResult.Technology == technology {
				scans = append(scans, scaResult)
			}
		}
	}
	return
}

func (r *SecurityCommandResults) GetTechnologies() []techutils.Technology {
	technologies := datastructures.MakeSet[techutils.Technology]()
	for _, scan := range r.Targets {
		technologies.AddElements(scan.GetTechnologies()...)
	}
	return technologies.ToSlice()
}

// In case multipleRoots is true, the field Component will show the root of each impact path, otherwise it will show the root's child.
// Set multipleRoots to true in case the given vulnerabilities array contains (or may contain) results of several projects or files (like in binary scan).
func (r *SecurityCommandResults) HasMultipleTargets() bool {
	if len(r.Targets) > 1 {
		return true
	}
	for _, scan := range r.Targets {
		// If there is more than one SCA scan target (i.e multiple files with dependencies information)
		if len(scan.ScaResults) > 1 {
			return true
		}
	}
	return false
}

func (r *SecurityCommandResults) HasInformation() bool {
	for _, scan := range r.Targets {
		if scan.HasInformation() {
			return true
		}
	}
	return false
}

func (r *SecurityCommandResults) HasFindings() bool {
	for _, scan := range r.Targets {
		if scan.HasFindings() {
			return true
		}
	}
	return false
}

// --- Scan on a target ---

func (r *SecurityCommandResults) NewScanResults(target ScanTarget) *TargetResults {
	scanResults := &TargetResults{ScanTarget: target, errorsMutex: sync.Mutex{}}
	if r.EntitledForJas {
		scanResults.JasResults = &JasScansResults{}
	}
	r.scansMutex.Lock()
	r.Targets = append(r.Targets, scanResults)
	r.scansMutex.Unlock()
	return scanResults
}

func (sr *TargetResults) GetScaScansXrayResults() (results []services.ScanResponse) {
	for _, scaResult := range sr.ScaResults {
		results = append(results, scaResult.XrayResult)
	}
	return
}

func (sr *TargetResults) GetTechnologies() []techutils.Technology {
	technologies := datastructures.MakeSet[techutils.Technology]()
	for _, scaResult := range sr.ScaResults {
		technologies.Add(scaResult.Technology)
	}
	return technologies.ToSlice()
}

func (sr *TargetResults) GetJasScansResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	if sr.JasResults == nil {
		return
	}
	return sr.JasResults.GetResults(scanType)
}

func (sr *TargetResults) HasInformation() bool {
	for _, scaResult := range sr.ScaResults {
		if scaResult.HasInformation() {
			return true
		}
	}
	return false
}

func (sr *TargetResults) HasFindings() bool {
	for _, scaResult := range sr.ScaResults {
		if scaResult.HasFindings() {
			return true
		}
	}
	return false
}

func (sr *TargetResults) AddError(err error) {
	sr.errorsMutex.Lock()
	sr.Error = errors.Join(sr.Error, err)
	sr.errorsMutex.Unlock()
}

func (sr *TargetResults) SetDescriptors(descriptors ...string) *TargetResults {
	if sr.ScaResults == nil {
		return sr
	}
	sr.ScaResults.Descriptors = descriptors
	return sr
}

func (sr *TargetResults) NewScaScanResults(responses ...*services.ScanResponse) *ScaScanResults {
	scaScanResults := NewScaScanResults(response)
	sr.ScaResults = append(sr.ScaResults, scaScanResults)
	return scaScanResults
}

func (sr *TargetResults) NewScaScan(descriptors ...string) *ScaScanResults {
	scaScanResults := &ScaScanResults{Descriptors: descriptors}
	sr.ScaResults = append(sr.ScaResults, scaScanResults)
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

// func NewAuditResults() *ScanCommandResults {
// 	return &ScanCommandResults{ExtendedScanResults: &ExtendedScanResults{}}
// }

// func (r *ScanCommandResults) GetScaScansXrayResults() (results []services.ScanResponse) {
// 	for _, scaResult := range r.ScaResults {
// 		results = append(results, scaResult.XrayResults...)
// 	}
// 	return
// }

// func (r *ScanCommandResults) GetScaScannedTechnologies() []techutils.Technology {
// 	technologies := datastructures.MakeSet[techutils.Technology]()
// 	for _, scaResult := range r.ScaResults {
// 		technologies.Add(scaResult.Technology)
// 	}
// 	return technologies.ToSlice()
// }

// func (r *ScanCommandResults) IsMultipleProject() bool {
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

// func (r *ScanCommandResults) IsScaIssuesFound() bool {
// 	for _, scan := range r.ScaResults {
// 		if scan.HasInformation() {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (r *ScanCommandResults) getScaScanResultByTarget(target string) *ScaScanResult {
// 	for _, scan := range r.ScaResults {
// 		if scan.Target == target {
// 			return scan
// 		}
// 	}
// 	return nil
// }

// func (r *ScanCommandResults) IsIssuesFound() bool {
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
// func (r *ScanCommandResults) CountScanResultsFindings() (total int) {
// 	return formats.SummaryResults{Scans: r.getScanSummaryByTargets()}.GetTotalIssueCount()
// }
// func (r *ScanCommandResults) GetSummary() (summary formats.SummaryResults) {
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
// func (r *ScanCommandResults) getScanSummaryByTargets(targets ...string) (summaries []formats.ScanSummaryResult) {
// 	if len(targets) == 0 {
// 		// No filter, one scan summary for all targets
// 		summaries = append(summaries, getScanSummary(r.ExtendedScanResults, r.ScaResults...))
// 		return
// 	}
// 	for _, target := range targets {
// 		// Get target sca results
// 		targetScaResults := []*ScaScanResult{}
// 		if targetScaResult := r.getScaScanResultByTarget(target); targetScaResult != nil {
// 			targetScaResults = append(targetScaResults, targetScaResult)
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
// 	return sarifutils.GetResultsLocationCount(e.ApplicabilityScanResults...) > 0 ||
// 		sarifutils.GetResultsLocationCount(e.SecretsScanResults...) > 0 ||
// 		sarifutils.GetResultsLocationCount(e.IacScanResults...) > 0 ||
// 		sarifutils.GetResultsLocationCount(e.SastScanResults...) > 0
// }

// func (e *ExtendedScanResults) GetResultsForTarget(target string) (result *ExtendedScanResults) {
// 	return &ExtendedScanResults{
// 		ApplicabilityScanResults: sarifutils.GetRunsByWorkingDirectory(target, e.ApplicabilityScanResults...),
// 		SecretsScanResults:       sarifutils.GetRunsByWorkingDirectory(target, e.SecretsScanResults...),
// 		IacScanResults:           sarifutils.GetRunsByWorkingDirectory(target, e.IacScanResults...),
// 		SastScanResults:          sarifutils.GetRunsByWorkingDirectory(target, e.SastScanResults...),
// 	}
// }
