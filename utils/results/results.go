package results

import (
	"errors"
	"strings"
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
	Targets      []*TargetResults `json:"targets"`
	targetsMutex sync.Mutex       `json:"-"`
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
	return &SecurityCommandResults{XrayVersion: xrayVersion, EntitledForJas: entitledForJas, targetsMutex: sync.Mutex{}}
}

func (r *SecurityCommandResults) SetMultiScanId(multiScanId string) *SecurityCommandResults {
	r.MultiScanId = multiScanId
	return r
}

// --- Aggregated results for all targets ---

func (r *SecurityCommandResults) GetTargetsPaths() (paths []string) {
	for _, scan := range r.Targets {
		paths = append(paths, scan.Target)
	}
	return
}

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
	err = r.Error
	for _, target := range r.Targets {
		for _, targetErr := range target.Errors {
			err = errors.Join(err, targetErr)
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
	for _, scanTarget := range r.Targets {
		// If there is more than one SCA scan target (i.e multiple files with dependencies information)
		if scanTarget.ScaResults != nil && (len(scanTarget.ScaResults.XrayResults) > 0 || (scanTarget.ScaResults.IsMultipleRootProject != nil && *scanTarget.ScaResults.IsMultipleRootProject)) {
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
	targetResults := &TargetResults{ScanTarget: target, errorsMutex: sync.Mutex{}}
	if r.EntitledForJas {
		targetResults.JasResults = &JasScansResults{}
	}

	r.targetsMutex.Lock()
	r.Targets = append(r.Targets, targetResults)
	r.targetsMutex.Unlock()
	return targetResults
}

func (sr *TargetResults) GetScaScansXrayResults() (results []services.ScanResponse) {
	if sr.ScaResults == nil {
		return
	}
	results = append(results, sr.ScaResults.XrayResults...)
	return
}

func (sr *TargetResults) GetTechnologies() []techutils.Technology {
	technologiesSet := datastructures.MakeSet[techutils.Technology]()
	if sr.Technology != "" {
		technologiesSet.Add(sr.Technology)
	}
	if sr.ScaResults == nil {
		return technologiesSet.ToSlice()
	}
	for _, scaResult := range sr.ScaResults.XrayResults {
		if scaResult.ScannedPackageType != "" {
			technologiesSet.Add(techutils.Technology(strings.ToLower(scaResult.ScannedPackageType)))
		}
	}
	return technologiesSet.ToSlice()
}

func (sr *TargetResults) GetJasScansResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	if sr.JasResults == nil {
		return
	}
	return sr.JasResults.GetResults(scanType)
}

func (sr *TargetResults) HasInformation() bool {
	if sr.JasResults != nil && sr.JasResults.HasInformation() {
		return true
	}
	if sr.ScaResults != nil && sr.ScaResults.HasInformation() {
		return true
	}
	return false
}

func (sr *TargetResults) HasFindings() bool {
	if sr.JasResults != nil && sr.JasResults.HasFindings() {
		return true
	}
	if sr.ScaResults != nil && sr.ScaResults.HasFindings() {
		return true
	}
	return false
}

func (sr *TargetResults) AddError(err error) {
	sr.errorsMutex.Lock()
	sr.Errors = append(sr.Errors, err)
	sr.errorsMutex.Unlock()
}

func (sr *TargetResults) SetDescriptors(descriptors ...string) *TargetResults {
	if sr.ScaResults == nil {
		sr.ScaResults = &ScaScanResults{}
	}
	sr.ScaResults.Descriptors = descriptors
	return sr
}

func (sr *TargetResults) NewScaScanResults(responses ...services.ScanResponse) *ScaScanResults {
	if sr.ScaResults == nil {
		sr.ScaResults = &ScaScanResults{}
	}
	sr.ScaResults.XrayResults = append(sr.ScaResults.XrayResults, responses...)
	return sr.ScaResults
}

func (ssr *ScaScanResults) HasInformation() bool {
	if ssr.HasFindings() {
		return true
	}
	for _, scanResults := range ssr.XrayResults {
		if len(scanResults.Licenses) > 0 {
			return true
		}
	}
	return false
}

func (ssr *ScaScanResults) HasFindings() bool {
	for _, scanResults := range ssr.XrayResults {
		if len(scanResults.Vulnerabilities) > 0 || len(scanResults.Violations) > 0 {
			return true
		}
	}
	return false
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

func (jsr *JasScansResults) HasFindings() bool {
	for _, scanType := range jasutils.GetJasScanTypes() {
		if jsr.HasFindingsByType(scanType) {
			return true
		}
	}
	return false
}

func (jsr *JasScansResults) HasFindingsByType(scanType jasutils.JasScanType) bool {
	for _, run := range jsr.GetResults(scanType) {
		for _, result := range run.Results {
			if len(result.Locations) > 0 {
				return true
			}
		}
	}
	return false
}

func (jsr *JasScansResults) HasInformation() bool {
	for _, scanType := range jasutils.GetJasScanTypes() {
		if jsr.HasInformationByType(scanType) {
			return true
		}
	}
	return false
}

func (jsr *JasScansResults) HasInformationByType(scanType jasutils.JasScanType) bool {
	for _, run := range jsr.GetResults(scanType) {
		if len(run.Results) > 0 {
			return true
		}
	}
	return false
}