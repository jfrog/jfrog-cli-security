package results

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// SecurityCommandResults is a struct that holds the results of a security scan/audit command.
type SecurityCommandResults struct {
	// General fields describing the command metadata
	XrayVersion      string            `json:"xray_version"`
	EntitledForJas   bool              `json:"jas_entitled"`
	SecretValidation bool              `json:"secret_validation,omitempty"`
	CmdType          utils.CommandType `json:"command_type"`
	// MultiScanId is a unique identifier that is used to group multiple scans together.
	MultiScanId string `json:"multi_scan_id,omitempty"`
	// Results for each target in the command
	Targets      []*TargetResults `json:"targets"`
	targetsMutex sync.Mutex       `json:"-"`
	// GeneralError that occurred during the command execution
	GeneralError error      `json:"general_error,omitempty"`
	errorsMutex  sync.Mutex `json:"-"`
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
	XrayResults []services.ScanResponse `json:"xray_scan,omitempty"`
}

type JasScansResults struct {
	ApplicabilityScanResults []*sarif.Run `json:"contextual_analysis,omitempty"`
	SecretsScanResults       []*sarif.Run `json:"secrets,omitempty"`
	IacScanResults           []*sarif.Run `json:"iac,omitempty"`
	SastScanResults          []*sarif.Run `json:"sast,omitempty"`
}

type ScanTarget struct {
	// Physical location of the target: Working directory (audit) / binary to scan (scan / docker scan)
	Target string `json:"target,omitempty"`
	// Logical name of the target (build name / module name / docker image name...)
	Name string `json:"name,omitempty"`
	// Optional field (not used only in build scan) to provide the technology of the target
	Technology techutils.Technology `json:"technology,omitempty"`
}

func (st ScanTarget) Copy(newTarget string) ScanTarget {
	return ScanTarget{Target: newTarget, Name: st.Name, Technology: st.Technology}
}

func (st ScanTarget) String() (str string) {
	str = st.Target
	if st.Name != "" {
		str = st.Name
	}
	tech := st.Technology.String()
	if tech == techutils.NoTech.String() {
		tech = "unknown"
	}
	str += fmt.Sprintf(" [%s]", tech)
	return
}

// func NewCommandResults(cmdType utils.CommandType, xrayVersion string, entitledForJas, secretValidation bool) *SecurityCommandResults {
// 	return &SecurityCommandResults{CmdType: cmdType, XrayVersion: xrayVersion, EntitledForJas: entitledForJas, SecretValidation: secretValidation, targetsMutex: sync.Mutex{}}
// }

func NewCommandResults(cmdType utils.CommandType) *SecurityCommandResults {
	return &SecurityCommandResults{CmdType: cmdType, targetsMutex: sync.Mutex{}, errorsMutex: sync.Mutex{}}
}

func (r *SecurityCommandResults) SetXrayVersion(xrayVersion string) *SecurityCommandResults {
	r.XrayVersion = xrayVersion
	return r
}

func (r *SecurityCommandResults) SetEntitledForJas(entitledForJas bool) *SecurityCommandResults {
	r.EntitledForJas = entitledForJas
	return r
}

func (r *SecurityCommandResults) SetSecretValidation(secretValidation bool) *SecurityCommandResults {
	r.SecretValidation = secretValidation
	return r
}

func (r *SecurityCommandResults) SetMultiScanId(multiScanId string) *SecurityCommandResults {
	r.MultiScanId = multiScanId
	return r
}

// --- Aggregated results for all targets ---
// Adds a general error to the command results in different phases of its execution.
// Notice that in some usages we pass constant 'false' to the 'allowSkippingError' parameter in some places, where we wish to force propagation of the error when it occurs.
func (r *SecurityCommandResults) AddGeneralError(err error, allowSkippingError bool) *SecurityCommandResults {
	if allowSkippingError && err != nil {
		log.Warn(fmt.Sprintf("Partial results are allowed, the error is skipped: %s", err.Error()))
		return r
	}
	r.GeneralError = errors.Join(r.GeneralError, err)
	return r
}

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
	err = r.GeneralError
	for _, target := range r.Targets {
		if targetErr := target.GetErrors(); targetErr != nil {
			err = errors.Join(err, fmt.Errorf("target '%s' errors:\n%s", target.String(), targetErr))
		}
	}
	return
}

func (r *SecurityCommandResults) GetTechnologies(additionalTechs ...techutils.Technology) []techutils.Technology {
	technologies := datastructures.MakeSetFromElements(additionalTechs...)
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
		if scanTarget.ScaResults != nil && (len(scanTarget.ScaResults.XrayResults) > 1 || (scanTarget.ScaResults.IsMultipleRootProject != nil && *scanTarget.ScaResults.IsMultipleRootProject)) {
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

func (sr *TargetResults) GetErrors() (err error) {
	for _, targetErr := range sr.Errors {
		err = errors.Join(err, targetErr)
	}
	return
}

func (sr *TargetResults) GetWatches() []string {
	watches := datastructures.MakeSet[string]()
	for _, xrayResults := range sr.GetScaScansXrayResults() {
		for _, violation := range xrayResults.Violations {
			if violation.WatchName != "" {
				watches.Add(violation.WatchName)
			}
		}
	}
	return watches.ToSlice()
}

func (sr *TargetResults) GetScanIds() []string {
	scanIds := datastructures.MakeSet[string]()
	for _, xrayResults := range sr.GetScaScansXrayResults() {
		if xrayResults.ScanId != "" {
			scanIds.Add(xrayResults.ScanId)
		}
	}
	return scanIds.ToSlice()
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
		for _, vulnerability := range scaResult.Vulnerabilities {
			if tech := techutils.Technology(strings.ToLower(vulnerability.Technology)); tech != "" {
				technologiesSet.Add(tech)
			}
		}
		for _, violation := range scaResult.Violations {
			if tech := techutils.Technology(strings.ToLower(violation.Technology)); tech != "" {
				technologiesSet.Add(tech)
			}
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

func (sr *TargetResults) AddTargetError(err error, allowSkippingError bool) error {
	if allowSkippingError && err != nil {
		log.Warn(fmt.Sprintf("Partial results are allowed, the error is skipped in target '%s': %s", sr.String(), err.Error()))
		return nil
	}
	sr.errorsMutex.Lock()
	sr.Errors = append(sr.Errors, err)
	sr.errorsMutex.Unlock()
	return err
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
