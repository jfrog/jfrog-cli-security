package results

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayApi "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// SecurityCommandResults is a struct that holds the results of a security scan/audit command.
type SecurityCommandResults struct {
	// General fields describing the command metadata
	XrayVersion      string            `json:"xray_version"`
	XscVersion       string            `json:"xsc_version,omitempty"`
	EntitledForJas   bool              `json:"jas_entitled"`
	SecretValidation bool              `json:"secret_validation,omitempty"`
	CmdType          utils.CommandType `json:"command_type"`
	ResultContext    ResultContext     `json:"result_context,omitempty"`
	StartTime        time.Time         `json:"start_time"`
	// MultiScanId is a unique identifier that is used to group multiple scans together.
	MultiScanId string `json:"multi_scan_id,omitempty"`
	// Results for each target in the command
	Targets      []*TargetResults `json:"targets"`
	targetsMutex sync.Mutex       `json:"-"`
	// GeneralError that occurred during the command execution
	GeneralError error      `json:"general_error,omitempty"`
	errorsMutex  sync.Mutex `json:"-"`
}

// We have three types of results: vulnerabilities, violations and licenses.
// If the user provides a violation context (watches, repo_path, project_key, git_repo_key) the results will only include violations.
// If the user provides a violation context and requests vulnerabilities, the results will include both vulnerabilities and violations.
// If the user doesn't provide a violation context, the results will include vulnerabilities.
// Only one (Resource) field can be provided at a time.
// License information can be provided in all cases if requested.
type ResultContext struct {
	// If watches are provided, the scan will be performed only with the provided watches.
	Watches []string `json:"watches,omitempty"`
	// (Resource) If repo_path is provided, the scan will be performed on the repository's watches.
	RepoPath string `json:"repo_path,omitempty"`
	// (Resource) If projectKey is provided we will fetch the watches defined on the project.
	ProjectKey string `json:"project_key,omitempty"`
	// (Resource) If gitRepository is provided we will fetch the watches defined on the git repository.
	GitRepoHttpsCloneUrl string `json:"git_repo_key,omitempty"`
	// If non of the above is provided or requested, the results will include vulnerabilities
	IncludeVulnerabilities bool `json:"include_vulnerabilities"`
	// If requested, the results will include licenses
	IncludeLicenses bool `json:"include_licenses"`
	// The active watches defined on the project_key and git_repository values above that were fetched from the platform
	PlatformWatches *xrayApi.ResourcesWatchesBody `json:"platform_watches,omitempty"`
}

func (rc *ResultContext) HasViolationContext() bool {
	return len(rc.Watches) > 0 || len(rc.GitRepoHttpsCloneUrl) > 0 || len(rc.ProjectKey) > 0 || len(rc.RepoPath) > 0
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

type ScanResult[T interface{}] struct {
	Scan       T   `json:"scan"`
	StatusCode int `json:"status_code,omitempty"`
}

func (sr *ScanResult[T]) IsScanFailed() bool {
	return sr.StatusCode != 0
}

type ScaScanResults struct {
	IsMultipleRootProject *bool `json:"is_multiple_root_project,omitempty"`
	// Target of the scan
	Descriptors []string `json:"descriptors,omitempty"`
	// Sca scan results
	XrayResults []ScanResult[services.ScanResponse] `json:"xray_scan,omitempty"`
}

type JasScansResults struct {
	JasVulnerabilities       JasScanResults             `json:"jas_vulnerabilities,omitempty"`
	JasViolations            JasScanResults             `json:"jas_violations,omitempty"`
	ApplicabilityScanResults []ScanResult[[]*sarif.Run] `json:"contextual_analysis,omitempty"`
}

type JasScanResults struct {
	SecretsScanResults   []ScanResult[[]*sarif.Run] `json:"secrets,omitempty"`
	IacScanResults       []ScanResult[[]*sarif.Run] `json:"iac,omitempty"`
	SastScanResults      []ScanResult[[]*sarif.Run] `json:"sast,omitempty"`
	MaliciousScanResults []ScanResult[[]*sarif.Run] `json:"malicious_code,omitempty"`
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

func NewCommandResults(cmdType utils.CommandType) *SecurityCommandResults {
	return &SecurityCommandResults{CmdType: cmdType, targetsMutex: sync.Mutex{}, errorsMutex: sync.Mutex{}}
}

func (r *SecurityCommandResults) SetStartTime(startTime time.Time) *SecurityCommandResults {
	r.StartTime = startTime
	return r
}

func (r *SecurityCommandResults) SetXrayVersion(xrayVersion string) *SecurityCommandResults {
	r.XrayVersion = xrayVersion
	return r
}

func (r *SecurityCommandResults) SetXscVersion(xscVersion string) *SecurityCommandResults {
	r.XscVersion = xscVersion
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

func (r *SecurityCommandResults) SetResultsContext(context ResultContext) *SecurityCommandResults {
	r.ResultContext = context
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
	r.errorsMutex.Lock()
	r.GeneralError = errors.Join(r.GeneralError, err)
	r.errorsMutex.Unlock()
	return r
}

// Is the result includes violations
func (r *SecurityCommandResults) HasViolationContext() bool {
	return r.ResultContext.HasViolationContext()
}

// Is the result includes vulnerabilities
func (r *SecurityCommandResults) IncludesVulnerabilities() bool {
	return r.ResultContext.IncludeVulnerabilities
}

// Is the result includes licenses
func (r *SecurityCommandResults) IncludesLicenses() bool {
	return r.ResultContext.IncludeLicenses
}

func (r *SecurityCommandResults) GetTargetsPaths() (paths []string) {
	for _, scan := range r.Targets {
		paths = append(paths, scan.Target)
	}
	return
}

func (r *SecurityCommandResults) GetTargets() (targets []ScanTarget) {
	for _, scan := range r.Targets {
		targets = append(targets, scan.ScanTarget)
	}
	return
}

func (r *SecurityCommandResults) GetScaScansXrayResults() (results []services.ScanResponse) {
	for _, scan := range r.Targets {
		results = append(results, scan.GetScaScansXrayResults()...)
	}
	return
}

func (r *SecurityCommandResults) HasJasScansResults(scanType jasutils.JasScanType) bool {
	if !r.EntitledForJas {
		return false
	}
	for _, target := range r.Targets {
		if target.HasJasScansResults(scanType) {
			return true
		}
	}
	return false
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
	for _, target := range r.Targets {
		if target.HasInformation() {
			return true
		}
	}
	return false
}

func (r *SecurityCommandResults) HasFindings() bool {
	for _, target := range r.Targets {
		if target.HasFindings() {
			return true
		}
	}
	return false
}

// --- Scan on a target ---

func (r *SecurityCommandResults) NewScanResults(target ScanTarget) *TargetResults {
	targetResults := &TargetResults{ScanTarget: target, errorsMutex: sync.Mutex{}}
	if r.EntitledForJas {
		targetResults.JasResults = &JasScansResults{JasVulnerabilities: JasScanResults{}, JasViolations: JasScanResults{}}
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
	for _, scanResult := range sr.ScaResults.XrayResults {
		results = append(results, scanResult.Scan)
	}
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
		xrayScanResult := scaResult.Scan
		for _, vulnerability := range xrayScanResult.Vulnerabilities {
			if tech := techutils.Technology(strings.ToLower(vulnerability.Technology)); tech != "" {
				technologiesSet.Add(tech)
			}
		}
		for _, violation := range xrayScanResult.Violations {
			if tech := techutils.Technology(strings.ToLower(violation.Technology)); tech != "" {
				technologiesSet.Add(tech)
			}
		}
	}
	return technologiesSet.ToSlice()
}

func (sr *TargetResults) HasJasScansResults(scanType jasutils.JasScanType) bool {
	if sr.JasResults == nil {
		return false
	}
	return sr.JasResults.HasInformationByType(scanType)
}

func (sr *TargetResults) GetJasScansResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	if sr.JasResults == nil {
		return
	}
	return sr.JasResults.GetVulnerabilitiesResults(scanType)
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

func (sr *TargetResults) NewScaScanResults(errorCode int, responses ...services.ScanResponse) *ScaScanResults {
	if sr.ScaResults == nil {
		sr.ScaResults = &ScaScanResults{}
	}
	for _, response := range responses {
		sr.ScaResults.XrayResults = append(sr.ScaResults.XrayResults, ScanResult[services.ScanResponse]{Scan: response, StatusCode: errorCode})
	}
	return sr.ScaResults
}

func (ssr *ScaScanResults) HasInformation() bool {
	if ssr.HasFindings() {
		return true
	}
	for _, scanResults := range ssr.XrayResults {
		if len(scanResults.Scan.Licenses) > 0 {
			return true
		}
	}
	return false
}

func (ssr *ScaScanResults) HasFindings() bool {
	for _, scanResults := range ssr.XrayResults {
		if len(scanResults.Scan.Vulnerabilities) > 0 || len(scanResults.Scan.Violations) > 0 {
			return true
		}
	}
	return false
}

func (jsr *JasScansResults) AddApplicabilityScanResults(exitCode int, runs ...*sarif.Run) {
	jsr.ApplicabilityScanResults = append(jsr.ApplicabilityScanResults, ScanResult[[]*sarif.Run]{Scan: runs, StatusCode: exitCode})
}

func (jsr *JasScansResults) AddJasScanResults(scanType jasutils.JasScanType, vulnerabilitiesRuns []*sarif.Run, violationsRuns []*sarif.Run, exitCode int) {
	switch scanType {
	case jasutils.Secrets:
		jsr.JasVulnerabilities.SecretsScanResults = append(jsr.JasVulnerabilities.SecretsScanResults, ScanResult[[]*sarif.Run]{Scan: vulnerabilitiesRuns, StatusCode: exitCode})
		jsr.JasViolations.SecretsScanResults = append(jsr.JasViolations.SecretsScanResults, ScanResult[[]*sarif.Run]{Scan: violationsRuns, StatusCode: exitCode})
	case jasutils.IaC:
		jsr.JasVulnerabilities.IacScanResults = append(jsr.JasVulnerabilities.IacScanResults, ScanResult[[]*sarif.Run]{Scan: vulnerabilitiesRuns, StatusCode: exitCode})
		jsr.JasViolations.IacScanResults = append(jsr.JasViolations.IacScanResults, ScanResult[[]*sarif.Run]{Scan: violationsRuns, StatusCode: exitCode})
	case jasutils.Sast:
		jsr.JasVulnerabilities.SastScanResults = append(jsr.JasVulnerabilities.SastScanResults, ScanResult[[]*sarif.Run]{Scan: vulnerabilitiesRuns, StatusCode: exitCode})
		jsr.JasViolations.SastScanResults = append(jsr.JasViolations.SastScanResults, ScanResult[[]*sarif.Run]{Scan: violationsRuns, StatusCode: exitCode})
	case jasutils.MaliciousCode:
		jsr.JasVulnerabilities.MaliciousScanResults = append(jsr.JasVulnerabilities.MaliciousScanResults, ScanResult[[]*sarif.Run]{Scan: vulnerabilitiesRuns, StatusCode: exitCode})
		jsr.JasViolations.MaliciousScanResults = append(jsr.JasViolations.MaliciousScanResults, ScanResult[[]*sarif.Run]{Scan: violationsRuns, StatusCode: exitCode})
	}
}

func (jsr *JasScansResults) GetApplicabilityScanResults() (results []*sarif.Run) {
	for _, scan := range jsr.ApplicabilityScanResults {
		results = append(results, scan.Scan...)
	}
	return
}

func (jsr *JasScansResults) GetVulnerabilitiesResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	switch scanType {
	case jasutils.Secrets:
		for _, scan := range jsr.JasVulnerabilities.SecretsScanResults {
			if scan.IsScanFailed() {
				continue
			}
			results = append(results, scan.Scan...)
		}
	case jasutils.IaC:
		for _, scan := range jsr.JasVulnerabilities.IacScanResults {
			if scan.IsScanFailed() {
				continue
			}
			results = append(results, scan.Scan...)
		}
	case jasutils.Sast:
		for _, scan := range jsr.JasVulnerabilities.SastScanResults {
			if scan.IsScanFailed() {
				continue
			}
			results = append(results, scan.Scan...)
		}
	case jasutils.MaliciousCode:
		for _, scan := range jsr.JasVulnerabilities.MaliciousScanResults {
			if scan.IsScanFailed() {
				continue
			}
			results = append(results, scan.Scan...)
		}
	}
	return
}

func (jsr *JasScansResults) GetViolationsResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	switch scanType {
	case jasutils.Secrets:
		for _, scan := range jsr.JasViolations.SecretsScanResults {
			if scan.IsScanFailed() {
				continue
			}
			results = append(results, scan.Scan...)
		}
	case jasutils.IaC:
		for _, scan := range jsr.JasViolations.IacScanResults {
			if scan.IsScanFailed() {
				continue
			}
			results = append(results, scan.Scan...)
		}
	case jasutils.Sast:
		for _, scan := range jsr.JasViolations.SastScanResults {
			if scan.IsScanFailed() {
				continue
			}
			results = append(results, scan.Scan...)
		}
	case jasutils.MaliciousCode:
		for _, scan := range jsr.JasViolations.MaliciousScanResults {
			if scan.IsScanFailed() {
				continue
			}
			results = append(results, scan.Scan...)
		}
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
	for _, run := range jsr.GetVulnerabilitiesResults(scanType) {
		for _, result := range run.Results {
			if len(result.Locations) > 0 {
				return true
			}
		}
	}

	for _, run := range jsr.GetViolationsResults(scanType) {
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
	if scanType == jasutils.Applicability && len(jsr.ApplicabilityScanResults) > 0 {
		return true
	}
	for _, run := range jsr.GetVulnerabilitiesResults(scanType) {
		if len(run.Results) > 0 {
			return true
		}
	}
	for _, run := range jsr.GetViolationsResults(scanType) {
		if len(run.Results) > 0 {
			return true
		}
	}
	return false
}
