package results

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/gofrog/datastructures"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayApi "github.com/jfrog/jfrog-client-go/xray/services/utils"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	CmdStepSbom               = "SBOM Generation"
	CmdStepSca                = "SCA Scan"
	CmdStepContextualAnalysis = "Contextual Analysis Enrichment"
	CmdStepIaC                = "IaC Scan"
	CmdStepSecrets            = "Secret Detection Scan"
	CmdStepSast               = "Static Application Security Testing (SAST)"
	CmdStepViolations         = "Violations Reporting"
)

type SecurityCommandStep string

// SecurityCommandResults is a struct that holds the results of a security scan/audit command.
type SecurityCommandResults struct {
	errorsMutex  sync.Mutex `json:"-"`
	targetsMutex sync.Mutex `json:"-"`
	// General fields describing the command metadata
	ResultsMetaData
	// Results for each target in the command
	Targets []*TargetResults `json:"targets"`
	// Policy violations found in the command
	Violations           *violationutils.Violations `json:"violations,omitempty"`
	ViolationsStatusCode *int                       `json:"violations_status_code,omitempty"`
}

type ResultsMetaData struct {
	XrayVersion      string                         `json:"xray_version"`
	XscVersion       string                         `json:"xsc_version,omitempty"`
	EntitledForJas   bool                           `json:"jas_entitled"`
	SecretValidation bool                           `json:"secret_validation"`
	CmdType          utils.CommandType              `json:"command_type"`
	ResultContext    ResultContext                  `json:"result_context,omitempty"`
	GitContext       *xscServices.XscGitInfoContext `json:"git_context,omitempty"`
	StartTime        time.Time                      `json:"start_time"`
	// MultiScanId is a unique identifier that is used to group multiple scans together.
	MultiScanId        string `json:"multi_scan_id,omitempty"`
	ResultsPlatformUrl string `json:"results_platform_url,omitempty"`
	// GeneralError that occurred during the command execution
	GeneralError error `json:"general_error,omitempty"`
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
	// If requested, the results will include sbom
	IncludeSbom bool `json:"include_sbom,omitempty"`
	// The active watches defined on the project_key and git_repository values above that were fetched from the platform
	PlatformWatches *xrayApi.ResourcesWatchesBody `json:"platform_watches,omitempty"`
}

func (rc *ResultContext) HasViolationContext() bool {
	return len(rc.Watches) > 0 || len(rc.GitRepoHttpsCloneUrl) > 0 || len(rc.ProjectKey) > 0 || len(rc.RepoPath) > 0
}

type ResultsStatus struct {
	SbomScanStatusCode           *int `json:"sbom,omitempty"`
	ScaScanStatusCode            *int `json:"sca,omitempty"`
	ContextualAnalysisStatusCode *int `json:"contextual_analysis,omitempty"`
	SecretsScanStatusCode        *int `json:"secrets,omitempty"`
	IacScanStatusCode            *int `json:"iac,omitempty"`
	SastScanStatusCode           *int `json:"sast,omitempty"`
	ViolationsStatusCode         *int `json:"violations,omitempty"`
}

func (status *ResultsStatus) IsScanFailed(step SecurityCommandStep) bool {
	switch step {
	case CmdStepSbom:
		return isScanFailed(status.SbomScanStatusCode)
	case CmdStepSca:
		return isScanFailed(status.ScaScanStatusCode)
	case CmdStepContextualAnalysis:
		return isScanFailed(status.ContextualAnalysisStatusCode)
	case CmdStepSecrets:
		return isScanFailed(status.SecretsScanStatusCode)
	case CmdStepIaC:
		return isScanFailed(status.IacScanStatusCode)
	case CmdStepSast:
		return isScanFailed(status.SastScanStatusCode)
	case CmdStepViolations:
		return isScanFailed(status.ViolationsStatusCode)
	}
	return false
}

func isScanFailed(statusCode *int) bool {
	return statusCode != nil && *statusCode != 0
}

func (status *ResultsStatus) UpdateStatus(step SecurityCommandStep, statusCode *int) {
	switch step {
	case CmdStepSbom:
		if shouldUpdateStatus(status.SbomScanStatusCode, statusCode) {
			status.SbomScanStatusCode = statusCode
		}
	case CmdStepSca:
		if shouldUpdateStatus(status.ScaScanStatusCode, statusCode) {
			status.ScaScanStatusCode = statusCode
		}
	case CmdStepContextualAnalysis:
		if shouldUpdateStatus(status.ContextualAnalysisStatusCode, statusCode) {
			status.ContextualAnalysisStatusCode = statusCode
		}
	case CmdStepSecrets:
		if shouldUpdateStatus(status.SecretsScanStatusCode, statusCode) {
			status.SecretsScanStatusCode = statusCode
		}
	case CmdStepIaC:
		if shouldUpdateStatus(status.IacScanStatusCode, statusCode) {
			status.IacScanStatusCode = statusCode
		}
	case CmdStepSast:
		if shouldUpdateStatus(status.SastScanStatusCode, statusCode) {
			status.SastScanStatusCode = statusCode
		}
	case CmdStepViolations:
		if shouldUpdateStatus(status.ViolationsStatusCode, statusCode) {
			status.ViolationsStatusCode = statusCode
		}
	}
}

// We only care to update the status if it's the first time we see it or if status is 0 (completed) and the new status is not (failed)
func shouldUpdateStatus(currentStatus, newStatus *int) bool {
	if currentStatus == nil || (*currentStatus == 0 && newStatus != nil) {
		return true
	}
	return false
}

type TargetResults struct {
	ScanTarget
	AppsConfigModule *jfrogappsconfig.Module `json:"apps_config_module,omitempty"`
	// All scan results for the target
	ScaResults    *ScaScanResults  `json:"sca_scans,omitempty"`
	JasResults    *JasScansResults `json:"jas_scans,omitempty"`
	ResultsStatus ResultsStatus    `json:"status,omitempty"`
	// Errors that occurred during the scans
	Errors      []error    `json:"errors,omitempty"`
	errorsMutex sync.Mutex `json:"-"`
}

type ScaScanResults struct {
	// Metadata about the scan
	Descriptors           []string `json:"descriptors,omitempty"`
	IsMultipleRootProject *bool    `json:"is_multiple_root_project,omitempty"`
	// Sca scan results
	DeprecatedXrayResults []services.ScanResponse `json:"xray_scan,omitempty"`
	// Sbom (potentially, with enriched components and CVE Vulnerabilities) of the target
	Sbom *cyclonedx.BOM `json:"sbom,omitempty"`
}

type JasScansResults struct {
	JasVulnerabilities       JasScanResults `json:"jas_vulnerabilities,omitempty"`
	JasViolations            JasScanResults `json:"jas_violations,omitempty"`
	ApplicabilityScanResults []*sarif.Run   `json:"contextual_analysis,omitempty"`
}

type JasScanResults struct {
	SecretsScanResults []*sarif.Run `json:"secrets,omitempty"`
	IacScanResults     []*sarif.Run `json:"iac,omitempty"`
	SastScanResults    []*sarif.Run `json:"sast,omitempty"`
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
	return &SecurityCommandResults{ResultsMetaData: ResultsMetaData{CmdType: cmdType}, targetsMutex: sync.Mutex{}, errorsMutex: sync.Mutex{}}
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

func (r *SecurityCommandResults) SetGitContext(gitContext *xscServices.XscGitInfoContext) *SecurityCommandResults {
	r.GitContext = gitContext
	return r
}

func (r *SecurityCommandResults) SetResultsPlatformUrl(resultsPlatformUrl string) *SecurityCommandResults {
	r.ResultsPlatformUrl = resultsPlatformUrl
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

func (r *SecurityCommandResults) IncludeSbom() bool {
	return r.ResultContext.IncludeSbom
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

func (r *SecurityCommandResults) GetTargetResults(target string) *TargetResults {
	for _, scan := range r.Targets {
		if scan.Target == target {
			return scan
		}
	}
	return nil
}

func (r *SecurityCommandResults) GetCommonParentPath() string {
	return utils.GetCommonParentDir(r.GetTargetsPaths()...)
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
		if scanTarget.ScaResults != nil && (len(scanTarget.ScaResults.DeprecatedXrayResults) > 1 || (scanTarget.ScaResults.IsMultipleRootProject != nil && *scanTarget.ScaResults.IsMultipleRootProject)) {
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

func (r *SecurityCommandResults) SetViolations(statusCode int, violations violationutils.Violations) *SecurityCommandResults {
	r.Violations = &violations
	r.ViolationsStatusCode = &statusCode
	return r
}

func (r *SecurityCommandResults) GetStatusCodes() ResultsStatus {
	status := ResultsStatus{ViolationsStatusCode: r.ViolationsStatusCode}
	for _, targetResults := range r.Targets {
		status.UpdateStatus(CmdStepSbom, targetResults.ResultsStatus.SbomScanStatusCode)
		status.UpdateStatus(CmdStepSca, targetResults.ResultsStatus.ScaScanStatusCode)
		status.UpdateStatus(CmdStepContextualAnalysis, targetResults.ResultsStatus.ContextualAnalysisStatusCode)
		status.UpdateStatus(CmdStepSecrets, targetResults.ResultsStatus.SecretsScanStatusCode)
		status.UpdateStatus(CmdStepIaC, targetResults.ResultsStatus.IacScanStatusCode)
		status.UpdateStatus(CmdStepSast, targetResults.ResultsStatus.SastScanStatusCode)
		status.UpdateStatus(CmdStepViolations, targetResults.ResultsStatus.ViolationsStatusCode)
	}
	return status
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

func (sr *TargetResults) GetDescriptors() []string {
	if sr.ScaResults == nil {
		return nil
	}
	descriptors := datastructures.MakeSet[string]()
	for _, descriptor := range sr.ScaResults.Descriptors {
		descriptors.Add(utils.GetRelativePath(utils.ToURI(descriptor), utils.ToURI(sr.Target)))
	}
	return descriptors.ToSlice()
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
	return sr.ScaResults.DeprecatedXrayResults
}

func (sr *TargetResults) GetTechnologies() []techutils.Technology {
	technologiesSet := datastructures.MakeSet[techutils.Technology]()
	if sr.Technology != "" {
		technologiesSet.Add(sr.Technology)
	}
	if sr.ScaResults == nil {
		return technologiesSet.ToSlice()
	}
	for _, scaResult := range sr.ScaResults.DeprecatedXrayResults {
		for _, vulnerability := range scaResult.Vulnerabilities {
			if tech := techutils.ToTechnology(vulnerability.Technology); tech != techutils.NoTech {
				technologiesSet.Add(tech)
			}
		}
		for _, violation := range scaResult.Violations {
			if tech := techutils.ToTechnology(violation.Technology); tech != techutils.NoTech {
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

func (sr *TargetResults) AddApplicabilityScanResults(exitCode int, runs ...*sarif.Run) {
	if sr.JasResults != nil {
		sr.JasResults.ApplicabilityScanResults = append(sr.JasResults.ApplicabilityScanResults, runs...)
	}
	sr.ResultsStatus.UpdateStatus(CmdStepContextualAnalysis, &exitCode)
}

func (sr *TargetResults) AddJasScanResults(scanType jasutils.JasScanType, vulnerabilitiesRuns []*sarif.Run, violationsRuns []*sarif.Run, exitCode int) {
	switch scanType {
	case jasutils.Secrets:
		sr.ResultsStatus.UpdateStatus(CmdStepSecrets, &exitCode)
		if sr.JasResults != nil {
			sr.JasResults.JasVulnerabilities.SecretsScanResults = append(sr.JasResults.JasVulnerabilities.SecretsScanResults, vulnerabilitiesRuns...)
			sr.JasResults.JasViolations.SecretsScanResults = append(sr.JasResults.JasViolations.SecretsScanResults, violationsRuns...)
		}
	case jasutils.IaC:
		sr.ResultsStatus.UpdateStatus(CmdStepIaC, &exitCode)
		if sr.JasResults != nil {
			sr.JasResults.JasVulnerabilities.IacScanResults = append(sr.JasResults.JasVulnerabilities.IacScanResults, vulnerabilitiesRuns...)
			sr.JasResults.JasViolations.IacScanResults = append(sr.JasResults.JasViolations.IacScanResults, violationsRuns...)
		}
	case jasutils.Sast:
		sr.ResultsStatus.UpdateStatus(CmdStepSast, &exitCode)
		if sr.JasResults != nil {
			sr.JasResults.JasVulnerabilities.SastScanResults = append(sr.JasResults.JasVulnerabilities.SastScanResults, vulnerabilitiesRuns...)
			sr.JasResults.JasViolations.SastScanResults = append(sr.JasResults.JasViolations.SastScanResults, violationsRuns...)
		}
	}
}

func (sr *TargetResults) SetDescriptors(descriptors ...string) *TargetResults {
	if sr.ScaResults == nil {
		sr.ScaResults = &ScaScanResults{}
	}
	sr.ScaResults.Descriptors = descriptors
	return sr
}

func (sr *TargetResults) SetSbom(sbom *cyclonedx.BOM, optionalStatusCodes ...int) *ScaScanResults {
	if sr.ScaResults == nil {
		sr.ScaResults = &ScaScanResults{}
	}
	if sbom != nil {
		// Only overwrite the existing SBOM if it is not nil.
		sr.ScaResults.Sbom = sbom
		sr.ScaResults.IsMultipleRootProject = clientutils.Pointer(IsMultiProject(sbom))
	}
	for _, statusCode := range optionalStatusCodes {
		sr.ResultsStatus.UpdateStatus(CmdStepSbom, &statusCode)
	}
	return sr.ScaResults
}

func (sr *TargetResults) EnrichedSbomScanResults(statusCode int, enrichedSbom *cyclonedx.BOM) *ScaScanResults {
	sr.SetSbom(enrichedSbom)
	sr.ResultsStatus.UpdateStatus(CmdStepSca, &statusCode)
	return sr.ScaResults
}

func (sr *TargetResults) ScaScanResults(statusCode int, responses ...services.ScanResponse) *ScaScanResults {
	if sr.ScaResults == nil {
		sr.ScaResults = &ScaScanResults{}
	}
	sr.ScaResults.DeprecatedXrayResults = append(sr.ScaResults.DeprecatedXrayResults, responses...)
	sr.ResultsStatus.UpdateStatus(CmdStepSca, &statusCode)
	return sr.ScaResults
}

func (ssr *ScaScanResults) HasInformation() bool {
	if ssr.HasFindings() {
		return true
	}
	for _, scanResults := range ssr.DeprecatedXrayResults {
		if len(scanResults.Licenses) > 0 {
			return true
		}
	}
	if ssr.Sbom != nil && ssr.Sbom.Components != nil && len(*ssr.Sbom.Components) > 0 {
		for _, component := range *ssr.Sbom.Components {
			if component.Licenses != nil && len(*component.Licenses) > 0 {
				return true
			}
		}
	}
	return false
}

func (ssr *ScaScanResults) HasFindings() bool {
	for _, scanResults := range ssr.DeprecatedXrayResults {
		if len(scanResults.Vulnerabilities) > 0 || len(scanResults.Violations) > 0 {
			return true
		}
	}
	return ssr.Sbom != nil && ssr.Sbom.Vulnerabilities != nil && len(*ssr.Sbom.Vulnerabilities) > 0
}

func (jsr *JasScansResults) GetApplicabilityScanResults() (results []*sarif.Run) {
	return jsr.ApplicabilityScanResults
}

func (jsr *JasScansResults) GetVulnerabilitiesResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	switch scanType {
	case jasutils.Secrets:
		return jsr.JasVulnerabilities.SecretsScanResults
	case jasutils.IaC:
		return jsr.JasVulnerabilities.IacScanResults
	case jasutils.Sast:
		return jsr.JasVulnerabilities.SastScanResults
	}
	return
}

func (jsr *JasScansResults) GetViolationsResults(scanType jasutils.JasScanType) (results []*sarif.Run) {
	switch scanType {
	case jasutils.Secrets:
		return jsr.JasViolations.SecretsScanResults
	case jasutils.IaC:
		return jsr.JasViolations.IacScanResults
	case jasutils.Sast:
		return jsr.JasViolations.SastScanResults
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

// UnifyScaAndJasResults merges SCA and JAS diff results into a single SecurityCommandResults.
func UnifyScaAndJasResults(scaResults, jasDiffResults *SecurityCommandResults) *SecurityCommandResults {
	// Create unified results based on JAS diff structure
	unifiedResults := &SecurityCommandResults{
		ResultsMetaData: ResultsMetaData{
			EntitledForJas:   jasDiffResults.EntitledForJas,
			SecretValidation: jasDiffResults.SecretValidation,
			CmdType:          jasDiffResults.CmdType,
			XrayVersion:      jasDiffResults.XrayVersion,
			XscVersion:       jasDiffResults.XscVersion,
			MultiScanId:      jasDiffResults.MultiScanId,
			StartTime:        jasDiffResults.StartTime,
			ResultContext:    jasDiffResults.ResultContext,
		},
	}

	// Merge targets from both SCA and JAS results
	for _, scaTarget := range scaResults.Targets {
		// Find corresponding JAS target
		var jasTarget *TargetResults
		for _, jTarget := range jasDiffResults.Targets {
			if jTarget.Target == scaTarget.Target {
				jasTarget = jTarget
				break
			}
		}

		// Create unified target with both SCA and JAS results
		unifiedTarget := &TargetResults{
			ScanTarget:       scaTarget.ScanTarget,
			AppsConfigModule: scaTarget.AppsConfigModule,
			ScaResults:       scaTarget.ScaResults,
			JasResults:       nil,
		}

		// Add JAS diff results if available
		if jasTarget != nil {
			unifiedTarget.JasResults = jasTarget.JasResults
		}

		unifiedResults.Targets = append(unifiedResults.Targets, unifiedTarget)
	}

	return unifiedResults
}

// CompareJasResults computes the diff between target and source JAS results.
// Returns only NEW findings in source that don't exist in target.
func CompareJasResults(targetResults, sourceResults *SecurityCommandResults) *SecurityCommandResults {
	log.Info("[DIFF] Starting JAS diff calculation")
	log.Debug("[DIFF] Comparing", len(sourceResults.Targets), "source targets against", len(targetResults.Targets), "target targets")

	// Create diff results based on source structure
	diffResults := &SecurityCommandResults{
		ResultsMetaData: ResultsMetaData{
			EntitledForJas:   sourceResults.EntitledForJas,
			SecretValidation: sourceResults.SecretValidation,
			CmdType:          sourceResults.CmdType,
			XrayVersion:      sourceResults.XrayVersion,
			XscVersion:       sourceResults.XscVersion,
			MultiScanId:      sourceResults.MultiScanId,
			StartTime:        sourceResults.StartTime,
			ResultContext:    sourceResults.ResultContext,
		},
	}

	// Compare each source target against ALL target targets
	for _, sourceTarget := range sourceResults.Targets {
		if sourceTarget.JasResults == nil {
			continue
		}

		// Collect ALL target JAS results to compare against
		var allTargetJasResults []*JasScansResults
		for _, targetTarget := range targetResults.Targets {
			if targetTarget.JasResults != nil {
				allTargetJasResults = append(allTargetJasResults, targetTarget.JasResults)
			}
		}

		diffJasResults := filterExistingFindings(allTargetJasResults, sourceTarget.JasResults)

		diffTarget := &TargetResults{
			ScanTarget: sourceTarget.ScanTarget,
			JasResults: diffJasResults,
		}

		diffResults.Targets = append(diffResults.Targets, diffTarget)
	}

	return diffResults
}

// filterExistingFindings removes findings from source that already exist in target.
func filterExistingFindings(allTargetJasResults []*JasScansResults, sourceJasResults *JasScansResults) *JasScansResults {
	if sourceJasResults == nil {
		return nil
	}

	// If no target results, return all source results (everything is new)
	if len(allTargetJasResults) == 0 {
		return sourceJasResults
	}

	// Build target fingerprint set from ALL target results
	targetKeys := make(map[string]bool)

	for _, targetJasResults := range allTargetJasResults {
		if targetJasResults == nil {
			continue
		}

		// Extract from target secrets results (location-based)
		for _, targetRun := range targetJasResults.GetVulnerabilitiesResults(jasutils.Secrets) {
			extractLocationsOnly(targetRun, targetKeys)
		}
		for _, targetRun := range targetJasResults.GetViolationsResults(jasutils.Secrets) {
			extractLocationsOnly(targetRun, targetKeys)
		}
		// Extract from target IaC results (location-based)
		for _, targetRun := range targetJasResults.GetVulnerabilitiesResults(jasutils.IaC) {
			extractLocationsOnly(targetRun, targetKeys)
		}
		for _, targetRun := range targetJasResults.GetViolationsResults(jasutils.IaC) {
			extractLocationsOnly(targetRun, targetKeys)
		}
		// Extract from target SAST results (fingerprint-based)
		for _, targetRun := range targetJasResults.GetVulnerabilitiesResults(jasutils.Sast) {
			extractFingerprints(targetRun, targetKeys)
		}
		for _, targetRun := range targetJasResults.GetViolationsResults(jasutils.Sast) {
			extractFingerprints(targetRun, targetKeys)
		}
	}

	log.Debug("[DIFF] Built target fingerprint set with", len(targetKeys), "unique keys")

	// Count source results before filtering
	sourceSecrets := countSarifResults(sourceJasResults.JasVulnerabilities.SecretsScanResults) +
		countSarifResults(sourceJasResults.JasViolations.SecretsScanResults)
	sourceIac := countSarifResults(sourceJasResults.JasVulnerabilities.IacScanResults) +
		countSarifResults(sourceJasResults.JasViolations.IacScanResults)
	sourceSast := countSarifResults(sourceJasResults.JasVulnerabilities.SastScanResults) +
		countSarifResults(sourceJasResults.JasViolations.SastScanResults)

	log.Debug("[DIFF] Source findings before diff - Secrets:", sourceSecrets, "| IaC:", sourceIac, "| SAST:", sourceSast)

	// Filter source results - keep only what's NOT in target
	filteredJasResults := &JasScansResults{}

	// Filter vulnerabilities
	filteredJasResults.JasVulnerabilities.SecretsScanResults = filterSarifRuns(
		sourceJasResults.JasVulnerabilities.SecretsScanResults, targetKeys)
	filteredJasResults.JasVulnerabilities.IacScanResults = filterSarifRuns(
		sourceJasResults.JasVulnerabilities.IacScanResults, targetKeys)
	filteredJasResults.JasVulnerabilities.SastScanResults = filterSarifRuns(
		sourceJasResults.JasVulnerabilities.SastScanResults, targetKeys)

	// Filter violations
	filteredJasResults.JasViolations.SecretsScanResults = filterSarifRuns(
		sourceJasResults.JasViolations.SecretsScanResults, targetKeys)
	filteredJasResults.JasViolations.IacScanResults = filterSarifRuns(
		sourceJasResults.JasViolations.IacScanResults, targetKeys)
	filteredJasResults.JasViolations.SastScanResults = filterSarifRuns(
		sourceJasResults.JasViolations.SastScanResults, targetKeys)

	// Count filtered results after diff
	diffSecrets := countSarifResults(filteredJasResults.JasVulnerabilities.SecretsScanResults) +
		countSarifResults(filteredJasResults.JasViolations.SecretsScanResults)
	diffIac := countSarifResults(filteredJasResults.JasVulnerabilities.IacScanResults) +
		countSarifResults(filteredJasResults.JasViolations.IacScanResults)
	diffSast := countSarifResults(filteredJasResults.JasVulnerabilities.SastScanResults) +
		countSarifResults(filteredJasResults.JasViolations.SastScanResults)

	log.Info("[DIFF] New findings after diff - Secrets:", diffSecrets, "| IaC:", diffIac, "| SAST:", diffSast)
	log.Info("[DIFF] Filtered out - Secrets:", sourceSecrets-diffSecrets, "| IaC:", sourceIac-diffIac, "| SAST:", sourceSast-diffSast)

	return filteredJasResults
}

// countSarifResults counts total results across all SARIF runs
func countSarifResults(runs []*sarif.Run) int {
	count := 0
	for _, run := range runs {
		if run != nil {
			count += len(run.Results)
		}
	}
	return count
}

// extractFingerprints extracts fingerprints from SARIF run (for SAST)
func extractFingerprints(run *sarif.Run, targetKeys map[string]bool) {
	for _, result := range run.Results {
		if result.Fingerprints != nil {
			key := getResultFingerprint(result)
			if key != "" {
				targetKeys[key] = true
			}
		} else {
			for _, location := range result.Locations {
				key := getRelativeLocationFileName(location, run.Invocations) + getLocationSnippetText(location)
				targetKeys[key] = true
			}
		}
	}
}

// extractLocationsOnly extracts locations (for Secrets and IaC - no fingerprints)
func extractLocationsOnly(run *sarif.Run, targetKeys map[string]bool) {
	for _, result := range run.Results {
		for _, location := range result.Locations {
			key := getRelativeLocationFileName(location, run.Invocations) + getLocationSnippetText(location)
			targetKeys[key] = true
		}
	}
}

// getResultFingerprint returns the SAST fingerprint from a result
func getResultFingerprint(result *sarif.Result) string {
	if result.Fingerprints != nil {
		if value, ok := result.Fingerprints["precise_sink_and_sink_function"]; ok {
			return value
		}
	}
	return ""
}

// getLocationSnippetText returns the snippet text from a location
func getLocationSnippetText(location *sarif.Location) string {
	if location.PhysicalLocation != nil && location.PhysicalLocation.Region != nil &&
		location.PhysicalLocation.Region.Snippet != nil && location.PhysicalLocation.Region.Snippet.Text != nil {
		return *location.PhysicalLocation.Region.Snippet.Text
	}
	return ""
}

// getRelativeLocationFileName returns the relative file path from a location
func getRelativeLocationFileName(location *sarif.Location, invocations []*sarif.Invocation) string {
	wd := ""
	if len(invocations) > 0 {
		wd = getInvocationWorkingDirectory(invocations[0])
	}
	filePath := getLocationFileName(location)
	if filePath != "" {
		return extractRelativePath(filePath, wd)
	}
	return ""
}

func getInvocationWorkingDirectory(invocation *sarif.Invocation) string {
	if invocation != nil && invocation.WorkingDirectory != nil && invocation.WorkingDirectory.URI != nil {
		return *invocation.WorkingDirectory.URI
	}
	return ""
}

func getLocationFileName(location *sarif.Location) string {
	if location != nil && location.PhysicalLocation != nil && location.PhysicalLocation.ArtifactLocation != nil && location.PhysicalLocation.ArtifactLocation.URI != nil {
		return *location.PhysicalLocation.ArtifactLocation.URI
	}
	return ""
}

func extractRelativePath(resultPath string, projectRoot string) string {
	// Remove OS-specific file prefix
	resultPath = strings.TrimPrefix(resultPath, "file:///private")
	resultPath = strings.TrimPrefix(resultPath, "file:///")
	projectRoot = strings.TrimPrefix(projectRoot, "file:///private")
	projectRoot = strings.TrimPrefix(projectRoot, "file:///")
	projectRoot = strings.TrimPrefix(projectRoot, "/")

	// Get relative path (removes temp directory)
	relativePath := strings.ReplaceAll(resultPath, projectRoot, "")
	trimSlash := strings.TrimPrefix(relativePath, string(filepath.Separator))
	return strings.TrimPrefix(trimSlash, "/")
}

// MergeStatusCodes merges two ResultsStatus structs, taking the worst (non-zero) status for each scanner
// This is used when combining target and source results to ensure partial results filtering works correctly
func MergeStatusCodes(target, source ResultsStatus) ResultsStatus {
	merged := ResultsStatus{}
	merged.SbomScanStatusCode = mergeStatusCode(target.SbomScanStatusCode, source.SbomScanStatusCode)
	merged.ScaScanStatusCode = mergeStatusCode(target.ScaScanStatusCode, source.ScaScanStatusCode)
	merged.ContextualAnalysisStatusCode = mergeStatusCode(target.ContextualAnalysisStatusCode, source.ContextualAnalysisStatusCode)
	merged.SecretsScanStatusCode = mergeStatusCode(target.SecretsScanStatusCode, source.SecretsScanStatusCode)
	merged.IacScanStatusCode = mergeStatusCode(target.IacScanStatusCode, source.IacScanStatusCode)
	merged.SastScanStatusCode = mergeStatusCode(target.SastScanStatusCode, source.SastScanStatusCode)
	merged.ViolationsStatusCode = mergeStatusCode(target.ViolationsStatusCode, source.ViolationsStatusCode)
	return merged
}

// mergeStatusCode returns the worst (non-zero) status code between two
func mergeStatusCode(a, b *int) *int {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	// Return the non-zero value (failed status), or zero if both succeeded
	if *a != 0 {
		return a
	}
	return b
}

// filterSarifRuns filters SARIF runs, keeping only results that are NOT in target
func filterSarifRuns(sourceRuns []*sarif.Run, targetKeys map[string]bool) []*sarif.Run {
	var filteredRuns []*sarif.Run

	for _, run := range sourceRuns {
		var filteredResults []*sarif.Result

		for _, result := range run.Results {
			if result.Fingerprints != nil {
				// Use fingerprint for matching (SAST)
				if !targetKeys[getResultFingerprint(result)] {
					filteredResults = append(filteredResults, result)
				}
			} else {
				// Use location for matching (Secrets, IaC)
				var filteredLocations []*sarif.Location
				for _, location := range result.Locations {
					key := getRelativeLocationFileName(location, run.Invocations) + getLocationSnippetText(location)
					if !targetKeys[key] {
						filteredLocations = append(filteredLocations, location)
					}
				}

				if len(filteredLocations) > 0 {
					newResult := *result
					newResult.Locations = filteredLocations
					filteredResults = append(filteredResults, &newResult)
				}
			}
		}

		if len(filteredResults) > 0 {
			filteredRun := *run
			filteredRun.Results = filteredResults
			filteredRuns = append(filteredRuns, &filteredRun)
		}
	}

	return filteredRuns
}
