package violationutils

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

const (
	ScaViolationTypeSecurity        ScaViolationIssueType = "security"
	ScaViolationTypeOperationalRisk ScaViolationIssueType = "operational_risk"
	ScaViolationTypeLicense         ScaViolationIssueType = "license"

	CustomLicenseViolationId = "custom_license_violation"
)

type ScaViolationIssueType string

func (v ScaViolationIssueType) String() string {
	return string(v)
}

type Violations struct {
	Sca     []CveViolation             `json:"sca,omitempty"`
	License []LicenseViolation         `json:"license,omitempty"`
	OpRisk  []OperationalRiskViolation `json:"operational_risk,omitempty"`
	Secrets []JasViolation             `json:"secrets,omitempty"`
	Iac     []JasViolation             `json:"iac,omitempty"`
	Sast    []JasViolation             `json:"sast,omitempty"`
}

func (vs *Violations) HasViolations() bool {
	return len(vs.Sca) > 0 || len(vs.License) > 0 || len(vs.OpRisk) > 0 || len(vs.Secrets) > 0 || len(vs.Iac) > 0 || len(vs.Sast) > 0
}

func (vs *Violations) Count() int {
	return len(vs.Sca) + len(vs.License) + len(vs.OpRisk) + len(vs.Secrets) + len(vs.Iac) + len(vs.Sast)
}

func (vs *Violations) String() string {
	if !vs.HasViolations() {
		return "No violations found"
	}
	out := []string{}
	if len(vs.Sca) > 0 {
		out = append(out, fmt.Sprintf("SCA (%d)", len(vs.Sca)))
	}
	if len(vs.License) > 0 {
		out = append(out, fmt.Sprintf("License (%d)", len(vs.License)))
	}
	if len(vs.OpRisk) > 0 {
		out = append(out, fmt.Sprintf("Operational Risk (%d)", len(vs.OpRisk)))
	}
	if len(vs.Secrets) > 0 {
		out = append(out, fmt.Sprintf("Secrets (%d)", len(vs.Secrets)))
	}
	if len(vs.Iac) > 0 {
		out = append(out, fmt.Sprintf("IaC (%d)", len(vs.Iac)))
	}
	if len(vs.Sast) > 0 {
		out = append(out, fmt.Sprintf("SAST (%d)", len(vs.Sast)))
	}
	return strings.Join(out, ", ")
}

func (vs *Violations) ShouldFailBuild() bool {
	for _, v := range vs.Sca {
		if v.ShouldFailBuild() {
			return true
		}
	}
	for _, v := range vs.License {
		if v.ShouldFailBuild() {
			return true
		}
	}
	for _, v := range vs.OpRisk {
		if v.ShouldFailBuild() {
			return true
		}
	}
	for _, v := range vs.Secrets {
		if v.ShouldFailBuild() {
			return true
		}
	}
	for _, v := range vs.Iac {
		if v.ShouldFailBuild() {
			return true
		}
	}
	for _, v := range vs.Sast {
		if v.ShouldFailBuild() {
			return true
		}
	}
	return false
}

func (vs *Violations) ShouldFailPR() bool {
	for _, v := range vs.Sca {
		if v.ShouldFailPR() {
			return true
		}
	}
	for _, v := range vs.License {
		if v.ShouldFailPR() {
			return true
		}
	}
	for _, v := range vs.OpRisk {
		if v.ShouldFailPR() {
			return true
		}
	}
	for _, v := range vs.Secrets {
		if v.ShouldFailPR() {
			return true
		}
	}
	for _, v := range vs.Iac {
		if v.ShouldFailPR() {
			return true
		}
	}
	for _, v := range vs.Sast {
		if v.ShouldFailPR() {
			return true
		}
	}
	return false
}

type Violation struct {
	ViolationId string                 `json:"violation_id"`
	Severity    severityutils.Severity `json:"severity"`
	Watch       string                 `json:"watch_name"`
	Policies    []Policy               `json:"matched_policies,omitempty"`
}

func (v *Violation) ShouldSkipNotApplicable() bool {
	// If at least one of the policies does not have SkipNotApplicable, we do not skip the violation.
	for _, p := range v.Policies {
		if !p.SkipNotApplicable {
			return false
		}
	}
	return true
}

func (v *Violation) ShouldFailBuild() bool {
	for _, p := range v.Policies {
		if p.FailBuild {
			return true
		}
	}
	return false
}

func (v *Violation) ShouldFailPR() bool {
	for _, p := range v.Policies {
		if p.FailPullRequest {
			return true
		}
	}
	return false
}

type Policy struct {
	PolicyName        string `json:"policy"`
	Rule              string `json:"rule"`
	FailBuild         bool   `json:"fail_build,omitempty"`
	FailPullRequest   bool   `json:"fail_pull_request,omitempty"`
	SkipNotApplicable bool   `json:"skip_not_applicable,omitempty"`
}

type JasViolation struct {
	Violation
	Rule     *sarif.ReportingDescriptor `json:"rule,omitempty"`
	Result   *sarif.Result              `json:"result,omitempty"`
	Location *sarif.Location            `json:"location,omitempty"`
}

type ScaViolation struct {
	Violation
	ImpactedComponent cyclonedx.Component `json:"impacted_component"`
	// TODO:
	DirectComponents []formats.ComponentRow   `json:"direct_components,omitempty"`
	ImpactPaths      [][]formats.ComponentRow `json:"impact_paths,omitempty"`
}

type CveViolation struct {
	ScaViolation
	CveVulnerability   cyclonedx.Vulnerability
	ContextualAnalysis *formats.Applicability `json:"contextual_analysis,omitempty"`
	// TODO:
	FixedVersions *[]cyclonedx.AffectedVersions `json:"fixed_versions,omitempty"`
	// TODO: remove after information displayed in cyclonedx.Vulnerability
	JfrogResearchInformation *formats.JfrogResearchInformation `json:"jfrogResearchInformation,omitempty"`
}

type LicenseViolation struct {
	ScaViolation
	LicenseKey  string `json:"license_key"`
	LicenseName string `json:"license_name"`
}

type OperationalRiskViolationReadableData struct {
	RiskReason    string `json:"riskReason"`
	IsEol         string `json:"isEndOfLife"`
	EolMessage    string `json:"endOfLifeMessage"`
	Cadence       string `json:"cadence"`
	Commits       string `json:"commits"`
	Committers    string `json:"committers"`
	NewerVersions string `json:"newerVersions"`
	LatestVersion string `json:"latestVersion"`
}

func GetOperationalRiskViolationReadableData(riskReason string, isEol *bool, eolMsg string, cadence *float64, commits *int64, committers *int, latestVersion string, newerVersion *int) OperationalRiskViolationReadableData {
	isEolStr, cadenceStr, commitsStr, committersStr, newerVersionsStr, latestVersionStr := "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
	if isEol != nil {
		isEolStr = strconv.FormatBool(*isEol)
	}
	if cadence != nil {
		cadenceStr = strconv.FormatFloat(*cadence, 'f', -1, 64)
	}
	if committers != nil {
		committersStr = strconv.FormatInt(int64(*committers), 10)
	}
	if commits != nil {
		commitsStr = strconv.FormatInt(*commits, 10)
	}
	if newerVersion != nil {
		newerVersionsStr = strconv.FormatInt(int64(*newerVersion), 10)
	}
	if latestVersion != "" {
		latestVersionStr = latestVersion
	}
	return OperationalRiskViolationReadableData{
		IsEol:         isEolStr,
		Cadence:       cadenceStr,
		Commits:       commitsStr,
		Committers:    committersStr,
		EolMessage:    eolMsg,
		RiskReason:    riskReason,
		LatestVersion: latestVersionStr,
		NewerVersions: newerVersionsStr,
	}
}

type OperationalRiskViolation struct {
	ScaViolation
	OperationalRiskViolationReadableData
}
