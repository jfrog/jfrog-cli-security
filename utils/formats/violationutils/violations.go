package violationutils

import (
	"fmt"
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

type Violation struct {
	ViolationId string                 `json:"violation_id"`
	Severity    severityutils.Severity `json:"severity"`
	Watch       string                 `json:"watch_name"`
	Policies    []Policy               `json:"matched_policies,omitempty"`
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

type OperationalRiskViolation struct {
	ScaViolation
	OperationalRiskViolationReadableData
}
