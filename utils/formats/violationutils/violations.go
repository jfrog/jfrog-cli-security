package violationutils

import "github.com/jfrog/jfrog-cli-security/utils/severityutils"

const (
	ScaViolationType     ViolationType = "sca"
	SecretsViolationType ViolationType = "secrets"
	IacViolationType     ViolationType = "iac"
	SastViolationType    ViolationType = "sast"
)

type ViolationType string

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

type Violation struct {
	Type        ViolationType          `json:"type"`
	ViolationId string                 `json:"violation_id"`
	Severity    severityutils.Severity `json:"severity"`
	// Can be used to match the related vulnerability in the scan results.
	IssueId string `json:"issue_id"`
}

type MatchedPolicy struct {
	Watch  string `json:"watch_name"`
	Policy string `json:"policy"`
}
