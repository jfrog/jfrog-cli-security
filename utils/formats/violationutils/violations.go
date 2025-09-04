package violationutils

import "github.com/jfrog/jfrog-cli-security/utils/severityutils"

const (
	CustomLicenseViolationId = "custom_license_violation"
)

const (
	ViolationTypeSecurity        ViolationIssueType = "security"
	ViolationTypeLicense         ViolationIssueType = "license"
	ViolationTypeOperationalRisk ViolationIssueType = "operational_risk"
)

type ViolationIssueType string

func (v ViolationIssueType) String() string {
	return string(v)
}

type Violation struct {
	ViolationId string                 `json:"violation_id"`
	Severity    severityutils.Severity `json:"severity"`
	// Can be used to match the related vulnerability in the scan results.
	IssueId string `json:"issue_id"`
}

type MatchedPolicy struct {
	Watch  string `json:"watch_name"`
	Policy string `json:"policy"`
}
