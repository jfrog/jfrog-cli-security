package formats

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

// Structs in this file should NOT be changed!
// The structs are used as an API for the simple-json format, thus changing their structure or the 'json' annotation will break the API.

// This struct holds the sorted results of the simple-json output.
type SimpleJsonResults struct {
	Vulnerabilities           []VulnerabilityOrViolationRow `json:"vulnerabilities"`
	SecurityViolations        []VulnerabilityOrViolationRow `json:"securityViolations"`
	LicensesViolations        []LicenseViolationRow         `json:"licensesViolations"`
	Licenses                  []LicenseRow                  `json:"licenses"`
	OperationalRiskViolations []OperationalRiskViolationRow `json:"operationalRiskViolations"`
	SecretsVulnerabilities    []SourceCodeRow               `json:"secrets"`
	IacsVulnerabilities       []SourceCodeRow               `json:"iac"`
	SastVulnerabilities       []SourceCodeRow               `json:"sast"`
	SecretsViolations         []SourceCodeRow               `json:"secretsViolations"`
	IacsViolations            []SourceCodeRow               `json:"iacViolations"`
	SastViolations            []SourceCodeRow               `json:"sastViolations"`
	Errors                    []SimpleJsonError             `json:"errors"`
	Statuses                  ScanStatus                    `json:"scansStatus"`
	MultiScanId               string                        `json:"multiScanId,omitempty"`
}

type ScanStatus struct {
	// If not nil, the scan was performed. The value is the status code of the scans. if not 0, the scan failed.
	ScaStatusCode           *int `json:"scaScanStatusCode,omitempty"`
	SastStatusCode          *int `json:"sastScanStatusCode,omitempty"`
	IacStatusCode           *int `json:"iacScanStatusCode,omitempty"`
	SecretsStatusCode       *int `json:"secretsScanStatusCode,omitempty"`
	ApplicabilityStatusCode *int `json:"ContextualAnalysisScanStatusCode,omitempty"`
}

type ViolationContext struct {
	// The watch name that generated the violation
	Watch string `json:"watch,omitempty"`
	// Unique id of the violation if exists
	IssueId string `json:"issueId,omitempty"`
	// The related policy names
	Policies []string `json:"policies,omitempty"`
}

type SeverityDetails struct {
	Severity         string `json:"severity"`
	SeverityNumValue int    `json:"-"` // For sorting
}

type ImpactedDependencyDetails struct {
	SeverityDetails
	ImpactedDependencyName    string         `json:"impactedPackageName"`
	ImpactedDependencyVersion string         `json:"impactedPackageVersion"`
	ImpactedDependencyType    string         `json:"impactedPackageType"`
	Components                []ComponentRow `json:"components"`
}

// Used for vulnerabilities and security violations
type VulnerabilityOrViolationRow struct {
	ImpactedDependencyDetails
	ViolationContext
	Summary                  string                    `json:"summary"`
	Applicable               string                    `json:"applicable"`
	FixedVersions            []string                  `json:"fixedVersions"`
	Cves                     []CveRow                  `json:"cves"`
	IssueId                  string                    `json:"issueId"`
	References               []string                  `json:"references"`
	ImpactPaths              [][]ComponentRow          `json:"impactPaths"`
	JfrogResearchInformation *JfrogResearchInformation `json:"jfrogResearchInformation"`
	Technology               techutils.Technology      `json:"-"`
}

type LicenseViolationRow struct {
	LicenseRow
	ViolationContext
}

type LicenseRow struct {
	ImpactedDependencyDetails
	LicenseKey  string           `json:"licenseKey"`
	LicenseName string           `json:"licenseName,omitempty"`
	ImpactPaths [][]ComponentRow `json:"impactPaths"`
}

type OperationalRiskViolationRow struct {
	ImpactedDependencyDetails
	ViolationContext
	RiskReason    string `json:"riskReason"`
	IsEol         string `json:"isEndOfLife"`
	EolMessage    string `json:"endOfLifeMessage"`
	Cadence       string `json:"cadence"`
	Commits       string `json:"commits"`
	Committers    string `json:"committers"`
	NewerVersions string `json:"newerVersions"`
	LatestVersion string `json:"latestVersion"`
}

type SourceCodeRow struct {
	SeverityDetails
	ViolationContext
	ScannerInfo
	Location
	Finding       string         `json:"finding,omitempty"`
	Fingerprint   string         `json:"fingerprint,omitempty"`
	Applicability *Applicability `json:"applicability,omitempty"`
	CodeFlow      [][]Location   `json:"codeFlow,omitempty"`
}

type ScannerInfo struct {
	RuleId                  string   `json:"ruleId"`
	Cwe                     []string `json:"cwe,omitempty"`
	ScannerShortDescription string   `json:"scannerShortDescription,omitempty"`
	ScannerDescription      string   `json:"scannerDescription,omitempty"`
}

type Location struct {
	File        string `json:"file"`
	StartLine   int    `json:"startLine,omitempty"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndLine     int    `json:"endLine,omitempty"`
	EndColumn   int    `json:"endColumn,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
}

// String Representation of the location (can be used as unique ID of the location)
func (l Location) ToString() string {
	return fmt.Sprintf("%s|%d|%d|%d|%d|%s", l.File, l.StartLine, l.StartColumn, l.EndLine, l.EndColumn, l.Snippet)
}

type ComponentRow struct {
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Location *Location `json:"location,omitempty"`
}

type CveRow struct {
	Id            string         `json:"id"`
	CvssV2        string         `json:"cvssV2"`
	CvssV3        string         `json:"cvssV3"`
	Applicability *Applicability `json:"applicability,omitempty"`
}

type Applicability struct {
	Status             string     `json:"status"`
	ScannerDescription string     `json:"scannerDescription,omitempty"`
	UndeterminedReason string     `json:"undeterminedReason,omitempty"`
	Evidence           []Evidence `json:"evidence,omitempty"`
}

type Evidence struct {
	Location
	Reason string `json:"reason,omitempty"`
}

type SimpleJsonError struct {
	FilePath     string `json:"filePath"`
	ErrorMessage string `json:"errorMessage"`
}

type JfrogResearchInformation struct {
	SeverityDetails
	Summary         string                        `json:"summary,omitempty"`
	Details         string                        `json:"details,omitempty"`
	SeverityReasons []JfrogResearchSeverityReason `json:"severityReasons,omitempty"`
	Remediation     string                        `json:"remediation,omitempty"`
}

type JfrogResearchSeverityReason struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	IsPositive  bool   `json:"isPositive,omitempty"`
}
