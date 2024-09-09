package validations

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/stretchr/testify/assert"
)

// Content should be a Json string of slice of formats.SimpleJsonResults and will be unmarshal.
// Value is set as the Actual content in the validation params
func VerifySimpleJsonResults(t *testing.T, content string, params ValidationParams) {
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err, "Failed to unmarshal content to formats.SimpleJsonResults")
	params.Actual = results
	ValidateCommandSimpleJsonOutput(t, params)
}

// ValidateCommandSimpleJsonOutput validates SimpleJsonResults results. params.Actual (and params.Expected if provided) should be of type formats.SimpleJsonResults
func ValidateCommandSimpleJsonOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.(formats.SimpleJsonResults)
	if assert.True(t, ok, "Actual content is not of type formats.SimpleJsonResults") {
		ValidateSimpleJsonIssuesCount(t, params, results)
		if params.Expected != nil {
			expectedResults, ok := params.Expected.(formats.SimpleJsonResults)
			if assert.True(t, ok, "Expected content is not of type formats.SimpleJsonResults") {
				ValidateSimpleJsonResults(t, params.ExactResultsMatch, expectedResults, results)
			}
		}
	}
}

func ValidateSimpleJsonIssuesCount(t *testing.T, params ValidationParams, results formats.SimpleJsonResults) {
	var applicableResults, undeterminedResults, notCoveredResults, notApplicableResults int
	for _, vuln := range results.Vulnerabilities {
		switch vuln.Applicable {
		case string(jasutils.NotApplicable):
			notApplicableResults++
		case string(jasutils.Applicable):
			applicableResults++
		case string(jasutils.NotCovered):
			notCoveredResults++
		case string(jasutils.ApplicabilityUndetermined):
			undeterminedResults++
		}
	}

	if params.ExactResultsMatch {
		assert.Equal(t, params.Sast, len(results.Sast), "Expected %d sast in scan responses, but got %d sast.", params.Sast, len(results.Sast))
		assert.Equal(t, params.Secrets, len(results.Secrets), "Expected %d secrets in scan responses, but got %d secrets.", params.Secrets, len(results.Secrets))
		assert.Equal(t, params.Iac, len(results.Iacs), "Expected %d IaC in scan responses, but got %d IaC.", params.Iac, len(results.Iacs))

		assert.Equal(t, params.Applicable, applicableResults, "Expected %d applicable vulnerabilities in scan responses, but got %d applicable vulnerabilities.", params.Applicable, applicableResults)
		assert.Equal(t, params.Undetermined, undeterminedResults, "Expected %d undetermined vulnerabilities in scan responses, but got %d undetermined vulnerabilities.", params.Undetermined, undeterminedResults)
		assert.Equal(t, params.NotCovered, notCoveredResults, "Expected %d not covered vulnerabilities in scan responses, but got %d not covered vulnerabilities.", params.NotCovered, notCoveredResults)
		assert.Equal(t, params.NotApplicable, notApplicableResults, "Expected %d not applicable vulnerabilities in scan responses, but got %d not applicable vulnerabilities.", params.NotApplicable, notApplicableResults)

		assert.Equal(t, params.SecurityViolations, len(results.SecurityViolations), "Expected %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, len(results.SecurityViolations))
		assert.Equal(t, params.LicenseViolations, len(results.LicensesViolations), "Expected %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, len(results.LicensesViolations))
		assert.Equal(t, params.OperationalViolations, len(results.OperationalRiskViolations), "Expected %d operational risk violations in scan responses, but got %d operational risk violations.", params.OperationalViolations, len(results.OperationalRiskViolations))

		assert.Equal(t, params.Licenses, len(results.Licenses), "Expected %d Licenses in scan responses, but got %d Licenses.", params.Licenses, len(results.Licenses))
		return
	}
	assert.GreaterOrEqual(t, len(results.Sast), params.Sast, "Expected at least %d sast in scan responses, but got %d sast.", params.Sast, len(results.Sast))
	assert.GreaterOrEqual(t, len(results.Secrets), params.Secrets, "Expected at least %d secrets in scan responses, but got %d secrets.", params.Secrets, len(results.Secrets))
	assert.GreaterOrEqual(t, len(results.Iacs), params.Iac, "Expected at least %d IaC in scan responses, but got %d IaC.", params.Iac, len(results.Iacs))

	assert.GreaterOrEqual(t, applicableResults, params.Applicable, "Expected at least %d applicable vulnerabilities in scan responses, but got %d applicable vulnerabilities.", params.Applicable, applicableResults)
	assert.GreaterOrEqual(t, undeterminedResults, params.Undetermined, "Expected at least %d undetermined vulnerabilities in scan responses, but got %d undetermined vulnerabilities.", params.Undetermined, undeterminedResults)
	assert.GreaterOrEqual(t, notCoveredResults, params.NotCovered, "Expected at least %d not covered vulnerabilities in scan responses, but got %d not covered vulnerabilities.", params.NotCovered, notCoveredResults)
	assert.GreaterOrEqual(t, notApplicableResults, params.NotApplicable, "Expected at least %d not applicable vulnerabilities in scan responses, but got %d not applicable vulnerabilities.", params.NotApplicable, notApplicableResults)

	assert.GreaterOrEqual(t, len(results.SecurityViolations), params.SecurityViolations, "Expected at least %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, len(results.SecurityViolations))
	assert.GreaterOrEqual(t, len(results.LicensesViolations), params.LicenseViolations, "Expected at least %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, len(results.LicensesViolations))
	assert.GreaterOrEqual(t, len(results.OperationalRiskViolations), params.OperationalViolations, "Expected at least %d operational risk violations in scan responses, but got %d operational risk violations.", params.OperationalViolations, len(results.OperationalRiskViolations))

	assert.GreaterOrEqual(t, len(results.Licenses), params.Licenses, "Expected at least %d Licenses in scan responses, but got %d Licenses.", params.Licenses, len(results.Licenses))
}

func ValidateSimpleJsonResults(t *testing.T, exactMatch bool, expected, actual formats.SimpleJsonResults) {
	validateContent(t, exactMatch, StringValidation{Expected: expected.MultiScanId, Actual: actual.MultiScanId, Msg: "MultiScanId mismatch"})
	validateContent(t, false, NumberValidation[int]{Expected: len(expected.Errors), Actual: len(actual.Errors), Msg: "Errors count mismatch"})
	// Validate vulnerabilities
	for _, expectedVulnerability := range expected.Vulnerabilities {
		vulnerability := getVulnerabilityOrViolationByIssueId(expectedVulnerability.IssueId, actual.Vulnerabilities)
		if !assert.NotNil(t, vulnerability, fmt.Sprintf("IssueId %s not found in the vulnerabilities", expectedVulnerability.IssueId)) {
			return
		}
		validateVulnerabilityOrViolationRow(t, exactMatch, expectedVulnerability, *vulnerability)
	}
	// Validate securityViolations
	for _, expectedViolation := range expected.SecurityViolations {
		violation := getVulnerabilityOrViolationByIssueId(expectedViolation.IssueId, actual.SecurityViolations)
		if !assert.NotNil(t, violation, fmt.Sprintf("IssueId %s not found in the securityViolations", expectedViolation.IssueId)) {
			return
		}
		validateVulnerabilityOrViolationRow(t, exactMatch, expectedViolation, *violation)
	}
}

func getVulnerabilityOrViolationByIssueId(issueId string, content []formats.VulnerabilityOrViolationRow) *formats.VulnerabilityOrViolationRow {
	for _, result := range content {
		if result.IssueId == issueId {
			return &result
		}
	}
	return nil
}

func validateVulnerabilityOrViolationRow(t *testing.T, exactMatch bool, expected, actual formats.VulnerabilityOrViolationRow) {
	validateContent(t, exactMatch,
		StringValidation{Expected: expected.Summary, Actual: actual.Summary, Msg: fmt.Sprintf("IssueId %s: Summary mismatch", expected.IssueId)},
		StringValidation{Expected: expected.Severity, Actual: actual.Severity, Msg: fmt.Sprintf("IssueId %s: Severity mismatch", expected.IssueId)},
		StringValidation{Expected: expected.Applicable, Actual: actual.Applicable, Msg: fmt.Sprintf("IssueId %s: Applicable mismatch", expected.IssueId)},
		StringValidation{Expected: expected.Technology.String(), Actual: actual.Technology.String(), Msg: fmt.Sprintf("IssueId %s: Technology mismatch", expected.IssueId)},
		ListValidation[string]{Expected: expected.References, Actual: actual.References, Msg: fmt.Sprintf("IssueId %s: References mismatch", expected.IssueId)},

		StringValidation{Expected: expected.ImpactedDependencyName, Actual: actual.ImpactedDependencyName, Msg: fmt.Sprintf("IssueId %s: ImpactedDependencyName mismatch", expected.IssueId)},
		StringValidation{Expected: expected.ImpactedDependencyVersion, Actual: actual.ImpactedDependencyVersion, Msg: fmt.Sprintf("IssueId %s: ImpactedDependencyVersion mismatch", expected.IssueId)},
		StringValidation{Expected: expected.ImpactedDependencyType, Actual: actual.ImpactedDependencyType, Msg: fmt.Sprintf("IssueId %s: ImpactedDependencyType mismatch", expected.IssueId)},

		ListValidation[string]{Expected: expected.FixedVersions, Actual: actual.FixedVersions, Msg: fmt.Sprintf("IssueId %s: FixedVersions mismatch", expected.IssueId)},
	)
	if ValidatePointersAndNotNil(t, exactMatch, PointerValidation[formats.JfrogResearchInformation]{Expected: expected.JfrogResearchInformation, Actual: actual.JfrogResearchInformation, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation mismatch", expected.IssueId)}) {
		validateContent(t, exactMatch,
			StringValidation{Expected: expected.JfrogResearchInformation.Summary, Actual: actual.JfrogResearchInformation.Summary, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Summary mismatch", expected.IssueId)},
			StringValidation{Expected: expected.JfrogResearchInformation.Severity, Actual: actual.JfrogResearchInformation.Severity, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Severity mismatch", expected.IssueId)},
			StringValidation{Expected: expected.JfrogResearchInformation.Remediation, Actual: actual.JfrogResearchInformation.Remediation, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Remediation mismatch", expected.IssueId)},
			ListValidation[formats.JfrogResearchSeverityReason]{Expected: expected.JfrogResearchInformation.SeverityReasons, Actual: actual.JfrogResearchInformation.SeverityReasons, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.SeverityReasons mismatch", expected.IssueId)},
		)
	}
	validateComponentRows(t, expected.IssueId, exactMatch, expected.Components, actual.Components)
	validateCveRows(t, expected.IssueId, exactMatch, expected.Cves, actual.Cves)
	if exactMatch {
		assert.ElementsMatch(t, expected.ImpactPaths, actual.ImpactPaths, fmt.Sprintf("IssueId %s: ImpactPaths mismatch", expected.IssueId))
	} else {
		assert.Len(t, actual.ImpactPaths, len(expected.ImpactPaths), fmt.Sprintf("IssueId %s: ImpactPaths count mismatch", expected.IssueId))
	}
}

func validateComponentRows(t *testing.T, issueId string, exactMatch bool, expected, actual []formats.ComponentRow) {
	if exactMatch && !assert.Len(t, actual, len(expected), fmt.Sprintf("IssueId %s: Components count mismatch", issueId)) {
		return
	}
	for _, expectedComponent := range expected {
		component := getComponent(expectedComponent.Name, expectedComponent.Version, actual)
		if !assert.NotNil(t, component, fmt.Sprintf("IssueId %s: Component %s: not found in the components", issueId, expectedComponent.Name)) {
			return
		}
		validateComponentRow(t, issueId, exactMatch, expectedComponent, *component)
	}
}

func validateComponentRow(t *testing.T, issueId string, exactMatch bool, expected, actual formats.ComponentRow) {
	validateContent(t, exactMatch,
		PointerValidation[formats.Location]{Expected: expected.Location, Actual: actual.Location, Msg: fmt.Sprintf("IssueId %s: Component %s:%s Location mismatch", issueId, expected.Name, expected.Version)},
	)
	if expected.Location != nil {
		validateContent(t, exactMatch, StringValidation{Expected: expected.Location.File, Actual: actual.Location.File, Msg: fmt.Sprintf("IssueId %s: Component %s:%s Location.File mismatch", issueId, expected.Name, expected.Version)})
	}
}

func getComponent(name, version string, content []formats.ComponentRow) *formats.ComponentRow {
	for _, result := range content {
		if result.Name == name && result.Version == version {
			return &result
		}
	}
	return nil
}

func validateCveRows(t *testing.T, issueId string, exactMatch bool, expected, actual []formats.CveRow) {
	if exactMatch && !assert.Len(t, actual, len(expected), fmt.Sprintf("IssueId %s: CVEs count mismatch", issueId)) {
		return
	}
	for _, expectedCve := range expected {
		cve := getCve(expectedCve.Id, actual)
		if !assert.NotNil(t, cve, fmt.Sprintf("IssueId %s: CVE %s not found in the CVEs", issueId, expectedCve.Id)) {
			return
		}
		validateCveRow(t, issueId, exactMatch, expectedCve, *cve)
	}
}

func validateCveRow(t *testing.T, issueId string, exactMatch bool, expected, actual formats.CveRow) {
	if !validateContent(t, exactMatch,
		StringValidation{Expected: expected.CvssV2, Actual: actual.CvssV2, Msg: fmt.Sprintf("IssueId %s: Cve %s: CvssV2 mismatch", issueId, expected.Id)},
		StringValidation{Expected: expected.CvssV3, Actual: actual.CvssV3, Msg: fmt.Sprintf("IssueId %s: Cve %s: CvssV3 mismatch", issueId, expected.Id)},
	) {
		return
	}
	if ValidatePointersAndNotNil(t, exactMatch, PointerValidation[formats.Applicability]{Expected: expected.Applicability, Actual: actual.Applicability, Msg: fmt.Sprintf("IssueId %s: Cve %s: Applicability mismatch", issueId, expected.Id)}) {
		validateContent(t, exactMatch,
			StringValidation{Expected: expected.Applicability.Status, Actual: actual.Applicability.Status, Msg: fmt.Sprintf("IssueId %s: Cve %s: Applicability.Status mismatch", issueId, expected.Id)},
			StringValidation{Expected: expected.Applicability.ScannerDescription, Actual: actual.Applicability.ScannerDescription, Msg: fmt.Sprintf("IssueId %s: Cve %s: Applicability.ScannerDescription mismatch", issueId, expected.Id)},
			ListValidation[formats.Evidence]{Expected: expected.Applicability.Evidence, Actual: actual.Applicability.Evidence, Msg: fmt.Sprintf("IssueId %s: Cve %s: Applicability.Evidence mismatch", issueId, expected.Id)},
		)
	}
}

func getCve(cve string, content []formats.CveRow) *formats.CveRow {
	for _, result := range content {
		if result.Id == cve {
			return &result
		}
	}
	return nil
}
