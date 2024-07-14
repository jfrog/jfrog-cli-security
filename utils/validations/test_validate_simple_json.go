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
	assert.NoError(t, err)
	params.Actual = results
	ValidateCommandSimpleJsonOutput(t, params)
}

func ValidateCommandSimpleJsonOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.(formats.SimpleJsonResults)
	if assert.True(t, ok) {
		ValidateSimpleJsonIssuesCount(t, params, results)
		if params.Expected != nil {
			expectedResults, ok := params.Expected.(formats.SimpleJsonResults)
			if assert.True(t, ok) {
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
	} else {
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
}

func ValidateSimpleJsonResults(t *testing.T, exactMatch bool, expected, actual formats.SimpleJsonResults) {
	validatePairs(t, exactMatch, ValidationPair{ Expected: expected.MultiScanId, Actual: actual.MultiScanId, ErrMsg: "MultiScanId mismatch" })
	validatePairs(t, false, ValidationPair{ Expected: len(expected.Errors), Actual: len(actual.Errors), ErrMsg: "Errors count mismatch" })
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
	validatePairs(t, exactMatch, 
		ValidationPair{ Expected: expected.Summary, Actual: actual.Summary, ErrMsg: fmt.Sprintf("IssueId %s: Summary mismatch", expected.IssueId) },
		ValidationPair{ Expected: expected.Severity, Actual: actual.Severity, ErrMsg: fmt.Sprintf("IssueId %s: Severity mismatch", expected.IssueId) },
		ValidationPair{ Expected: expected.Applicable, Actual: actual.Applicable, ErrMsg: fmt.Sprintf("IssueId %s: Applicable mismatch", expected.IssueId) },
		ValidationPair{ Expected: expected.Technology, Actual: actual.Technology, ErrMsg: fmt.Sprintf("IssueId %s: Technology mismatch", expected.IssueId) },
		ValidationPair{ Expected: expected.References, Actual: actual.References, ErrMsg: fmt.Sprintf("IssueId %s: References mismatch", expected.IssueId) },

		ValidationPair{ Expected: expected.ImpactedDependencyName, Actual: actual.ImpactedDependencyName, ErrMsg: fmt.Sprintf("IssueId %s: ImpactedDependencyName mismatch", expected.IssueId) },
		ValidationPair{ Expected: expected.ImpactedDependencyVersion, Actual: actual.ImpactedDependencyVersion, ErrMsg: fmt.Sprintf("IssueId %s: ImpactedDependencyVersion mismatch", expected.IssueId) },
		ValidationPair{ Expected: expected.ImpactedDependencyType, Actual: actual.ImpactedDependencyType, ErrMsg: fmt.Sprintf("IssueId %s: ImpactedDependencyType mismatch", expected.IssueId) },

		ValidationPair{ Expected: expected.FixedVersions, Actual: actual.FixedVersions, ErrMsg: fmt.Sprintf("IssueId %s: FixedVersions mismatch", expected.IssueId) },
	)
	if validatePairs(t, exactMatch, ValidationPair{ Expected: expected.JfrogResearchInformation, Actual: actual.JfrogResearchInformation}) && expected.JfrogResearchInformation != nil {
		validatePairs(t, exactMatch, 
			ValidationPair{ Expected: expected.JfrogResearchInformation.Summary, Actual: actual.JfrogResearchInformation.Summary, ErrMsg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Summary mismatch", expected.IssueId) },
			ValidationPair{ Expected: expected.JfrogResearchInformation.Severity, Actual: actual.JfrogResearchInformation.Severity, ErrMsg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Severity mismatch", expected.IssueId) },
			ValidationPair{ Expected: expected.JfrogResearchInformation.Remediation, Actual: actual.JfrogResearchInformation.Remediation, ErrMsg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Remediation mismatch", expected.IssueId) },
			ValidationPair{ Expected: expected.JfrogResearchInformation.SeverityReasons, Actual: actual.JfrogResearchInformation.SeverityReasons, ErrMsg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.SeverityReasons mismatch", expected.IssueId) },
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
	validatePairs(t, exactMatch, 
		ValidationPair{ Expected: expected.Location, Actual: actual.Location, ErrMsg: fmt.Sprintf("IssueId %s: Component %s:%s Location mismatch", issueId, expected.Name, expected.Version) },
	)
	if expected.Location != nil {
		validatePairs(t, exactMatch, ValidationPair{ Expected: expected.Location.File, Actual: actual.Location.File, ErrMsg: fmt.Sprintf("IssueId %s: Component %s:%s Location.File mismatch", issueId, expected.Name, expected.Version) })
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
	validatePairs(t, exactMatch, 
		ValidationPair{ Expected: expected.CvssV2, Actual: actual.CvssV2, ErrMsg: fmt.Sprintf("IssueId %s: Cve %s: CvssV2 mismatch", issueId, expected.Id) },
		ValidationPair{ Expected: expected.CvssV3, Actual: actual.CvssV3, ErrMsg: fmt.Sprintf("IssueId %s: Cve %s: CvssV3 mismatch", issueId, expected.Id) },
	)
	if validatePairs(t, exactMatch, ValidationPair{ Expected: expected.Applicability, Actual: actual.Applicability, ErrMsg: fmt.Sprintf("IssueId %s: Cve %s: Applicability mismatch", issueId, expected.Id) }) && expected.Applicability != nil {
		validatePairs(t, exactMatch, 
			ValidationPair{ Expected: expected.Applicability.Status, Actual: actual.Applicability.Status, ErrMsg: fmt.Sprintf("IssueId %s: Cve %s: Applicability.Status mismatch", issueId, expected.Id) },
			ValidationPair{ Expected: expected.Applicability.ScannerDescription, Actual: actual.Applicability.ScannerDescription, ErrMsg: fmt.Sprintf("IssueId %s: Cve %s: Applicability.ScannerDescription mismatch", issueId, expected.Id) },
			ValidationPair{ Expected: expected.Applicability.Evidence, Actual: actual.Applicability.Evidence, ErrMsg: fmt.Sprintf("IssueId %s: Cve %s: Applicability.Evidence mismatch", issueId, expected.Id) },
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



// func VerifySimpleJsonJasResults(t *testing.T, content string, minSastViolations, minIacViolations, minSecrets,
// 	minApplicable, minUndetermined, minNotCovered, minNotApplicable int) {
// 	var results formats.SimpleJsonResults
// 	err := json.Unmarshal([]byte(content), &results)
// 	if assert.NoError(t, err) {
// 		assert.GreaterOrEqual(t, len(results.Sast), minSastViolations, "Found less sast then expected")
// 		assert.GreaterOrEqual(t, len(results.Secrets), minSecrets, "Found less secrets then expected")
// 		assert.GreaterOrEqual(t, len(results.Iacs), minIacViolations, "Found less IaC then expected")
// 		var applicableResults, undeterminedResults, notCoveredResults, notApplicableResults int
// 		for _, vuln := range results.Vulnerabilities {
// 			switch vuln.Applicable {
// 			case string(jasutils.NotApplicable):
// 				notApplicableResults++
// 			case string(jasutils.Applicable):
// 				applicableResults++
// 			case string(jasutils.NotCovered):
// 				notCoveredResults++
// 			case string(jasutils.ApplicabilityUndetermined):
// 				undeterminedResults++
// 			}
// 		}
// 		assert.GreaterOrEqual(t, applicableResults, minApplicable, "Found less applicableResults then expected")
// 		assert.GreaterOrEqual(t, undeterminedResults, minUndetermined, "Found less undeterminedResults then expected")
// 		assert.GreaterOrEqual(t, notCoveredResults, minNotCovered, "Found less notCoveredResults then expected")
// 		assert.GreaterOrEqual(t, notApplicableResults, minNotApplicable, "Found less notApplicableResults then expected")
// 	}
// }
