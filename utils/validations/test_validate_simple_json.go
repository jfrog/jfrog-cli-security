package validations

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/stretchr/testify/assert"
)

// Validate simple-json report results according to the expected values and issue counts in the validation params.
// Content/Expected should be a formats.SimpleJsonResults in the validation params.
// If Expected is provided, the validation will check if the Actual content matches the expected results.
// If ExactResultsMatch is true, the validation will check exact values and not only the 'equal or grater' counts / existence of expected attributes. (For Integration tests with JFrog API, ExactResultsMatch should be set to false)
func VerifySimpleJsonResults(t *testing.T, content string, params ValidationParams) {
	var results formats.SimpleJsonResults
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err, "Failed to unmarshal content to formats.SimpleJsonResults")
	params.Actual = results
	ValidateCommandSimpleJsonOutput(t, params)
}

// Validate simple-json report results according to the expected values and issue counts in the validation params.
// Actual/Expected content should be a formats.SimpleJsonResults in the validation params.
// If Expected is provided, the validation will check if the Actual content matches the expected results.
// If ExactResultsMatch is true, the validation will check exact values and not only the 'equal or grater' counts / existence of expected attributes. (For Integration tests with JFrog API, ExactResultsMatch should be set to false)
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

// Validate simple-json report results according to the expected counts in the validation params.
// Actual content should be a formats.SimpleJsonResults in the validation params.
// If Expected is provided, the validation will check if the Actual content matches the expected results.
// If ExactResultsMatch is true, the validation will check exact values and not only the 'equal or grater' counts / existence of expected attributes. (For Integration tests with JFrog API, ExactResultsMatch should be set to false)
func ValidateSimpleJsonIssuesCount(t *testing.T, params ValidationParams, results formats.SimpleJsonResults) {
	var applicableResults, undeterminedResults, notCoveredResults, notApplicableResults, missingContextResults, inactiveResults int
	for _, vuln := range results.Vulnerabilities {
		switch vuln.Applicable {
		case jasutils.NotApplicable.String():
			notApplicableResults++
		case jasutils.Applicable.String():
			applicableResults++
		case jasutils.NotCovered.String():
			notCoveredResults++
		case jasutils.ApplicabilityUndetermined.String():
			undeterminedResults++
		case jasutils.MissingContext.String():
			missingContextResults++
		}
	}
	for _, result := range results.Secrets {
		if result.Applicability != nil {
			if result.Applicability.Status == jasutils.Inactive.String() {
				inactiveResults += 1
			}
		}
	}
	vulnerabilitiesCount := len(results.Vulnerabilities) + len(results.Secrets) + len(results.Sast) + len(results.Iacs)

	ValidateContent(t, params.ExactResultsMatch,
		CountValidation[int]{Expected: params.Vulnerabilities, Actual: vulnerabilitiesCount, Msg: GetValidationCountErrMsg("vulnerabilities", "simple-json", params.ExactResultsMatch, params.Vulnerabilities, vulnerabilitiesCount)},
		CountValidation[int]{Expected: params.Sast, Actual: len(results.Sast), Msg: GetValidationCountErrMsg("sast", "simple-json", params.ExactResultsMatch, params.Sast, len(results.Sast))},
		CountValidation[int]{Expected: params.Iac, Actual: len(results.Iacs), Msg: GetValidationCountErrMsg("IaC", "simple-json", params.ExactResultsMatch, params.Iac, len(results.Iacs))},
		CountValidation[int]{Expected: params.Secrets, Actual: len(results.Secrets), Msg: GetValidationCountErrMsg("secrets", "simple-json", params.ExactResultsMatch, params.Secrets, len(results.Secrets))},
		CountValidation[int]{Expected: params.Inactive, Actual: inactiveResults, Msg: GetValidationCountErrMsg("inactive secrets", "simple-json", params.ExactResultsMatch, params.Inactive, inactiveResults)},

		CountValidation[int]{Expected: params.Applicable, Actual: applicableResults, Msg: GetValidationCountErrMsg("applicable vulnerabilities", "simple-json", params.ExactResultsMatch, params.Applicable, applicableResults)},
		CountValidation[int]{Expected: params.Undetermined, Actual: undeterminedResults, Msg: GetValidationCountErrMsg("undetermined vulnerabilities", "simple-json", params.ExactResultsMatch, params.Undetermined, undeterminedResults)},
		CountValidation[int]{Expected: params.NotCovered, Actual: notCoveredResults, Msg: GetValidationCountErrMsg("not covered vulnerabilities", "simple-json", params.ExactResultsMatch, params.NotCovered, notCoveredResults)},
		CountValidation[int]{Expected: params.NotApplicable, Actual: notApplicableResults, Msg: GetValidationCountErrMsg("not applicable vulnerabilities", "simple-json", params.ExactResultsMatch, params.NotApplicable, notApplicableResults)},
		CountValidation[int]{Expected: params.MissingContext, Actual: missingContextResults, Msg: GetValidationCountErrMsg("missing context vulnerabilities", "simple-json", params.ExactResultsMatch, params.MissingContext, missingContextResults)},

		CountValidation[int]{Expected: params.SecurityViolations, Actual: len(results.SecurityViolations), Msg: GetValidationCountErrMsg("security violations", "simple-json", params.ExactResultsMatch, params.SecurityViolations, len(results.SecurityViolations))},
		CountValidation[int]{Expected: params.LicenseViolations, Actual: len(results.LicensesViolations), Msg: GetValidationCountErrMsg("license violations", "simple-json", params.ExactResultsMatch, params.LicenseViolations, len(results.LicensesViolations))},
		CountValidation[int]{Expected: params.OperationalViolations, Actual: len(results.OperationalRiskViolations), Msg: GetValidationCountErrMsg("operational risk violations", "simple-json", params.ExactResultsMatch, params.OperationalViolations, len(results.OperationalRiskViolations))},
		CountValidation[int]{Expected: params.Licenses, Actual: len(results.Licenses), Msg: GetValidationCountErrMsg("Licenses", "simple-json", params.ExactResultsMatch, params.Licenses, len(results.Licenses))},
	)
}

func ValidateSimpleJsonResults(t *testing.T, exactMatch bool, expected, actual formats.SimpleJsonResults) {
	ValidateContent(t, exactMatch, StringValidation{Expected: expected.MultiScanId, Actual: actual.MultiScanId, Msg: "MultiScanId mismatch"})
	ValidateContent(t, false, NumberValidation[int]{Expected: len(expected.Errors), Actual: len(actual.Errors), Msg: "Errors count mismatch"})
	// Validate vulnerabilities
	for _, expectedVulnerability := range expected.Vulnerabilities {
		vulnerability := getVulnerabilityOrViolationByIssueId(expectedVulnerability.IssueId, expectedVulnerability.ImpactedDependencyName, expectedVulnerability.ImpactedDependencyVersion, actual.Vulnerabilities)
		if !assert.NotNil(t, vulnerability, fmt.Sprintf("IssueId %s not found in the vulnerabilities", expectedVulnerability.IssueId)) {
			return
		}
		validateVulnerabilityOrViolationRow(t, exactMatch, expectedVulnerability, *vulnerability)
	}
	// Validate securityViolations
	for _, expectedViolation := range expected.SecurityViolations {
		violation := getVulnerabilityOrViolationByIssueId(expectedViolation.IssueId, expectedViolation.ImpactedDependencyName, expectedViolation.ImpactedDependencyVersion, actual.SecurityViolations)
		if !assert.NotNil(t, violation, fmt.Sprintf("IssueId %s not found in the securityViolations", expectedViolation.IssueId)) {
			return
		}
		validateVulnerabilityOrViolationRow(t, exactMatch, expectedViolation, *violation)
	}
}

func getVulnerabilityOrViolationByIssueId(issueId, impactedDependencyName, impactedDependencyVersion string, content []formats.VulnerabilityOrViolationRow) *formats.VulnerabilityOrViolationRow {
	for _, result := range content {
		if result.IssueId == issueId && result.ImpactedDependencyName == impactedDependencyName && result.ImpactedDependencyVersion == impactedDependencyVersion {
			return &result
		}
	}
	return nil
}

func validateVulnerabilityOrViolationRow(t *testing.T, exactMatch bool, expected, actual formats.VulnerabilityOrViolationRow) {
	ValidateContent(t, exactMatch,
		StringValidation{Expected: expected.Summary, Actual: actual.Summary, Msg: fmt.Sprintf("IssueId %s: Summary mismatch", expected.IssueId)},
		StringValidation{Expected: expected.Severity, Actual: actual.Severity, Msg: fmt.Sprintf("IssueId %s: Severity mismatch", expected.IssueId)},
		StringValidation{Expected: expected.Applicable, Actual: actual.Applicable, Msg: fmt.Sprintf("IssueId %s: Applicable mismatch", expected.IssueId)},
		StringValidation{Expected: expected.Technology.String(), Actual: actual.Technology.String(), Msg: fmt.Sprintf("IssueId %s: Technology mismatch", expected.IssueId)},
		ListValidation[string]{Expected: expected.References, Actual: actual.References, Msg: fmt.Sprintf("IssueId %s: References mismatch", expected.IssueId)},

		StringValidation{Expected: expected.ImpactedDependencyType, Actual: actual.ImpactedDependencyType, Msg: fmt.Sprintf("IssueId %s: ImpactedDependencyType mismatch", expected.IssueId)},

		ListValidation[string]{Expected: expected.FixedVersions, Actual: actual.FixedVersions, Msg: fmt.Sprintf("IssueId %s: FixedVersions mismatch", expected.IssueId)},
	)
	if ValidatePointersAndNotNil(t, exactMatch, PointerValidation[formats.JfrogResearchInformation]{Expected: expected.JfrogResearchInformation, Actual: actual.JfrogResearchInformation, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation mismatch", expected.IssueId)}) {
		ValidateContent(t, exactMatch,
			StringValidation{Expected: expected.JfrogResearchInformation.Summary, Actual: actual.JfrogResearchInformation.Summary, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Summary mismatch", expected.IssueId)},
			StringValidation{Expected: expected.JfrogResearchInformation.Severity, Actual: actual.JfrogResearchInformation.Severity, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Severity mismatch", expected.IssueId)},
			StringValidation{Expected: expected.JfrogResearchInformation.Remediation, Actual: actual.JfrogResearchInformation.Remediation, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.Remediation mismatch", expected.IssueId)},
			ListValidation[formats.JfrogResearchSeverityReason]{Expected: expected.JfrogResearchInformation.SeverityReasons, Actual: actual.JfrogResearchInformation.SeverityReasons, Msg: fmt.Sprintf("IssueId %s: JfrogResearchInformation.SeverityReasons mismatch", expected.IssueId)},
		)
	}
	validateComponentRows(t, expected.IssueId, exactMatch, expected.Components, actual.Components)
	validateCveRows(t, expected.IssueId, exactMatch, expected.Cves, actual.Cves)
	validateImpactPaths(t, expected.IssueId, exactMatch, expected.ImpactPaths, actual.ImpactPaths)
}

func validateImpactPaths(t *testing.T, issueId string, exactMatch bool, expected, actual [][]formats.ComponentRow) {
	assert.Len(t, actual, len(expected), fmt.Sprintf("IssueId %s: ImpactPaths count mismatch", issueId))
	if !exactMatch {
		return
	}
	for _, expectedPath := range expected {
		impactPath := getImpactPath(expectedPath, actual)
		if !assert.NotNil(t, impactPath, fmt.Sprintf("IssueId %s: expected ImpactPath not found in the impactPaths", issueId)) {
			return
		}
	}
}

func getImpactPath(path []formats.ComponentRow, content [][]formats.ComponentRow) *[]formats.ComponentRow {
	for _, result := range content {
		if len(result) != len(path) {
			continue
		}
		found := true
		for i, component := range result {
			if component.Name != path[i].Name || component.Version != path[i].Version {
				found = false
				break
			}
		}
		if found {
			return &result
		}
	}
	return nil
}

func validateComponentRows(t *testing.T, issueId string, exactMatch bool, expected, actual []formats.ComponentRow) {
	assert.Len(t, actual, len(expected), fmt.Sprintf("IssueId %s: Components count mismatch", issueId))
	if !exactMatch {
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
	ValidateContent(t, exactMatch,
		PointerValidation[formats.Location]{Expected: expected.Location, Actual: actual.Location, Msg: fmt.Sprintf("IssueId %s: Component %s:%s Location mismatch", issueId, expected.Name, expected.Version)},
	)
	if expected.Location != nil {
		ValidateContent(t, exactMatch, StringValidation{Expected: expected.Location.File, Actual: actual.Location.File, Msg: fmt.Sprintf("IssueId %s: Component %s:%s Location.File mismatch", issueId, expected.Name, expected.Version)})
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
	assert.Len(t, actual, len(expected), fmt.Sprintf("IssueId %s: CVEs count mismatch", issueId))
	if !exactMatch {
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
	if !ValidateContent(t, exactMatch,
		StringValidation{Expected: expected.CvssV2, Actual: actual.CvssV2, Msg: fmt.Sprintf("IssueId %s: Cve %s: CvssV2 mismatch", issueId, expected.Id)},
		StringValidation{Expected: expected.CvssV3, Actual: actual.CvssV3, Msg: fmt.Sprintf("IssueId %s: Cve %s: CvssV3 mismatch", issueId, expected.Id)},
	) {
		return
	}
	if ValidatePointersAndNotNil(t, exactMatch, PointerValidation[formats.Applicability]{Expected: expected.Applicability, Actual: actual.Applicability, Msg: fmt.Sprintf("IssueId %s: Cve %s: Applicability mismatch", issueId, expected.Id)}) {
		ValidateContent(t, exactMatch,
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
