package validations

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/stretchr/testify/assert"
)

// Validate summary results according to the expected values and issue counts in the validation params.
// Content/Expected should be a formats.ResultsSummary in the validation params.
// If Expected is provided, the validation will check if the Actual content matches the expected results.
// If ExactResultsMatch is true, the validation will check exact values and not only the 'equal or grater' counts / existence of expected attributes. (For Integration tests with JFrog API, ExactResultsMatch should be set to false)
func ValidateCommandSummaryOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.(formats.ResultsSummary)
	if assert.True(t, ok, "Actual content is not a formats.ResultsSummary") {
		ValidateSummaryIssuesCount(t, params, results)
	}
}

func ValidateSummaryIssuesCount(t *testing.T, params ValidationParams, results formats.ResultsSummary) {
	var vulnerabilities, applicableVulnerabilitiesResults, undeterminedVulnerabilitiesResults, notCoveredVulnerabilitiesResults, notApplicableVulnerabilitiesResults, missingContextVulnerabilitiesResults, sastVulnerabilities, iacVulnerabilities, secretsVulnerabilities int
	var violations, securityViolations, licenseViolations, opRiskViolations, applicableViolationsResults, undeterminedViolationsResults, notCoveredViolationsResults, notApplicableViolationsResults, missingContextViolationsResults, sastViolations, iacViolations, secretsViolations int
	// Total
	vulnerabilities = results.GetTotalVulnerabilities()
	violations = results.GetTotalViolations()
	// Jas
	sastVulnerabilities = results.GetTotalVulnerabilities(formats.SastResult)
	secretsVulnerabilities = results.GetTotalVulnerabilities(formats.SecretsResult)
	iacVulnerabilities = results.GetTotalVulnerabilities(formats.IacResult)
	sastViolations = results.GetTotalViolations(formats.SastResult)
	secretsViolations = results.GetTotalViolations(formats.SecretsResult)
	iacViolations = results.GetTotalViolations(formats.IacResult)
	// Sca
	securityViolations = results.GetTotalViolations(formats.ScaSecurityResult)
	licenseViolations = results.GetTotalViolations(formats.ScaLicenseResult)
	opRiskViolations = results.GetTotalViolations(formats.ScaOperationalResult)
	// Get applicability status counts
	for _, scan := range results.Scans {
		if scan.Vulnerabilities != nil {
			if scan.Vulnerabilities.ScaResults != nil {
				for _, counts := range scan.Vulnerabilities.ScaResults.Security {
					for status, count := range counts {
						switch status {
						case jasutils.Applicable.String():
							applicableVulnerabilitiesResults += count
						case jasutils.ApplicabilityUndetermined.String():
							undeterminedVulnerabilitiesResults += count
						case jasutils.NotCovered.String():
							notCoveredVulnerabilitiesResults += count
						case jasutils.NotApplicable.String():
							notApplicableVulnerabilitiesResults += count
						case jasutils.MissingContext.String():
							missingContextVulnerabilitiesResults += count
						}
					}
				}
			}
		}
		if scan.Violations != nil {
			if scan.Violations.ScaResults != nil {
				for _, counts := range scan.Violations.ScaResults.Security {
					for status, count := range counts {
						switch status {
						case jasutils.Applicable.String():
							applicableViolationsResults += count
						case jasutils.ApplicabilityUndetermined.String():
							undeterminedViolationsResults += count
						case jasutils.NotCovered.String():
							notCoveredViolationsResults += count
						case jasutils.NotApplicable.String():
							notApplicableViolationsResults += count
						case jasutils.MissingContext.String():
							missingContextViolationsResults += count
						}
					}
				}
			}
		}
	}

	ValidateContent(t, params.ExactResultsMatch,
		// Total
		CountValidation[int]{Expected: params.Vulnerabilities, Actual: vulnerabilities, Msg: GetValidationCountErrMsg("vulnerabilities", "summary", params.ExactResultsMatch, params.Vulnerabilities, vulnerabilities)},
		CountValidation[int]{Expected: params.Violations, Actual: violations, Msg: GetValidationCountErrMsg("violations", "summary", params.ExactResultsMatch, params.Violations, violations)},
		// Jas Vulnerabilities
		CountValidation[int]{Expected: params.SastVulnerabilities, Actual: sastVulnerabilities, Msg: GetValidationCountErrMsg("sast vulnerabilities", "summary", params.ExactResultsMatch, params.SastVulnerabilities, sastVulnerabilities)},
		CountValidation[int]{Expected: params.SecretsVulnerabilities, Actual: secretsVulnerabilities, Msg: GetValidationCountErrMsg("secrets vulnerabilities", "summary", params.ExactResultsMatch, params.SecretsVulnerabilities, secretsVulnerabilities)},
		CountValidation[int]{Expected: params.IacVulnerabilities, Actual: iacVulnerabilities, Msg: GetValidationCountErrMsg("IaC vulnerabilities", "summary", params.ExactResultsMatch, params.IacVulnerabilities, iacVulnerabilities)},
		// Jas Violations
		CountValidation[int]{Expected: params.SastViolations, Actual: sastViolations, Msg: GetValidationCountErrMsg("sast violations", "summary", params.ExactResultsMatch, params.SastViolations, sastViolations)},
		CountValidation[int]{Expected: params.SecretsViolations, Actual: secretsViolations, Msg: GetValidationCountErrMsg("secrets violations", "summary", params.ExactResultsMatch, params.SecretsViolations, secretsViolations)},
		CountValidation[int]{Expected: params.IacViolations, Actual: iacViolations, Msg: GetValidationCountErrMsg("IaC violations", "summary", params.ExactResultsMatch, params.IacViolations, iacViolations)},
		// Sca vulnerabilities
		CountValidation[int]{Expected: params.ApplicableVulnerabilities, Actual: applicableVulnerabilitiesResults, Msg: GetValidationCountErrMsg("applicable vulnerabilities", "summary", params.ExactResultsMatch, params.ApplicableVulnerabilities, applicableVulnerabilitiesResults)},
		CountValidation[int]{Expected: params.UndeterminedVulnerabilities, Actual: undeterminedVulnerabilitiesResults, Msg: GetValidationCountErrMsg("undetermined vulnerabilities", "summary", params.ExactResultsMatch, params.UndeterminedVulnerabilities, undeterminedVulnerabilitiesResults)},
		CountValidation[int]{Expected: params.NotCoveredVulnerabilities, Actual: notCoveredVulnerabilitiesResults, Msg: GetValidationCountErrMsg("not covered vulnerabilities", "summary", params.ExactResultsMatch, params.NotCoveredVulnerabilities, notCoveredVulnerabilitiesResults)},
		CountValidation[int]{Expected: params.NotApplicableVulnerabilities, Actual: notApplicableVulnerabilitiesResults, Msg: GetValidationCountErrMsg("not applicable vulnerabilities", "summary", params.ExactResultsMatch, params.NotApplicableVulnerabilities, notApplicableVulnerabilitiesResults)},
		CountValidation[int]{Expected: params.MissingContextVulnerabilities, Actual: missingContextVulnerabilitiesResults, Msg: GetValidationCountErrMsg("missing context vulnerabilities", "summary", params.ExactResultsMatch, params.MissingContextVulnerabilities, missingContextVulnerabilitiesResults)},
		// Sca violations
		CountValidation[int]{Expected: params.ApplicableViolations, Actual: applicableViolationsResults, Msg: GetValidationCountErrMsg("applicable violations", "summary", params.ExactResultsMatch, params.ApplicableViolations, applicableViolationsResults)},
		CountValidation[int]{Expected: params.UndeterminedViolations, Actual: undeterminedViolationsResults, Msg: GetValidationCountErrMsg("undetermined violations", "summary", params.ExactResultsMatch, params.UndeterminedViolations, undeterminedViolationsResults)},
		CountValidation[int]{Expected: params.NotCoveredViolations, Actual: notCoveredViolationsResults, Msg: GetValidationCountErrMsg("not covered violations", "summary", params.ExactResultsMatch, params.NotCoveredViolations, notCoveredViolationsResults)},
		CountValidation[int]{Expected: params.NotApplicableViolations, Actual: notApplicableViolationsResults, Msg: GetValidationCountErrMsg("not applicable violations", "summary", params.ExactResultsMatch, params.NotApplicableViolations, notApplicableViolationsResults)},
		CountValidation[int]{Expected: params.MissingContextViolations, Actual: missingContextViolationsResults, Msg: GetValidationCountErrMsg("missing context violations", "summary", params.ExactResultsMatch, params.MissingContextViolations, missingContextViolationsResults)},
		CountValidation[int]{Expected: params.ScaSecurityViolations, Actual: securityViolations, Msg: GetValidationCountErrMsg("security violations", "summary", params.ExactResultsMatch, params.ScaSecurityViolations, securityViolations)},
		CountValidation[int]{Expected: params.LicenseViolations, Actual: licenseViolations, Msg: GetValidationCountErrMsg("license violations", "summary", params.ExactResultsMatch, params.LicenseViolations, licenseViolations)},
		CountValidation[int]{Expected: params.OperationalViolations, Actual: opRiskViolations, Msg: GetValidationCountErrMsg("operational risk violations", "summary", params.ExactResultsMatch, params.OperationalViolations, opRiskViolations)},
	)
}
