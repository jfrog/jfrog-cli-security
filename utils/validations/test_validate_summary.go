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
	var vulnerabilities, securityViolations, licenseViolations, opRiskViolations, applicableResults, undeterminedResults, notCoveredResults, notApplicableResults, missingContextResults, sast, iac, secrets int

	vulnerabilities = results.GetTotalVulnerabilities()

	securityViolations = results.GetTotalViolations(formats.ScaSecurityResult)
	licenseViolations = results.GetTotalViolations(formats.ScaLicenseResult)
	opRiskViolations = results.GetTotalViolations(formats.ScaOperationalResult)
	// Jas Results only available as vulnerabilities
	sast = results.GetTotalVulnerabilities(formats.SastResult)
	secrets = results.GetTotalVulnerabilities(formats.SecretsResult)
	iac = results.GetTotalVulnerabilities(formats.IacResult)
	// Get applicability status counts
	for _, scan := range results.Scans {
		if scan.Vulnerabilities != nil {
			if scan.Vulnerabilities.ScaResults != nil {
				for _, counts := range scan.Vulnerabilities.ScaResults.Security {
					for status, count := range counts {
						switch status {
						case jasutils.Applicable.String():
							applicableResults += count
						case jasutils.ApplicabilityUndetermined.String():
							undeterminedResults += count
						case jasutils.NotCovered.String():
							notCoveredResults += count
						case jasutils.NotApplicable.String():
							notApplicableResults += count
						case jasutils.MissingContext.String():
							missingContextResults += count
						}
					}
				}
			}
		}
	}

	ValidateContent(t, params.ExactResultsMatch,
		CountValidation[int]{Expected: params.Vulnerabilities, Actual: vulnerabilities, Msg: GetValidationCountErrMsg("vulnerabilities", "summary", params.ExactResultsMatch, params.Vulnerabilities, vulnerabilities)},
		CountValidation[int]{Expected: params.Sast, Actual: sast, Msg: GetValidationCountErrMsg("sast", "summary", params.ExactResultsMatch, params.Sast, sast)},
		CountValidation[int]{Expected: params.Secrets, Actual: secrets, Msg: GetValidationCountErrMsg("secrets", "summary", params.ExactResultsMatch, params.Secrets, secrets)},
		CountValidation[int]{Expected: params.Iac, Actual: iac, Msg: GetValidationCountErrMsg("IaC", "summary", params.ExactResultsMatch, params.Iac, iac)},
		CountValidation[int]{Expected: params.Applicable, Actual: applicableResults, Msg: GetValidationCountErrMsg("applicable vulnerabilities", "summary", params.ExactResultsMatch, params.Applicable, applicableResults)},
		CountValidation[int]{Expected: params.Undetermined, Actual: undeterminedResults, Msg: GetValidationCountErrMsg("undetermined vulnerabilities", "summary", params.ExactResultsMatch, params.Undetermined, undeterminedResults)},
		CountValidation[int]{Expected: params.NotCovered, Actual: notCoveredResults, Msg: GetValidationCountErrMsg("not covered vulnerabilities", "summary", params.ExactResultsMatch, params.NotCovered, notCoveredResults)},
		CountValidation[int]{Expected: params.NotApplicable, Actual: notApplicableResults, Msg: GetValidationCountErrMsg("not applicable vulnerabilities", "summary", params.ExactResultsMatch, params.NotApplicable, notApplicableResults)},
		CountValidation[int]{Expected: params.MissingContext, Actual: missingContextResults, Msg: GetValidationCountErrMsg("missing context vulnerabilities", "summary", params.ExactResultsMatch, params.MissingContext, missingContextResults)},
		CountValidation[int]{Expected: params.SecurityViolations, Actual: securityViolations, Msg: GetValidationCountErrMsg("security violations", "summary", params.ExactResultsMatch, params.SecurityViolations, securityViolations)},
		CountValidation[int]{Expected: params.LicenseViolations, Actual: licenseViolations, Msg: GetValidationCountErrMsg("license violations", "summary", params.ExactResultsMatch, params.LicenseViolations, licenseViolations)},
		CountValidation[int]{Expected: params.OperationalViolations, Actual: opRiskViolations, Msg: GetValidationCountErrMsg("operational risk violations", "summary", params.ExactResultsMatch, params.OperationalViolations, opRiskViolations)},
	)
}
