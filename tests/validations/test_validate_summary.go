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
	actualValues := validationCountActualValues{
		// Total
		Vulnerabilities: results.GetTotalVulnerabilities(),
		Violations:      results.GetTotalViolations(),
		// Jas vulnerabilities
		SastVulnerabilities:    results.GetTotalVulnerabilities(formats.SastResult),
		SecretsVulnerabilities: results.GetTotalVulnerabilities(formats.SecretsResult),
		IacVulnerabilities:     results.GetTotalVulnerabilities(formats.IacResult),
		// Jas violations
		SastViolations:    results.GetTotalViolations(formats.SastResult),
		SecretsViolations: results.GetTotalViolations(formats.SecretsResult),
		IacViolations:     results.GetTotalViolations(formats.IacResult),
		// Sca vulnerabilities
		ScaVulnerabilities: results.GetTotalVulnerabilities(formats.ScaSecurityResult),
		// Sca violations
		ScaViolations:         results.GetTotalViolations(formats.ScaSecurityResult, formats.ScaLicenseResult, formats.ScaOperationalResult),
		SecurityViolations:    results.GetTotalViolations(formats.ScaSecurityResult),
		LicenseViolations:     results.GetTotalViolations(formats.ScaLicenseResult),
		OperationalViolations: results.GetTotalViolations(formats.ScaOperationalResult),
	}

	// Get applicability status counts
	for _, scan := range results.Scans {
		if scan.Vulnerabilities != nil {
			if scan.Vulnerabilities.ScaResults != nil {
				for _, counts := range scan.Vulnerabilities.ScaResults.Security {
					for status, count := range counts {
						switch status {
						case jasutils.Applicable.String():
							actualValues.ApplicableVulnerabilities += count
						case jasutils.ApplicabilityUndetermined.String():
							actualValues.UndeterminedVulnerabilities += count
						case jasutils.NotCovered.String():
							actualValues.NotCoveredVulnerabilities += count
						case jasutils.NotApplicable.String():
							actualValues.NotApplicableVulnerabilities += count
						case jasutils.MissingContext.String():
							actualValues.MissingContextVulnerabilities += count
						}
					}
				}
			}
			if scan.Vulnerabilities.SecretsResults != nil {
				for _, counts := range *scan.Vulnerabilities.SecretsResults {
					for status, count := range counts {
						if status == jasutils.Inactive.String() {
							actualValues.InactiveSecretsVulnerabilities += count
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
							actualValues.ApplicableViolations += count
						case jasutils.ApplicabilityUndetermined.String():
							actualValues.UndeterminedViolations += count
						case jasutils.NotCovered.String():
							actualValues.NotCoveredViolations += count
						case jasutils.NotApplicable.String():
							actualValues.NotApplicableViolations += count
						case jasutils.MissingContext.String():
							actualValues.MissingContextViolations += count
						}
					}
				}
			}
			if scan.Violations.SecretsResults != nil {
				for _, counts := range *scan.Violations.SecretsResults {
					for status, count := range counts {
						if status == jasutils.Inactive.String() {
							actualValues.InactiveSecretsViolations += count
						}
					}
				}
			}
		}
	}
	if params.Total != nil {
		// Not supported in the summary output
		params.Total.Licenses = 0
	}
	ValidateCount(t, "summary", params, actualValues)
}
