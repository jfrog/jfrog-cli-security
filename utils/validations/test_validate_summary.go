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
	var vulnerabilities, securityViolations, licenseViolations, opRiskViolations, applicableResults, undeterminedResults, notCoveredResults, notApplicableResults, sast, iac, secrets int

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
						}
					}
				}
			}
		}
	}
	// validate the counts
	if params.ExactResultsMatch {
		assert.Equal(t, params.Vulnerabilities, vulnerabilities, "Expected %d vulnerabilities in scan responses, but got %d vulnerabilities.", params.Vulnerabilities, vulnerabilities)

		assert.Equal(t, params.Sast, sast, "Expected %d sast in scan responses, but got %d sast.", params.Sast, sast)
		assert.Equal(t, params.Secrets, secrets, "Expected %d secrets in scan responses, but got %d secrets.", params.Secrets, secrets)
		assert.Equal(t, params.Iac, iac, "Expected %d IaC in scan responses, but got %d IaC.", params.Iac, iac)

		assert.Equal(t, params.Applicable, applicableResults, "Expected %d applicable vulnerabilities in scan responses, but got %d applicable vulnerabilities.", params.Applicable, applicableResults)
		assert.Equal(t, params.Undetermined, undeterminedResults, "Expected %d undetermined vulnerabilities in scan responses, but got %d undetermined vulnerabilities.", params.Undetermined, undeterminedResults)
		assert.Equal(t, params.NotCovered, notCoveredResults, "Expected %d not covered vulnerabilities in scan responses, but got %d not covered vulnerabilities.", params.NotCovered, notCoveredResults)
		assert.Equal(t, params.NotApplicable, notApplicableResults, "Expected %d not applicable vulnerabilities in scan responses, but got %d not applicable vulnerabilities.", params.NotApplicable, notApplicableResults)

		assert.Equal(t, params.SecurityViolations, securityViolations, "Expected %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, securityViolations)
		assert.Equal(t, params.LicenseViolations, licenseViolations, "Expected %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, licenseViolations)
		assert.Equal(t, params.OperationalViolations, opRiskViolations, "Expected %d operational risk violations in scan responses, but got %d operational risk violations.", params.OperationalViolations, opRiskViolations)
		return
	}
	assert.GreaterOrEqual(t, vulnerabilities, params.Vulnerabilities, "Expected at least %d vulnerabilities in scan responses, but got %d vulnerabilities.", params.Vulnerabilities, vulnerabilities)

	assert.GreaterOrEqual(t, sast, params.Sast, "Expected at least %d sast in scan responses, but got %d sast.", params.Sast, sast)
	assert.GreaterOrEqual(t, secrets, params.Secrets, "Expected at least %d secrets in scan responses, but got %d secrets.", params.Secrets, secrets)
	assert.GreaterOrEqual(t, iac, params.Iac, "Expected at least %d IaC in scan responses, but got %d IaC.", params.Iac, iac)

	assert.GreaterOrEqual(t, applicableResults, params.Applicable, "Expected at least %d applicable vulnerabilities in scan responses, but got %d applicable vulnerabilities.", params.Applicable, applicableResults)
	assert.GreaterOrEqual(t, undeterminedResults, params.Undetermined, "Expected at least %d undetermined vulnerabilities in scan responses, but got %d undetermined vulnerabilities.", params.Undetermined, undeterminedResults)
	assert.GreaterOrEqual(t, notCoveredResults, params.NotCovered, "Expected at least %d not covered vulnerabilities in scan responses, but got %d not covered vulnerabilities.", params.NotCovered, notCoveredResults)
	assert.GreaterOrEqual(t, notApplicableResults, params.NotApplicable, "Expected at least %d not applicable vulnerabilities in scan responses, but got %d not applicable vulnerabilities.", params.NotApplicable, notApplicableResults)

	assert.GreaterOrEqual(t, securityViolations, params.SecurityViolations, "Expected at least %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, securityViolations)
	assert.GreaterOrEqual(t, licenseViolations, params.LicenseViolations, "Expected at least %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, licenseViolations)
	assert.GreaterOrEqual(t, securityViolations, params.OperationalViolations, "Expected at least %d operational risk violations in scan responses, but got %d operational risk violations.", params.OperationalViolations, opRiskViolations)
}
