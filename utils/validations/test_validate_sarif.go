package validations

import (
	"encoding/json"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

// Content should be a Json string of sarif.Report and will be unmarshal.
// Value is set as the Actual content in the validation params
func VerifySarifResults(t *testing.T, content string, params ValidationParams) {
	var results sarif.Report
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err)
	params.Actual = results
	ValidateCommandSarifOutput(t, params)
}

func ValidateCommandSarifOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.(sarif.Report)
	if assert.True(t, ok) {
		ValidateSarifIssuesCount(t, params, &results)
		// if params.Expected != nil {
		// 	expectedResults, ok := params.Expected.(sarif.Report)
		// 	if assert.True(t, ok) {
		// 		ValidateScanResponses(t, params.ExactResultsMatch, expectedResults, results)
		// 	}
		// }
	}
}

func ValidateSarifIssuesCount(t *testing.T, params ValidationParams, results *sarif.Report) {
	// var sast, iac, secrets, licenseViolations, applicableResults, undeterminedResults, notCoveredResults, notApplicableResults int
	// for _, run := range results.Runs {
	// 	for _, result := range run.Results {
			
	// 	}
	// }

	// for _, vuln := range results.Vulnerabilities {
	// 	switch vuln.Applicable {
	// 	case string(jasutils.NotApplicable):
	// 		notApplicableResults++
	// 	case string(jasutils.Applicable):
	// 		applicableResults++
	// 	case string(jasutils.NotCovered):
	// 		notCoveredResults++
	// 	case string(jasutils.ApplicabilityUndetermined):
	// 		undeterminedResults++
	// 	}
	// }

	// if params.ExactResultsMatch {
	// 	assert.Equal(t, params.Sast, len(results.Sast), "Expected %d sast in scan responses, but got %d sast.", params.Sast, len(results.Sast))
	// 	assert.Equal(t, params.Secrets, len(results.Secrets), "Expected %d secrets in scan responses, but got %d secrets.", params.Secrets, len(results.Secrets))
	// 	assert.Equal(t, params.Iac, len(results.Iacs), "Expected %d IaC in scan responses, but got %d IaC.", params.Iac, len(results.Iacs))

	// 	assert.Equal(t, params.Applicable, applicableResults, "Expected %d applicable vulnerabilities in scan responses, but got %d applicable vulnerabilities.", params.Applicable, applicableResults)
	// 	assert.Equal(t, params.Undetermined, undeterminedResults, "Expected %d undetermined vulnerabilities in scan responses, but got %d undetermined vulnerabilities.", params.Undetermined, undeterminedResults)
	// 	assert.Equal(t, params.NotCovered, notCoveredResults, "Expected %d not covered vulnerabilities in scan responses, but got %d not covered vulnerabilities.", params.NotCovered, notCoveredResults)
	// 	assert.Equal(t, params.NotApplicable, notApplicableResults, "Expected %d not applicable vulnerabilities in scan responses, but got %d not applicable vulnerabilities.", params.NotApplicable, notApplicableResults)

	// 	assert.Equal(t, params.SecurityViolations, len(results.SecurityViolations), "Expected %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, len(results.SecurityViolations))
	// 	assert.Equal(t, params.LicenseViolations, len(results.LicensesViolations), "Expected %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, len(results.LicensesViolations))
	// 	assert.Equal(t, params.OperationalViolations, len(results.OperationalRiskViolations), "Expected %d operational risk violations in scan responses, but got %d operational risk violations.", params.OperationalViolations, len(results.OperationalRiskViolations))

	// 	assert.Equal(t, params.Licenses, len(results.Licenses), "Expected %d Licenses in scan responses, but got %d Licenses.", params.Licenses, len(results.Licenses))
	// } else {
	// 	assert.GreaterOrEqual(t, len(results.Sast), params.Sast, "Expected at least %d sast in scan responses, but got %d sast.", params.Sast, len(results.Sast))
	// 	assert.GreaterOrEqual(t, len(results.Secrets), params.Secrets, "Expected at least %d secrets in scan responses, but got %d secrets.", params.Secrets, len(results.Secrets))
	// 	assert.GreaterOrEqual(t, len(results.Iacs), params.Iac, "Expected at least %d IaC in scan responses, but got %d IaC.", params.Iac, len(results.Iacs))

	// 	assert.GreaterOrEqual(t, applicableResults, params.Applicable, "Expected at least %d applicable vulnerabilities in scan responses, but got %d applicable vulnerabilities.", params.Applicable, applicableResults)
	// 	assert.GreaterOrEqual(t, undeterminedResults, params.Undetermined, "Expected at least %d undetermined vulnerabilities in scan responses, but got %d undetermined vulnerabilities.", params.Undetermined, undeterminedResults)
	// 	assert.GreaterOrEqual(t, notCoveredResults, params.NotCovered, "Expected at least %d not covered vulnerabilities in scan responses, but got %d not covered vulnerabilities.", params.NotCovered, notCoveredResults)
	// 	assert.GreaterOrEqual(t, notApplicableResults, params.NotApplicable, "Expected at least %d not applicable vulnerabilities in scan responses, but got %d not applicable vulnerabilities.", params.NotApplicable, notApplicableResults)

	// 	assert.GreaterOrEqual(t, len(results.SecurityViolations), params.SecurityViolations, "Expected at least %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, len(results.SecurityViolations))
	// 	assert.GreaterOrEqual(t, len(results.LicensesViolations), params.LicenseViolations, "Expected at least %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, len(results.LicensesViolations))
	// 	assert.GreaterOrEqual(t, len(results.OperationalRiskViolations), params.OperationalViolations, "Expected at least %d operational risk violations in scan responses, but got %d operational risk violations.", params.OperationalViolations, len(results.OperationalRiskViolations))

	// 	assert.GreaterOrEqual(t, len(results.Licenses), params.Licenses, "Expected at least %d Licenses in scan responses, but got %d Licenses.", params.Licenses, len(results.Licenses))
	// }
}