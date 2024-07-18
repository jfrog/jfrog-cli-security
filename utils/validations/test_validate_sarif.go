package validations

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/sarifparser"
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
	results, ok := params.Actual.(*sarif.Report)
	if assert.True(t, ok) {
		ValidateSarifIssuesCount(t, params, results)
		// if params.Expected != nil {
		// 	expectedResults, ok := params.Expected.(sarif.Report)
		// 	if assert.True(t, ok) {
		// 		ValidateScanResponses(t, params.ExactResultsMatch, expectedResults, results)
		// 	}
		// }
	}
}

func ValidateSarifIssuesCount(t *testing.T, params ValidationParams, results *sarif.Report) {
	var vulnerabilities, securityViolations, licenseViolations, applicableResults, undeterminedResults, notCoveredResults, notApplicableResults int

	iac := sarifutils.GetResultsLocationCount(sarifutils.GetRunsByToolName(results, sarifparser.IacToolName)...)
	secrets := sarifutils.GetResultsLocationCount(sarifutils.GetRunsByToolName(results, sarifparser.SecretsToolName)...)
	sast := sarifutils.GetResultsLocationCount(sarifutils.GetRunsByToolName(results, sarifparser.SastToolName)...)

	scaRuns := sarifutils.GetRunsByToolName(results, sarifparser.ScaToolName)
	for _, run := range scaRuns {
		for _, result := range run.Results {
			// If watch property exists, add to security violations or license violations else add to vulnerabilities
			if _, ok := result.Properties[sarifparser.WatchSarifPropertyKey]; ok {
				if isSecurityIssue(result) {
					securityViolations++
				} else {
					licenseViolations++
					// No more work needed for license violations
					continue
				}
			} else {
				vulnerabilities++
			}
			// Get the applicability status in the result properties (convert to string) and add count to the appropriate category
			applicabilityProperty := result.Properties[jasutils.ApplicabilitySarifPropertyKey]
			if applicability, ok := applicabilityProperty.(string); ok {
				switch applicability {
				case jasutils.Applicable.String():
					applicableResults++
				case jasutils.NotApplicable.String():
					notApplicableResults++
				case jasutils.ApplicabilityUndetermined.String():
					undeterminedResults++
				case jasutils.NotCovered.String():
					notCoveredResults++
				}
			}
		}
	}

	if params.ExactResultsMatch {
		assert.Equal(t, params.Sast, sast, "Expected %d sast in scan responses, but got %d sast.", params.Sast, sast)
		assert.Equal(t, params.Secrets, secrets, "Expected %d secrets in scan responses, but got %d secrets.", params.Secrets, secrets)
		assert.Equal(t, params.Iac, iac, "Expected %d IaC in scan responses, but got %d IaC.", params.Iac, iac)
		assert.Equal(t, params.Applicable, applicableResults, "Expected %d applicable results in scan responses, but got %d applicable results.", params.Applicable, applicableResults)
		assert.Equal(t, params.Undetermined, undeterminedResults, "Expected %d undetermined results in scan responses, but got %d undetermined results.", params.Undetermined, undeterminedResults)
		assert.Equal(t, params.NotCovered, notCoveredResults, "Expected %d not covered results in scan responses, but got %d not covered results.", params.NotCovered, notCoveredResults)
		assert.Equal(t, params.NotApplicable, notApplicableResults, "Expected %d not applicable results in scan responses, but got %d not applicable results.", params.NotApplicable, notApplicableResults)
		assert.Equal(t, params.SecurityViolations, securityViolations, "Expected %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, securityViolations)
		assert.Equal(t, params.LicenseViolations, licenseViolations, "Expected %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, licenseViolations)
		assert.Equal(t, params.Vulnerabilities, vulnerabilities, "Expected %d vulnerabilities in scan responses, but got %d vulnerabilities.", params.Vulnerabilities, vulnerabilities)
	} else {
		assert.GreaterOrEqual(t, sast, params.Sast, "Expected at least %d sast in scan responses, but got %d sast.", params.Sast, sast)
		assert.GreaterOrEqual(t, secrets, params.Secrets, "Expected at least %d secrets in scan responses, but got %d secrets.", params.Secrets, secrets)
		assert.GreaterOrEqual(t, iac, params.Iac, "Expected at least %d IaC in scan responses, but got %d IaC.", params.Iac, iac)
		assert.GreaterOrEqual(t, applicableResults, params.Applicable, "Expected at least %d applicable results in scan responses, but got %d applicable results.", params.Applicable, applicableResults)
		assert.GreaterOrEqual(t, undeterminedResults, params.Undetermined, "Expected at least %d undetermined results in scan responses, but got %d undetermined results.", params.Undetermined, undeterminedResults)
		assert.GreaterOrEqual(t, notCoveredResults, params.NotCovered, "Expected at least %d not covered results in scan responses, but got %d not covered results.", params.NotCovered, notCoveredResults)
		assert.GreaterOrEqual(t, notApplicableResults, params.NotApplicable, "Expected at least %d not applicable results in scan responses, but got %d not applicable results.", params.NotApplicable, notApplicableResults)
		assert.GreaterOrEqual(t, securityViolations, params.SecurityViolations, "Expected at least %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, securityViolations)
		assert.GreaterOrEqual(t, licenseViolations, params.LicenseViolations, "Expected at least %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, licenseViolations)
	}
}

func isSecurityIssue(result *sarif.Result) bool {
	// If the rule id starts with CVE or XRAY, it is a security issue
	if result.RuleID == nil {
		return false
	}
	ruleID := *result.RuleID

	if strings.HasPrefix(ruleID, "CVE") || strings.HasPrefix(ruleID, "XRAY") {
		return true
	}
	return false
}
