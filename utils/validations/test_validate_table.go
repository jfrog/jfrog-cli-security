package validations

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/stretchr/testify/assert"
)

// Content should be a Json string of formats.ResultsTables and will be unmarshal.
// Value is set as the Actual content in the validation params
func VerifyTableResults(t *testing.T, content string, params ValidationParams) {
	var results formats.ResultsTables
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err)
	params.Actual = results
	ValidateCommandTableOutput(t, params)
}

func ValidateCommandTableOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.(formats.ResultsTables)
	if assert.True(t, ok) {
		ValidateTableIssuesCount(t, params, results)
	}
}

func ValidateTableIssuesCount(t *testing.T, params ValidationParams, results formats.ResultsTables) {
	if params.ExactResultsMatch {
		assert.Len(t, results.SastTable, params.Sast, fmt.Sprintf("Expected %d sast issues in table, but got %d sast.", params.Sast, len(results.SastTable)))
		assert.Len(t, results.SecretsTable, params.Secrets, fmt.Sprintf("Expected %d secrets issues in table, but got %d secrets.", params.Secrets, len(results.SecretsTable)))
		assert.Len(t, results.IacTable, params.Iac, fmt.Sprintf("Expected %d IaC issues in table, but got %d IaC.", params.Iac, len(results.IacTable)))
		assert.Len(t, results.LicenseViolationsTable, params.LicenseViolations, fmt.Sprintf("Expected %d license issues in table, but got %d license issues.", params.Licenses, len(results.LicenseViolationsTable)))
		assert.Len(t, results.LicensesTable, params.Licenses, fmt.Sprintf("Expected %d licenses in table, but got %d licenses.", params.Licenses, len(results.LicensesTable)))
		assert.Len(t, results.OperationalRiskViolationsTable, params.OperationalViolations, fmt.Sprintf("Expected %d operational risk issues in table, but got %d operational risk issues.", params.OperationalViolations, len(results.OperationalRiskViolationsTable)))
		assert.Equal(t, params.Vulnerabilities+params.SecurityViolations, len(results.SecurityVulnerabilitiesTable), fmt.Sprintf("Expected %d vulnerabilities in table, but got %d vulnerabilities.", params.Vulnerabilities, len(results.SecurityVulnerabilitiesTable)))
		return
	}
	assert.GreaterOrEqual(t, len(results.SastTable), params.Sast, fmt.Sprintf("Expected at least %d sast issues in table, but got %d sast.", params.Sast, len(results.SastTable)))
	assert.GreaterOrEqual(t, len(results.SecretsTable), params.Secrets, fmt.Sprintf("Expected at least %d secrets issues in table, but got %d secrets.", params.Secrets, len(results.SecretsTable)))
	assert.GreaterOrEqual(t, len(results.IacTable), params.Iac, fmt.Sprintf("Expected at least %d IaC issues in table, but got %d IaC.", params.Iac, len(results.IacTable)))
	assert.GreaterOrEqual(t, len(results.LicenseViolationsTable), params.LicenseViolations, fmt.Sprintf("Expected at least %d license issues in table, but got %d license issues.", params.Licenses, len(results.LicenseViolationsTable)))
	assert.GreaterOrEqual(t, len(results.LicensesTable), params.Licenses, fmt.Sprintf("Expected at least %d licenses in table, but got %d licenses.", params.Licenses, len(results.LicensesTable)))
	assert.GreaterOrEqual(t, len(results.OperationalRiskViolationsTable), params.OperationalViolations, fmt.Sprintf("Expected at least %d operational risk issues in table, but got %d operational risk issues.", params.OperationalViolations, len(results.OperationalRiskViolationsTable)))
	assert.GreaterOrEqual(t, len(results.SecurityVulnerabilitiesTable), params.Vulnerabilities+params.SecurityViolations, fmt.Sprintf("Expected at least %d vulnerabilities in table, but got %d vulnerabilities.", params.Vulnerabilities, len(results.SecurityVulnerabilitiesTable)))
}
