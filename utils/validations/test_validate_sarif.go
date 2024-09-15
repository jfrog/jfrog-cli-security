package validations

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/sarifparser"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

const (
	SastToolName = "USAF"
	IacToolName  = "JFrog Terraform scanner"
	// #nosec G101 -- Not credentials.
	SecretsToolName = "JFrog Secrets scanner"
)

// Validate sarif report according to the expected values and issue counts in the validation params.
// Value/Actual content should be a *sarif.Report in the validation params
// If ExactResultsMatch is true, the validation will check exact values and not only the 'equal or grater' counts / existence of expected attributes.
// For Integration tests with JFrog API, ExactResultsMatch should be set to false.
func ValidateCommandSarifOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.(*sarif.Report)
	if assert.True(t, ok, "Actual content is not a *sarif.Report") {
		ValidateSarifIssuesCount(t, params, results)
		if params.Expected != nil {
			expectedResults, ok := params.Expected.(*sarif.Report)
			if assert.True(t, ok, "Expected content is not a *sarif.Report") {
				ValidateSarifReport(t, params.ExactResultsMatch, expectedResults, results)
			}
		}
	}
}

// Validate sarif report according to the expected counts in the validation params.
// Actual content should be a *sarif.Report in the validation params.
// If Expected is provided, the validation will check if the Actual content matches the expected results.
// If ExactResultsMatch is true, the validation will check exact values and not only the 'equal or grater' counts / existence of expected attributes. (For Integration tests with JFrog API, ExactResultsMatch should be set to false)
func ValidateSarifIssuesCount(t *testing.T, params ValidationParams, results *sarif.Report) {
	var vulnerabilities, securityViolations, licenseViolations, applicableResults, undeterminedResults, notCoveredResults, notApplicableResults int

	iac := sarifutils.GetResultsLocationCount(sarifutils.GetRunsByToolName(results, IacToolName)...)
	vulnerabilities += iac
	secrets := sarifutils.GetResultsLocationCount(sarifutils.GetRunsByToolName(results, SecretsToolName)...)
	vulnerabilities += secrets
	sast := sarifutils.GetResultsLocationCount(sarifutils.GetRunsByToolName(results, SastToolName)...)
	vulnerabilities += sast

	scaRuns := sarifutils.GetRunsByToolName(results, sarifparser.ScaScannerToolName)
	for _, run := range scaRuns {
		for _, result := range run.Results {
			// If watch property exists, add to security violations or license violations else add to vulnerabilities
			if _, ok := result.Properties[sarifparser.WatchSarifPropertyKey]; ok {
				if isSecurityIssue(result) {
					securityViolations++
				} else {
					licenseViolations++
				}
				continue
			}
			vulnerabilities++
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
		assert.Equal(t, params.Sast, sast, GetValidationCountErrMsg("sast", "sarif report", true, params.Sast, sast))
		assert.Equal(t, params.Secrets, secrets, GetValidationCountErrMsg("secrets", "sarif report", true, params.Secrets, secrets))
		assert.Equal(t, params.Iac, iac, GetValidationCountErrMsg("Iac", "sarif report", true, params.Iac, iac))
		assert.Equal(t, params.Applicable, applicableResults, "Expected %d applicable results in sarif report, but got %d applicable results.", params.Applicable, applicableResults)
		assert.Equal(t, params.Undetermined, undeterminedResults, "Expected %d undetermined results in sarif report, but got %d undetermined results.", params.Undetermined, undeterminedResults)
		assert.Equal(t, params.NotCovered, notCoveredResults, "Expected %d not covered results in sarif report, but got %d not covered results.", params.NotCovered, notCoveredResults)
		assert.Equal(t, params.NotApplicable, notApplicableResults, "Expected %d not applicable results in sarif report, but got %d not applicable results.", params.NotApplicable, notApplicableResults)
		assert.Equal(t, params.SecurityViolations, securityViolations, "Expected %d security violations in sarif report, but got %d security violations.", params.SecurityViolations, securityViolations)
		assert.Equal(t, params.LicenseViolations, licenseViolations, "Expected %d license violations in sarif report, but got %d license violations.", params.LicenseViolations, licenseViolations)
		assert.Equal(t, params.Vulnerabilities, vulnerabilities, "Expected %d vulnerabilities in sarif report, but got %d vulnerabilities.", params.Vulnerabilities, vulnerabilities)
	} else {
		assert.GreaterOrEqual(t, sast, params.Sast, "Expected at least %d sast in sarif report, but got %d sast.", params.Sast, sast)
		assert.GreaterOrEqual(t, secrets, params.Secrets, "Expected at least %d secrets in sarif report, but got %d secrets.", params.Secrets, secrets)
		assert.GreaterOrEqual(t, iac, params.Iac, "Expected at least %d IaC in sarif report, but got %d IaC.", params.Iac, iac)
		assert.GreaterOrEqual(t, applicableResults, params.Applicable, "Expected at least %d applicable results in sarif report, but got %d applicable results.", params.Applicable, applicableResults)
		assert.GreaterOrEqual(t, undeterminedResults, params.Undetermined, "Expected at least %d undetermined results in sarif report, but got %d undetermined results.", params.Undetermined, undeterminedResults)
		assert.GreaterOrEqual(t, notCoveredResults, params.NotCovered, "Expected at least %d not covered results in sarif report, but got %d not covered results.", params.NotCovered, notCoveredResults)
		assert.GreaterOrEqual(t, notApplicableResults, params.NotApplicable, "Expected at least %d not applicable results in sarif report, but got %d not applicable results.", params.NotApplicable, notApplicableResults)
		assert.GreaterOrEqual(t, securityViolations, params.SecurityViolations, "Expected at least %d security violations in sarif report, but got %d security violations.", params.SecurityViolations, securityViolations)
		assert.GreaterOrEqual(t, licenseViolations, params.LicenseViolations, "Expected at least %d license violations in sarif report, but got %d license violations.", params.LicenseViolations, licenseViolations)
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

func ValidateSarifReport(t *testing.T, exactMatch bool, expected, actual *sarif.Report) {
	ValidateContent(t, exactMatch, StringValidation{Expected: expected.Version, Actual: actual.Version, Msg: "Sarif version mismatch"})
	for _, run := range expected.Runs {
		// expect Invocation
		if !assert.Len(t, run.Invocations, 1, "Expected exactly one invocation for run with tool name %s", run.Tool.Driver.Name) {
			continue
		}
		actualRun := getRunByInvocationTargetAndToolName(sarifutils.GetInvocationWorkingDirectory(run.Invocations[0]), run.Tool.Driver.Name, actual.Runs)
		if !assert.NotNil(t, actualRun, "Expected run with tool name %s and working directory %s not found", run.Tool.Driver.Name, sarifutils.GetInvocationWorkingDirectory(run.Invocations[0])) {
			continue
		}
		validateSarifRun(t, exactMatch, run, actualRun)
	}
}

func getRunByInvocationTargetAndToolName(target, toolName string, content []*sarif.Run) *sarif.Run {
	potentialRuns := sarifutils.GetRunsByWorkingDirectory(target, content...)
	for _, run := range potentialRuns {
		if run.Tool.Driver != nil && run.Tool.Driver.Name == toolName {
			return run
		}
	}
	return nil
}

func validateSarifRun(t *testing.T, exactMatch bool, expected, actual *sarif.Run) {
	ValidateContent(t, exactMatch,
		PointerValidation[string]{Expected: expected.Tool.Driver.InformationURI, Actual: actual.Tool.Driver.InformationURI, Msg: fmt.Sprintf("Run tool information URI mismatch for tool %s", expected.Tool.Driver.Name)},
		PointerValidation[string]{Expected: expected.Tool.Driver.Version, Actual: actual.Tool.Driver.Version, Msg: fmt.Sprintf("Run tool version mismatch for tool %s", expected.Tool.Driver.Name)},
	)
	// validate rules
	for _, expectedRule := range expected.Tool.Driver.Rules {
		rule, err := actual.GetRuleById(expectedRule.ID)
		if !(assert.NoError(t, err, fmt.Sprintf("Run tool %s: Expected rule with ID %s not found", expected.Tool.Driver.Name, expectedRule.ID)) ||
			assert.NotNil(t, rule, fmt.Sprintf("Run tool %s: Expected rule with ID %s not found", expected.Tool.Driver.Name, expectedRule.ID))) {
			continue
		}
		validateSarifRule(t, exactMatch, expected.Tool.Driver.Name, expectedRule, rule)
	}
	// validate results
	for _, expectedResult := range expected.Results {
		result := getResultByResultId(expectedResult, actual.Results)
		if !assert.NotNil(t, result, fmt.Sprintf("Run tool %s: Expected result with rule ID %s not found", expected.Tool.Driver.Name, sarifutils.GetResultRuleId(expectedResult))) {
			continue
		}
		validateSarifResult(t, exactMatch, expected.Tool.Driver.Name, expectedResult, result)
	}
}

func validateSarifRule(t *testing.T, exactMatch bool, toolName string, expected, actual *sarif.ReportingDescriptor) {
	ValidateContent(t, exactMatch,
		StringValidation{Expected: sarifutils.GetRuleFullDescription(expected), Actual: sarifutils.GetRuleFullDescription(actual), Msg: fmt.Sprintf("Run tool %s: Rule full description mismatch for rule %s", toolName, expected.ID)},
		StringValidation{Expected: sarifutils.GetRuleFullDescriptionMarkdown(expected), Actual: sarifutils.GetRuleFullDescriptionMarkdown(actual), Msg: fmt.Sprintf("Run tool %s: Rule full description markdown mismatch for rule %s", toolName, expected.ID)},
		StringValidation{Expected: sarifutils.GetRuleShortDescription(expected), Actual: sarifutils.GetRuleShortDescription(actual), Msg: fmt.Sprintf("Run tool %s: Rule short description mismatch for rule %s", toolName, expected.ID)},
		StringValidation{Expected: sarifutils.GetRuleHelp(expected), Actual: sarifutils.GetRuleHelp(actual), Msg: fmt.Sprintf("Run tool %s: Rule help mismatch for rule %s", toolName, expected.ID)},
		StringValidation{Expected: sarifutils.GetRuleHelpMarkdown(expected), Actual: sarifutils.GetRuleHelpMarkdown(actual), Msg: fmt.Sprintf("Run tool %s: Rule help markdown mismatch for rule %s", toolName, expected.ID)},
	)
	// validate properties
	validateSarifProperties(t, exactMatch, expected.Properties, actual.Properties, toolName, expected.ID)
}

func getResultByResultId(expected *sarif.Result, actual []*sarif.Result) *sarif.Result {
	for _, result := range actual {
		if isPotentialSimilarResults(expected, result) && hasSameLocations(expected, result) {
			return result
		}
	}
	return nil
}

func isPotentialSimilarResults(expected, actual *sarif.Result) bool {
	return sarifutils.GetResultRuleId(actual) == sarifutils.GetResultRuleId(expected) && sarifutils.GetResultMsgText(actual) == sarifutils.GetResultMsgText(expected) && sarifutils.GetResultProperty(sarifparser.WatchSarifPropertyKey, actual) == sarifutils.GetResultProperty(sarifparser.WatchSarifPropertyKey, expected)
}

func hasSameLocations(expected, actual *sarif.Result) bool {
	if len(expected.Locations) != len(actual.Locations) {
		return false
	}
	for _, expectedLocation := range expected.Locations {
		location := getLocationById(expectedLocation, actual.Locations)
		if location == nil {
			return false
		}
	}
	return true
}

func validateSarifResult(t *testing.T, exactMatch bool, toolName string, expected, actual *sarif.Result) {
	ValidateContent(t, exactMatch,
		StringValidation{Expected: sarifutils.GetResultLevel(expected), Actual: sarifutils.GetResultLevel(actual), Msg: fmt.Sprintf("Run tool %s: Result level mismatch for rule %s", toolName, sarifutils.GetResultRuleId(expected))},
	)
	// validate properties
	validateSarifProperties(t, exactMatch, expected.Properties, actual.Properties, toolName, sarifutils.GetResultRuleId(expected))
	// validate locations
	for _, expectedLocation := range expected.Locations {
		location := getLocationById(expectedLocation, actual.Locations)
		if !assert.NotNil(t, location, "Expected location with physical location %s not found", expectedLocation.PhysicalLocation) {
			continue
		}
	}
}

func getLocationById(expected *sarif.Location, actual []*sarif.Location) *sarif.Location {
	for _, location := range actual {
		if sarifutils.GetLocationId(location) == sarifutils.GetLocationId(expected) {
			return location
		}
	}
	return nil
}

func validateSarifProperties(t *testing.T, exactMatch bool, expected, actual map[string]interface{}, toolName, ruleID string) {
	for key, expectedValue := range expected {
		actualValue, ok := actual[key]
		if !assert.True(t, ok, fmt.Sprintf("Run tool %s: Expected property with key %s not found for rule %s", toolName, key, ruleID)) {
			continue
		}
		// If the property is a string, compare the string values
		if expectedStr, ok := expectedValue.(string); ok {
			actualStr, ok := actualValue.(string)
			if assert.True(t, ok, fmt.Sprintf("Run tool %s: Expected property with key %s is not a string for rule %s", toolName, key, ruleID)) {
				ValidateContent(t, exactMatch, StringValidation{Expected: expectedStr, Actual: actualStr, Msg: fmt.Sprintf("Run tool %s: Rule property mismatch for rule %s", toolName, ruleID)})
				continue
			}
			assert.Fail(t, fmt.Sprintf("Run tool %s: Expected property with key %s is a string for rule %s", toolName, key, ruleID))
		}
	}
}
