package validations

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion/sarifparser"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

const (
	SastToolName = "🐸 JFrog SAST"
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
func ValidateSarifIssuesCount(t *testing.T, params ValidationParams, report *sarif.Report) {
	var vulnerabilities, violations int

	// SCA
	scaVulnerabilities, applicableVulnerabilitiesResults, undeterminedVulnerabilitiesResults, notCoveredVulnerabilitiesResults, notApplicableVulnerabilitiesResults, missingContextVulnerabilitiesResults, scaViolations, securityViolations, licenseViolations, applicableViolationsResults, undeterminedViolationsResults, notCoveredViolationsResults, notApplicableViolationsResults, missingContextViolationsResults := countScaResults(report)
	vulnerabilities += scaVulnerabilities
	violations += scaViolations

	// Secrets
	secretsVulnerabilities, inactiveVulnerabilities, secretsViolations, inactiveViolations := countSecretsResults(report)
	vulnerabilities += secretsVulnerabilities
	violations += secretsViolations

	// IAC
	iacVulnerabilities, iacViolations := countJasResults(sarifutils.GetRunsByToolName(report, IacToolName))
	vulnerabilities += iacVulnerabilities
	violations += iacViolations

	// SAST
	sastVulnerabilities, sastViolations := countJasResults(sarifutils.GetRunsByToolName(report, SastToolName))
	vulnerabilities += sastVulnerabilities
	violations += sastViolations

	ValidateContent(t, params.ExactResultsMatch,
		// Total
		CountValidation[int]{Expected: params.Vulnerabilities, Actual: vulnerabilities, Msg: GetValidationCountErrMsg("vulnerabilities", "sarif report", params.ExactResultsMatch, params.Vulnerabilities, vulnerabilities)},
		CountValidation[int]{Expected: params.SecurityViolations, Actual: violations, Msg: GetValidationCountErrMsg("violations", "sarif report", params.ExactResultsMatch, params.SecurityViolations, violations)},
		// JAS Vulnerabilities
		CountValidation[int]{Expected: params.SastVulnerabilities, Actual: sastVulnerabilities, Msg: GetValidationCountErrMsg("sast vulnerabilities", "sarif report", params.ExactResultsMatch, params.SastVulnerabilities, sastVulnerabilities)},
		CountValidation[int]{Expected: params.IacVulnerabilities, Actual: iacVulnerabilities, Msg: GetValidationCountErrMsg("Iac vulnerabilities", "sarif report", params.ExactResultsMatch, params.IacVulnerabilities, iacVulnerabilities)},
		CountValidation[int]{Expected: params.SecretsVulnerabilities, Actual: secretsVulnerabilities, Msg: GetValidationCountErrMsg("secrets vulnerabilities", "sarif report", params.ExactResultsMatch, params.SecretsVulnerabilities, secretsVulnerabilities)},
		CountValidation[int]{Expected: params.InactiveVulnerabilities, Actual: inactiveVulnerabilities, Msg: GetValidationCountErrMsg("inactive secrets vulnerabilities", "sarif report", params.ExactResultsMatch, params.InactiveVulnerabilities, inactiveVulnerabilities)},
		// JAS Violations
		CountValidation[int]{Expected: params.SastViolations, Actual: sastViolations, Msg: GetValidationCountErrMsg("sast violations", "sarif report", params.ExactResultsMatch, params.SastViolations, sastViolations)},
		CountValidation[int]{Expected: params.IacViolations, Actual: iacViolations, Msg: GetValidationCountErrMsg("Iac violations", "sarif report", params.ExactResultsMatch, params.IacViolations, iacViolations)},
		CountValidation[int]{Expected: params.SecretsViolations, Actual: secretsViolations, Msg: GetValidationCountErrMsg("secrets violations", "sarif report", params.ExactResultsMatch, params.SecretsViolations, secretsViolations)},
		CountValidation[int]{Expected: params.InactiveViolations, Actual: inactiveViolations, Msg: GetValidationCountErrMsg("inactive secrets violations", "sarif report", params.ExactResultsMatch, params.InactiveViolations, inactiveViolations)},
		// SCA Vulnerabilities
		CountValidation[int]{Expected: params.ApplicableVulnerabilities, Actual: applicableVulnerabilitiesResults, Msg: GetValidationCountErrMsg("applicable vulnerabilities", "sarif report", params.ExactResultsMatch, params.ApplicableVulnerabilities, applicableVulnerabilitiesResults)},
		CountValidation[int]{Expected: params.UndeterminedVulnerabilities, Actual: undeterminedVulnerabilitiesResults, Msg: GetValidationCountErrMsg("undetermined vulnerabilities", "sarif report", params.ExactResultsMatch, params.UndeterminedVulnerabilities, undeterminedVulnerabilitiesResults)},
		CountValidation[int]{Expected: params.NotCoveredVulnerabilities, Actual: notCoveredVulnerabilitiesResults, Msg: GetValidationCountErrMsg("not covered vulnerabilities", "sarif report", params.ExactResultsMatch, params.NotCoveredVulnerabilities, notCoveredVulnerabilitiesResults)},
		CountValidation[int]{Expected: params.NotApplicableVulnerabilities, Actual: notApplicableVulnerabilitiesResults, Msg: GetValidationCountErrMsg("not applicable vulnerabilities", "sarif report", params.ExactResultsMatch, params.NotApplicableVulnerabilities, notApplicableVulnerabilitiesResults)},
		CountValidation[int]{Expected: params.MissingContextVulnerabilities, Actual: missingContextVulnerabilitiesResults, Msg: GetValidationCountErrMsg("missing context vulnerabilities", "sarif report", params.ExactResultsMatch, params.MissingContextVulnerabilities, missingContextVulnerabilitiesResults)},
		// SCA Violations
		CountValidation[int]{Expected: params.ApplicableViolations, Actual: applicableViolationsResults, Msg: GetValidationCountErrMsg("applicable violations", "sarif report", params.ExactResultsMatch, params.ApplicableViolations, applicableViolationsResults)},
		CountValidation[int]{Expected: params.UndeterminedViolations, Actual: undeterminedViolationsResults, Msg: GetValidationCountErrMsg("undetermined violations", "sarif report", params.ExactResultsMatch, params.UndeterminedViolations, undeterminedViolationsResults)},
		CountValidation[int]{Expected: params.NotCoveredViolations, Actual: notCoveredViolationsResults, Msg: GetValidationCountErrMsg("not covered violations", "sarif report", params.ExactResultsMatch, params.NotCoveredViolations, notCoveredViolationsResults)},
		CountValidation[int]{Expected: params.NotApplicableViolations, Actual: notApplicableViolationsResults, Msg: GetValidationCountErrMsg("not applicable violations", "sarif report", params.ExactResultsMatch, params.NotApplicableViolations, notApplicableViolationsResults)},
		CountValidation[int]{Expected: params.MissingContextViolations, Actual: missingContextViolationsResults, Msg: GetValidationCountErrMsg("missing context violations", "sarif report", params.ExactResultsMatch, params.MissingContextViolations, missingContextViolationsResults)},
		CountValidation[int]{Expected: params.SecurityViolations, Actual: securityViolations, Msg: GetValidationCountErrMsg("security violations", "sarif report", params.ExactResultsMatch, params.SecurityViolations, securityViolations)},
		CountValidation[int]{Expected: params.LicenseViolations, Actual: licenseViolations, Msg: GetValidationCountErrMsg("license violations", "sarif report", params.ExactResultsMatch, params.LicenseViolations, licenseViolations)},
	)
}

func countScaResults(report *sarif.Report) (vulnerabilities, applicableVulnerabilitiesResults, undeterminedVulnerabilitiesResults, notCoveredVulnerabilitiesResults, notApplicableVulnerabilitiesResults, missingContextVulnerabilitiesResults, violations, securityViolations, licenseViolations, applicableViolationsResults, undeterminedViolationsResults, notCoveredViolationsResults, notApplicableViolationsResults, missingContextViolationsResults int) {
	for _, run := range sarifutils.GetRunsByToolName(report, sarifparser.ScaScannerToolName) {
		for _, result := range run.Results {
			// If watch property exists, add to security violations or license violations else add to vulnerabilities
			isViolations := false
			if _, ok := result.Properties[sarifparser.WatchSarifPropertyKey]; ok {
				isViolations = true
				violations++
				if !isSecurityIssue(result) {
					licenseViolations++
					continue
				}
				securityViolations++
			} else {
				vulnerabilities++
			}

			// Get the applicability status in the result properties (convert to string) and add count to the appropriate category
			applicabilityProperty := result.Properties[jasutils.ApplicabilitySarifPropertyKey]
			if applicability, ok := applicabilityProperty.(string); ok {
				switch applicability {
				case jasutils.Applicable.String():
					if isViolations {
						applicableViolationsResults++
					} else {
						applicableVulnerabilitiesResults++
					}
				case jasutils.NotApplicable.String():
					if isViolations {
						notApplicableViolationsResults++
					} else {
						notApplicableVulnerabilitiesResults++
					}
				case jasutils.ApplicabilityUndetermined.String():
					if isViolations {
						undeterminedViolationsResults++
					} else {
						undeterminedVulnerabilitiesResults++
					}
				case jasutils.NotCovered.String():
					if isViolations {
						notCoveredViolationsResults++
					} else {
						notCoveredVulnerabilitiesResults++
					}
				case jasutils.MissingContext.String():
					if isViolations {
						missingContextViolationsResults++
					} else {
						missingContextVulnerabilitiesResults++
					}
				}
			}
		}
	}
	return
}

func countSecretsResults(report *sarif.Report) (vulnerabilities, inactiveVulnerabilities, violations, inactiveViolations int) {
	allRuns := append(sarifutils.GetRunsByToolName(report, SecretsToolName), sarifutils.GetRunsByToolName(report, sarifparser.BinarySecretScannerToolName)...)
	for _, run := range allRuns {
		for _, result := range run.Results {
			isViolation := false
			// JAS results does not have watch property yet, we should infer by prefix in msg
			if strings.HasPrefix(sarifutils.GetResultMsgMarkdown(result), "Security violation") {
				isViolation = true
				violations++
			} else {
				vulnerabilities++
			}
			vulnerabilities++
			if tokenStatus := results.GetResultPropertyTokenValidation(result); tokenStatus == jasutils.Inactive.ToString() {
				if isViolation {
					inactiveViolations++
				} else {
					inactiveVulnerabilities++
				}
			}
		}
	}
	return
}

func countJasResults(runs []*sarif.Run) (vulnerabilities, violations int) {
	for _, run := range runs {
		for _, result := range run.Results {
			// JAS results does not have watch property yet, we should infer by prefix in msg
			if strings.HasPrefix(sarifutils.GetResultMsgMarkdown(result), "Security violation") {
				violations++
			} else {
				vulnerabilities++
			}
		}
	}
	return
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
	validateSarifProperties(t, exactMatch, expected.Properties, actual.Properties, expected.Tool.Driver.Name, "run")
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
		if !assert.NotNil(t, result, fmt.Sprintf("Run tool %s: Expected result with rule ID %s not found in %v", expected.Tool.Driver.Name, sarifutils.GetResultRuleId(expectedResult), getResultsRuleIds(actual.Results))) {
			continue
		}
		validateSarifResult(t, exactMatch, expected.Tool.Driver.Name, expectedResult, result)
	}
}

func getResultsRuleIds(results []*sarif.Result) []string {
	var ruleIds []string
	for _, result := range results {
		ruleIds = append(ruleIds, sarifutils.GetResultRuleId(result))
	}
	return ruleIds
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
	validateSarifProperties(t, exactMatch, expected.Properties, actual.Properties, toolName, fmt.Sprintf("rule %s", expected.ID))
}

func getResultByResultId(expected *sarif.Result, actual []*sarif.Result) *sarif.Result {
	log.Output("====================================")
	log.Output(fmt.Sprintf(":: Actual results with expected results: %s", getResultId(expected)))
	for _, result := range actual {
		log.Output(fmt.Sprintf("Compare actual result (isPotential=%t, hasSameLocations=%t) with expected result: %s", isPotentialSimilarResults(expected, result), hasSameLocations(expected, result), getResultId(result)))
		if isPotentialSimilarResults(expected, result) && hasSameLocations(expected, result) {
			return result
		}
	}
	log.Output("====================================")
	return nil
}

func isPotentialSimilarResults(expected, actual *sarif.Result) bool {
	return sarifutils.GetResultRuleId(actual) == sarifutils.GetResultRuleId(expected) && sarifutils.GetResultProperty(sarifparser.WatchSarifPropertyKey, actual) == sarifutils.GetResultProperty(sarifparser.WatchSarifPropertyKey, expected)
}

func getResultId(result *sarif.Result) string {
	return fmt.Sprintf("%s-%s-%s-%s", sarifutils.GetResultRuleId(result), sarifutils.GetResultMsgText(result), sarifutils.GetResultProperty(sarifparser.WatchSarifPropertyKey, result), getLocationsId(result.Locations))
}

func getLocationsId(locations []*sarif.Location) string {
	var locationsId string
	for _, location := range locations {
		locationsId += sarifutils.GetLocationId(location)
	}
	return locationsId
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
	validateSarifProperties(t, exactMatch, expected.Properties, actual.Properties, toolName, fmt.Sprintf("result rule %s", sarifutils.GetResultRuleId(expected)))
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

func validateSarifProperties(t *testing.T, exactMatch bool, expected, actual map[string]interface{}, toolName, id string) {
	for key, expectedValue := range expected {
		actualValue, ok := actual[key]
		if !assert.True(t, ok, fmt.Sprintf("Run tool %s: Expected property with key %s not found for %s", toolName, key, id)) {
			continue
		}
		// If the property is a string, compare the string values
		if expectedStr, ok := expectedValue.(string); ok {
			actualStr, ok := actualValue.(string)
			if assert.True(t, ok, fmt.Sprintf("Run tool %s: Expected property with key %s is not a string for %s", toolName, key, id)) {
				ValidateContent(t, exactMatch, StringValidation{Expected: expectedStr, Actual: actualStr, Msg: fmt.Sprintf("Run tool %s: Rule property mismatch for rule %s", toolName, id)})
				continue
			}
			assert.Fail(t, fmt.Sprintf("Run tool %s: Expected property with key %s is a string for %s", toolName, key, id))
		}
	}
}
