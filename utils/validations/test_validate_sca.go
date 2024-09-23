package validations

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

// Validate SCA content only (No JAS in this content) according to the expected values and issue counts in the validation params.
// Content/Expected should be a []services.ScanResponse in the validation params.
// If Expected is provided, the validation will check if the Actual content matches the expected results.
// If ExactResultsMatch is true, the validation will check exact values and not only the 'equal or grater' counts / existence of expected attributes. (For Integration tests with JFrog API, ExactResultsMatch should be set to false)
func VerifyJsonResults(t *testing.T, content string, params ValidationParams) {
	var results []services.ScanResponse
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err)
	params.Actual = results
	ValidateCommandJsonOutput(t, params)
}

// Validation on SCA content only (No JAS in this content)
// Actual (and optional Expected) content should be a slice of services.ScanResponse in the validation params
func ValidateCommandJsonOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.([]services.ScanResponse)
	if assert.True(t, ok, "Actual content is not a slice of services.ScanResponse") {
		ValidateScanResponseIssuesCount(t, params, results...)
		if params.Expected != nil {
			expectedResults, ok := params.Expected.([]services.ScanResponse)
			if assert.True(t, ok, "Expected content is not a slice of services.ScanResponse") {
				ValidateScanResponses(t, params.ExactResultsMatch, expectedResults, results)
			}
		}
	}
}

func ValidateScanResponseIssuesCount(t *testing.T, params ValidationParams, content ...services.ScanResponse) {
	var vulnerabilities, licenses, securityViolations, licenseViolations, operationalViolations int

	for _, result := range content {
		vulnerabilities += len(result.Vulnerabilities)
		licenses += len(result.Licenses)
		for _, violation := range result.Violations {
			switch violation.ViolationType {
			case utils.ViolationTypeSecurity.String():
				securityViolations += 1
			case utils.ViolationTypeLicense.String():
				licenseViolations += 1
			case utils.ViolationTypeOperationalRisk.String():
				operationalViolations += 1
			}
		}
	}

	ValidateContent(t, params.ExactResultsMatch,
		CountValidation[int]{Expected: params.Vulnerabilities, Actual: vulnerabilities, Msg: GetValidationCountErrMsg("vulnerabilities", "scan responses", params.ExactResultsMatch, params.Vulnerabilities, vulnerabilities)},
		CountValidation[int]{Expected: params.Licenses, Actual: licenses, Msg: GetValidationCountErrMsg("licenses", "scan responses", params.ExactResultsMatch, params.Licenses, licenses)},
		CountValidation[int]{Expected: params.SecurityViolations, Actual: securityViolations, Msg: GetValidationCountErrMsg("security violations", "scan responses", params.ExactResultsMatch, params.SecurityViolations, securityViolations)},
		CountValidation[int]{Expected: params.LicenseViolations, Actual: licenseViolations, Msg: GetValidationCountErrMsg("license violations", "scan responses", params.ExactResultsMatch, params.LicenseViolations, licenseViolations)},
		CountValidation[int]{Expected: params.OperationalViolations, Actual: operationalViolations, Msg: GetValidationCountErrMsg("operational risk violations", "scan responses", params.ExactResultsMatch, params.OperationalViolations, operationalViolations)},
	)
}

func ValidateScanResponses(t *testing.T, exactMatch bool, expected, actual []services.ScanResponse) {
	for _, expectedResponse := range expected {
		actualResponse := getScanResponseByScanId(expectedResponse.ScanId, actual)
		if !assert.NotNil(t, actualResponse, fmt.Sprintf("ScanId %s not found in the scan responses", expectedResponse.ScanId)) {
			return
		}
	}
}

func getScanResponseByScanId(scanId string, content []services.ScanResponse) *services.ScanResponse {
	for _, result := range content {
		if result.ScanId == scanId {
			return &result
		}
	}
	return nil
}
