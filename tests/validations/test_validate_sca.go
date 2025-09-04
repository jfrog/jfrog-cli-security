package validations

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
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
	var vulnerabilities, violations, licenses, securityViolations, licenseViolations, operationalViolations int

	for _, result := range content {
		vulnerabilities += len(result.Vulnerabilities)
		violations += len(result.Violations)
		licenses += len(result.Licenses)
		for _, violation := range result.Violations {
			switch violation.ViolationType {
			case violationutils.ViolationTypeSecurity.String():
				securityViolations += 1
			case violationutils.ViolationTypeLicense.String():
				licenseViolations += 1
			case violationutils.ViolationTypeOperationalRisk.String():
				operationalViolations += 1
			}
		}
	}

	ValidateTotalCount(t, "json", params.ExactResultsMatch, params.Total, vulnerabilities, violations, licenses, 0)
	if params.Violations != nil {
		ValidateScaViolationCount(t, "json", params.ExactResultsMatch, params.Violations.ValidateType, securityViolations, licenseViolations, operationalViolations)
		if params.Violations.ValidateApplicabilityStatus != nil || params.Violations.ValidateScan != nil {
			t.Error("Validate Violations only support ValidateType for JSON output")
		}
	}
	if params.Vulnerabilities != nil {
		t.Error("Validate Vulnerabilities is not supported for JSON output")
	}
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
