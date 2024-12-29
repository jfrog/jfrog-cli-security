package validations

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
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
		if params.FailBuild == true {
			ValidateScanResponseFailBuild(t, params.FailBuildCVESeverity, results)
		}
		if params.ExistingProperties != nil {
			for _, res := range results {
				ValidatePaths(t, res, params.ExistingProperties)
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

func ValidateScanResponseFailBuild(t *testing.T, severity string, content []services.ScanResponse) {
	for _, result := range content {
		for _, violation := range result.Violations {
			if violation.Severity == severity {
				assert.True(t, violation.FailBuild, "FailBuild field is true")
				return
			}
		}
	}
	assert.Fail(t, "fail_build field not found in the scan responses")
}

func ValidateScanResponses(t *testing.T, exactMatch bool, expected, actual []services.ScanResponse) {
	for _, expectedResponse := range expected {
		actualResponse := getScanResponseByScanId(expectedResponse.ScanId, actual)
		if !assert.NotNil(t, actualResponse, fmt.Sprintf("ScanId %s not found in the scan responses", expectedResponse.ScanId)) {
			return
		}
	}
}

func TestValidatePathsFunc(t *testing.T) {
	sampleJson := `{
         "scan_id": "1a97d1a4-4d30-430c-46e9-d0c998065d08",
         "vulnerabilities": [
           {
             "cves": [
               {
                 "cve": "CVE-2024-51744",
                 "cvss_v3_score": "3.1",
                 "cvss_v3_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                 "cwe": [
                   "CWE-347",
                   "CWE-755"
                 ],
                 "cwe_details": {
                   "CWE-347": {
                     "name": "Improper Verification of Cryptographic Signature",
                     "description": "The product does not verify, or incorrectly verifies, the cryptographic signature for data."
                   },
                   "CWE-755": {
                     "name": "Improper Handling of Exceptional Conditions",
                     "description": "The product does not handle or incorrectly handles an exceptional condition."
                   }
                 }
               }
             ],
             "summary": "golang-jwt is a Go implementation of JSON Web Tokens. Unclear documentation of the error behavior in \"ParseWithClaims\" can lead to situation where users are potentially not checking errors in the way they should be. Especially, if a token is both expired and invalid, the errors returned by \"ParseWithClaims\" return both error codes. If users only check for the \"jwt.ErrTokenExpired\" using \"error.Is\", they will ignore the embedded \"jwt.ErrTokenSignatureInvalid\" and thus potentially accept invalid tokens. A fix has been back-ported with the error handling logic from the \"v5\" branch to the \"v4\" branch. In this logic, the \"ParseWithClaims\" function will immediately return in \"dangerous\" situations (e.g., an invalid signature), limiting the combined errors only to situations where the signature is valid, but further validation failed (e.g., if the signature is valid, but is expired AND has the wrong audience). This fix is part of the 4.5.1 release. We are aware that this changes the behaviour of an established function and is not 100 % backwards compatible, so updating to 4.5.1 might break your code. In case you cannot update to 4.5.0, please make sure that you are properly checking for all errors (\"dangerous\" ones first), so that you are not running in the case detailed above.",
             "severity": "Low",
             "components": {
               "go://github.com/golang-jwt/jwt/v4:4.4.2": {
                 "fixed_versions": [
                   "[4.5.1]"
                 ],
                 "impact_paths": [
                   [
                     {
                       "component_id": "docker://localhost:8046/cli-docker-virtual-1734626392/bitnami/minio:2022"
                     },
                     {
                       "component_id": "generic://sha256:2252918a526208e7f0b752c923f267b14f1c8beece250ee6bc72c9c2ef7bb1c6/sha256__2252918a526208e7f0b752c923f267b14f1c8beece250ee6bc72c9c2ef7bb1c6.tar",
                       "full_path": "sha256__2252918a526208e7f0b752c923f267b14f1c8beece250ee6bc72c9c2ef7bb1c6.tar"
                     }
                   ]
                 ]
               }
             }
           }
         ]
       }`
	actualJson := services.ScanResponse{}
	err := json.Unmarshal([]byte(sampleJson), &actualJson)
	if err != nil {
		assert.NoError(t, err)
	}
	stringsToCheck := []string{"vulnerabilities[].components[*].impact_paths[][].full_path"}
	ValidatePaths(t, actualJson, stringsToCheck)
}

func ValidatePaths(t *testing.T, output interface{}, paths []string) {
	for _, path := range paths {
		elements := strings.Split(path, ".")
		assert.True(t, validatePath(output, elements), "path does not exist: %s", path)
	}
}

func validatePath(data interface{}, path []string) bool {
	if len(path) == 0 {
		return true
	}

	key := path[0]
	sliceKey := strings.Replace(key, "[]", "", -1)
	mapKey := strings.Replace(key, "[*]", "", -1)

	if key == "[]" {
		// Top-level is an array
		if reflect.TypeOf(data).Kind() == reflect.Slice {
			slice := reflect.ValueOf(data)
			for i := 0; i < slice.Len(); i++ {
				if validatePath(slice.Index(i).Interface(), path[1:]) {
					return true
				}
			}
		}
	} else if strings.Contains(key, "[]") {
		// Handle array notation in the middle
		if reflect.TypeOf(data).Kind() == reflect.Map {
			dataMap := reflect.ValueOf(data)
			if val := dataMap.MapIndex(reflect.ValueOf(sliceKey)); val.IsValid() {
				if val.Kind() == reflect.Slice {
					slice := val
					for i := 0; i < slice.Len(); i++ {
						if validatePath(slice.Index(i).Interface(), path[1:]) {
							return true
						}
					}
				}
			}
		} else if reflect.TypeOf(data).Kind() == reflect.Struct {
			structField, valid := getFieldByTag(data, sliceKey)
			if valid && structField.Kind() == reflect.Slice {
				slice := structField
				for i := 0; i < slice.Len(); i++ {
					if validatePath(slice.Index(i).Interface(), path[1:]) {
						return true
					}
				}
			}
		}
	} else if strings.Contains(key, "[*]") {
		// Handle any map key
		if reflect.TypeOf(data).Kind() == reflect.Map {
			dataMap := reflect.ValueOf(data)
			if val := dataMap.MapIndex(reflect.ValueOf(mapKey)); val.IsValid() {
				if val.Kind() == reflect.Map {
					for _, item := range val.MapKeys() {
						mapVal := val.MapIndex(item)
						if validatePath(mapVal.Interface(), path[1:]) {
							return true
						}
					}
				}
			}
		} else if reflect.TypeOf(data).Kind() == reflect.Struct {
			structField, valid := getFieldByTag(data, mapKey)
			if valid && structField.Kind() == reflect.Map {
				for _, item := range structField.MapKeys() {
					mapVal := structField.MapIndex(item)
					if validatePath(mapVal.Interface(), path[1:]) {
						return true
					}
				}
			}
		}
	} else {
		// Handle standard keys
		if reflect.TypeOf(data).Kind() == reflect.Map {
			dataMap := reflect.ValueOf(data)
			if val := dataMap.MapIndex(reflect.ValueOf(key)); val.IsValid() {
				return validatePath(val.Interface(), path[1:])
			}
		} else if reflect.TypeOf(data).Kind() == reflect.Struct {
			structField, valid := getFieldByTag(data, key)
			if valid {
				return validatePath(structField.Interface(), path[1:])
			}
		} else if reflect.TypeOf(data).Kind() == reflect.Slice {
			slice := reflect.ValueOf(data)
			for i := 0; i < slice.Len(); i++ {
				if validatePath(slice.Index(i).Interface(), path) {
					return true
				}
			}
		}
	}
	return false
}

func getFieldByTag(data interface{}, key string) (reflect.Value, bool) {
	structValue := reflect.ValueOf(data)
	structType := structValue.Type()

	for i := 0; i < structValue.NumField(); i++ {
		field := structType.Field(i)
		tag := field.Tag.Get("json")

		tagParts := strings.Split(tag, ",")
		if tagParts[0] == key {
			return structValue.Field(i), true
		}
	}

	return reflect.Value{}, false
}

func getScanResponseByScanId(scanId string, content []services.ScanResponse) *services.ScanResponse {
	for _, result := range content {
		if result.ScanId == scanId {
			return &result
		}
	}
	return nil
}
