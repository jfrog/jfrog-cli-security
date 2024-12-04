package conversion

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"

	testUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/validations"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

var (
	testDataDir = filepath.Join("..", "..", "..", "tests", "testdata", "output")
)

const (
	SimpleJson conversionFormat = "simple-json"
	Sarif      conversionFormat = "sarif"
	Summary    conversionFormat = "summary"
)

type conversionFormat string

func getAuditValidationParams() validations.ValidationParams {
	return validations.ValidationParams{
		ExactResultsMatch: true,

		Total: &validations.TotalCount{Vulnerabilities: 19, Violations: 7},

		Vulnerabilities: &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 12, Sast: 4, Secrets: 3},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 1, NotApplicable: 7, NotCovered: 4},
		},

		Violations: &validations.ViolationCount{
			ValidateScan:                &validations.ScanCount{Sca: 5, Sast: 1, Secrets: 1},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 1, NotApplicable: 4},
		},
	}
}

// For Summary we count unique CVE finding (issueId), for SARIF and SimpleJson we count all findings (pair of issueId+impactedComponent)
// We have in the result 2 CVE with 2 impacted components each
func getDockerScanValidationParams(unique bool) validations.ValidationParams {
	params := validations.ValidationParams{
		ExactResultsMatch: true,
		Total:             &validations.TotalCount{Violations: 3},
		Violations: &validations.ViolationCount{
			ValidateScan:                &validations.ScanCount{Sca: 1, Secrets: 2},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Undetermined: 1},
		},
	}
	if unique {
		params.Total.Vulnerabilities = 11
		params.Vulnerabilities = &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 8, Secrets: 3},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 3, NotApplicable: 3, NotCovered: 1, Undetermined: 1},
		}
	} else {
		params.Total.Vulnerabilities = 14
		params.Vulnerabilities = &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 11, Secrets: 3},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 5, NotApplicable: 4, NotCovered: 1, Undetermined: 1},
		}
	}
	return params
}

func TestConvertResults(t *testing.T) {
	auditInputResults := testUtils.ReadCmdScanResults(t, filepath.Join(testDataDir, "audit", "audit_results.json"))
	dockerScanInputResults := testUtils.ReadCmdScanResults(t, filepath.Join(testDataDir, "dockerscan", "docker_results.json"))

	testCases := []struct {
		contentFormat       conversionFormat
		inputResults        *results.SecurityCommandResults
		expectedContentPath string
	}{
		{
			contentFormat:       SimpleJson,
			inputResults:        auditInputResults,
			expectedContentPath: filepath.Join(testDataDir, "audit", "audit_simple_json.json"),
		},
		{
			contentFormat:       Sarif,
			inputResults:        auditInputResults,
			expectedContentPath: filepath.Join(testDataDir, "audit", "audit_sarif.json"),
		},
		{
			contentFormat:       Summary,
			inputResults:        auditInputResults,
			expectedContentPath: filepath.Join(testDataDir, "audit", "audit_summary.json"),
		},
		{
			contentFormat:       SimpleJson,
			inputResults:        dockerScanInputResults,
			expectedContentPath: filepath.Join(testDataDir, "dockerscan", "docker_simple_json.json"),
		},
		{
			contentFormat:       Sarif,
			inputResults:        dockerScanInputResults,
			expectedContentPath: filepath.Join(testDataDir, "dockerscan", "docker_sarif.json"),
		},
		{
			contentFormat:       Summary,
			inputResults:        dockerScanInputResults,
			expectedContentPath: filepath.Join(testDataDir, "dockerscan", "docker_summary.json"),
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("%s convert to %s", testCase.inputResults.CmdType, testCase.contentFormat), func(t *testing.T) {
			var validationParams validations.ValidationParams
			switch testCase.inputResults.CmdType {
			case utils.SourceCode:
				validationParams = getAuditValidationParams()
			case utils.DockerImage:
				validationParams = getDockerScanValidationParams(testCase.contentFormat == Summary)
			default:
				t.Fatalf("Unsupported command type: %s", testCase.inputResults.CmdType)
			}
			pretty := false
			if testCase.contentFormat == Sarif {
				pretty = true
			}
			convertor := NewCommandResultsConvertor(ResultConvertParams{IncludeVulnerabilities: true, HasViolationContext: true, Pretty: pretty})

			switch testCase.contentFormat {
			case SimpleJson:
				validateSimpleJsonConversion(t, testUtils.ReadSimpleJsonResults(t, testCase.expectedContentPath), testCase.inputResults, convertor, validationParams)
			case Sarif:
				validateSarifConversion(t, testUtils.ReadSarifResults(t, testCase.expectedContentPath), testCase.inputResults, convertor, validationParams)
			case Summary:
				validateSummaryConversion(t, testUtils.ReadSummaryResults(t, testCase.expectedContentPath), testCase.inputResults, convertor, validationParams)
			}
		})
	}
}

func validateSimpleJsonConversion(t *testing.T, expectedResults formats.SimpleJsonResults, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSimpleJson(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSimpleJsonOutput(t, validationParams)
}

func validateSarifConversion(t *testing.T, expectedResults *sarif.Report, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSarif(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSarifOutput(t, validationParams)
}

func validateSummaryConversion(t *testing.T, expectedResults formats.ResultsSummary, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSummary(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSummaryOutput(t, validationParams)
}
