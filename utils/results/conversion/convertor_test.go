package conversion

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-client-go/utils/log"

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
		ExactResultsMatch:  true,
		SecurityViolations: 11,
		Vulnerabilities:    19,
		Applicable:         1,
		NotApplicable:      7,
		NotCovered:         4,
		Sast:               4,
		Secrets:            3,
	}
}

func TestConvertResults(t *testing.T) {
	auditInputResults := testUtils.ReadCmdScanResults(t, filepath.Join(testDataDir, "audit", "audit_results.json"))

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
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Convert to %s", testCase.contentFormat), func(t *testing.T) {
			validationParams := getAuditValidationParams()
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

	marshAct, err := utils.GetAsJsonString(actualResults, false, true)
	assert.NoError(t, err)
	log.Output(marshAct)

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
