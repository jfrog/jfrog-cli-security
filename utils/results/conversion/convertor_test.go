package conversion

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"

	testUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/validations"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

var (
	testDataDir = filepath.Join("..", "..", "..", "tests", "testdata", "other", "output", "formats")
)

const (
	SimpleJson conversionFormat = "simple-json"
	Sarif      conversionFormat = "sarif"
	Summary    conversionFormat = "summary"
)

type conversionFormat string

func getValidationParams() validations.ValidationParams {
	return validations.ValidationParams{
		ExactResultsMatch: true,

		Vulnerabilities: 12,
		Applicable:      1,
		NotApplicable:   7,
		NotCovered:      4,

		Sast:    4,
		Secrets: 5,
	}
}

func TestConvertResults(t *testing.T) {
	inputResults := testUtils.ReadCmdScanResults(t, filepath.Join(testDataDir, "audit_results.json"))

	testCases := []struct {
		contentFormat       conversionFormat
		expectedContentPath string
	}{
		{
			contentFormat:       SimpleJson,
			expectedContentPath: filepath.Join(testDataDir, "audit_simple_json.json"),
		},
		{
			contentFormat:       Sarif,
			expectedContentPath: filepath.Join(testDataDir, "audit_sarif.json"),
		},
		{
			contentFormat:       Summary,
			expectedContentPath: filepath.Join(testDataDir, "audit_summary.json"),
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Convert to %s", testCase.contentFormat), func(t *testing.T) {
			validationParams := getValidationParams()
			convertor := NewCommandResultsConvertor(ResultConvertParams{})

			switch testCase.contentFormat {
			case SimpleJson:
				validateSimpleJsonConversion(t, testUtils.ReadSimpleJsonResults(t, testCase.expectedContentPath), inputResults, convertor, validationParams)
			case Sarif:
				validateSarifConversion(t, testUtils.ReadSarifResults(t, testCase.expectedContentPath), inputResults, convertor, validationParams)
			case Summary:
				validateSummaryConversion(t, testUtils.ReadSummaryResults(t, testCase.expectedContentPath), inputResults, convertor, validationParams)
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

func validateSummaryConversion(t *testing.T, expectedResults formats.SummaryResults, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSummary(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSummaryOutput(t, validationParams)
}
