package conversion

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

var (
	testDataDir = filepath.Join("..", "..", "..", "testdata", "other", "output", "formats")
)

const (
	SimpleJson conversionFormat = "simple-json"
	Sarif      conversionFormat = "sarif"
	Table      conversionFormat = "table"
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

		Sast:    2,
		Secrets: 5,
	}
}

func TestConvertResults(t *testing.T) {
	var inputResults *results.SecurityCommandResults
	if !assert.NoError(t, json.Unmarshal([]byte(utils.ReadOutputFromFile(t, filepath.Join(testDataDir, "audit_results.json"))), &inputResults)) {
		return
	}

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
			contentFormat:       Table,
			expectedContentPath: filepath.Join(testDataDir, "audit_table.json"),
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
				validateSimpleJsonConversion(t, []byte(utils.ReadOutputFromFile(t, testCase.expectedContentPath)), inputResults, convertor, validationParams)
			case Sarif:
				validateSarifConversion(t, []byte(utils.ReadOutputFromFile(t, testCase.expectedContentPath)), inputResults, convertor, validationParams)
			case Table:
				validateTableConversion(t, []byte(utils.ReadOutputFromFile(t, testCase.expectedContentPath)), inputResults, convertor, validationParams)
			case Summary:
				validateSummaryConversion(t, []byte(utils.ReadOutputFromFile(t, testCase.expectedContentPath)), inputResults, convertor, validationParams)
			}
		})
	}
}

func validateSimpleJsonConversion(t *testing.T, expectedContent []byte, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	var expectedResults formats.SimpleJsonResults
	if !assert.NoError(t, json.Unmarshal(expectedContent, &expectedResults)) {
		return
	}
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSimpleJson(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSimpleJsonOutput(t, validationParams)
}

func validateSarifConversion(t *testing.T, expectedContent []byte, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	var expectedResults *sarif.Report
	if !assert.NoError(t, json.Unmarshal(expectedContent, &expectedResults)) {
		return
	}
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSarif(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSarifOutput(t, validationParams)
}

func validateTableConversion(t *testing.T, expectedContent []byte, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	var expectedResults formats.ResultsTables
	if !assert.NoError(t, json.Unmarshal(expectedContent, &expectedResults)) {
		return
	}
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToTable(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandTableOutput(t, validationParams)
}

func validateSummaryConversion(t *testing.T, expectedContent []byte, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	var expectedResults formats.SummaryResults
	if !assert.NoError(t, json.Unmarshal(expectedContent, &expectedResults)) {
		return
	}
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSummary(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSummaryOutput(t, validationParams)
}
