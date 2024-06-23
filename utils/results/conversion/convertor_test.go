package conversion

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/stretchr/testify/assert"
)

var expectedTestResultsDir = filepath.Join("..", "..", "..", "tests", "testdata", "formats")

func TestSarifConvertor(t *testing.T) {
	testCases := []struct {
		name               string
		results            *results.ScanCommandResults
		expectedOutputPath string
	}{
		{
			name:               "No Jas results",
			results:            utils.NoJasTestResults,
			expectedOutputPath: "expected_sarif_no_jas.json",
		},
		{
			name:               "With Jas results",
			results:            utils.WithJasTestResults,
			expectedOutputPath: "expected_sarif_jas.json",
		},
	}

	convertor := NewCommandResultsConvertor(ResultConvertParams{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert the results
			output, err := convertor.ConvertToSarif(tc.results)
			assert.NoError(t, err)
			// Read the expected output
			assert.Equal(t, utils.GetOutputFromFile(t, filepath.Join(expectedTestResultsDir, tc.expectedOutputPath)), output)
		})
	}
}

func TestSummaryConvertor(t *testing.T) {
	testCases := []struct {
		name               string
		results            *results.ScanCommandResults
		expectedOutputPath string
	}{
		{
			name:               "No Jas results",
			results:            utils.NoJasTestResults,
			expectedOutputPath: "expected_summary_no_jas.json",
		},
		{
			name:               "With Jas results",
			results:            utils.WithJasTestResults,
			expectedOutputPath: "expected_summary_jas.json",
		},
	}

	convertor := NewCommandResultsConvertor(ResultConvertParams{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert the results
			output, err := convertor.ConvertToSummary(tc.results)
			assert.NoError(t, err)
			// Read the expected output
			assert.Equal(t, utils.GetOutputFromFile(t, filepath.Join(expectedTestResultsDir, tc.expectedOutputPath)), output)
		})
	}
}

func TestTableConvertor(t *testing.T) {
	testCases := []struct {
		name               string
		results            *results.ScanCommandResults
		expectedOutputPath string
	}{
		{
			name:               "No Jas results",
			results:            utils.NoJasTestResults,
			expectedOutputPath: "expected_table_no_jas.json",
		},
		{
			name:               "With Jas results",
			results:            utils.WithJasTestResults,
			expectedOutputPath: "expected_table_jas.json",
		},
	}

	convertor := NewCommandResultsConvertor(ResultConvertParams{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert the results
			output, err := convertor.ConvertToTable(tc.results)
			assert.NoError(t, err)
			// Read the expected output
			assert.Equal(t, utils.GetOutputFromFile(t, filepath.Join(expectedTestResultsDir, tc.expectedOutputPath)), output)
		})
	}
}

func TestSimpleJsonConvertor(t *testing.T) {
	testCases := []struct {
		name               string
		results            *results.ScanCommandResults
		expectedOutputPath string
	}{
		{
			name:               "No Jas results",
			results:            utils.NoJasTestResults,
			expectedOutputPath: "expected_simple_no_jas.json",
		},
		{
			name:               "With Jas results",
			results:            utils.WithJasTestResults,
			expectedOutputPath: "expected_simple_jas.json",
		},
	}

	convertor := NewCommandResultsConvertor(ResultConvertParams{})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert the results
			output, err := convertor.ConvertToSimpleJson(tc.results)
			assert.NoError(t, err)
			// Read the expected output
			assert.Equal(t, utils.GetOutputFromFile(t, filepath.Join(expectedTestResultsDir, tc.expectedOutputPath)), output)
		})
	}
}

func TestGetUniqueKey(t *testing.T) {
	vulnerableDependency := "test-dependency"
	vulnerableVersion := "1.0"
	expectedKey := "test-dependency:1.0:XRAY-12234:true"
	key := GetUniqueKey(vulnerableDependency, vulnerableVersion, "XRAY-12234", true)
	assert.Equal(t, expectedKey, key)

	expectedKey = "test-dependency:1.0:XRAY-12143:false"
	key = GetUniqueKey(vulnerableDependency, vulnerableVersion, "XRAY-12143", false)
	assert.Equal(t, expectedKey, key)
}
