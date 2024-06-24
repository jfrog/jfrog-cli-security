package severityutils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSeveritiesFormat(t *testing.T) {
	testCases := []struct {
		input          string
		isSarifFormat  bool
		expectedOutput string
		expectedError  error
	}{
		// Test supported severity
		{input: "critical", isSarifFormat: false, expectedOutput: "Critical", expectedError: nil},
		{input: "hiGH", isSarifFormat: false, expectedOutput: "High", expectedError: nil},
		{input: "Low", isSarifFormat: false, expectedOutput: "Low", expectedError: nil},
		{input: "MedIum", isSarifFormat: false, expectedOutput: "Medium", expectedError: nil},
		{input: "", isSarifFormat: false, expectedOutput: "", expectedError: nil},
		// Test supported sarif level
		{input: "error", isSarifFormat: true, expectedOutput: "High", expectedError: nil},
		{input: "warning", isSarifFormat: true, expectedOutput: "Medium", expectedError: nil},
		{input: "info", isSarifFormat: true, expectedOutput: "Medium", expectedError: nil},
		{input: "note", isSarifFormat: true, expectedOutput: "Low", expectedError: nil},
		{input: "none", isSarifFormat: true, expectedOutput: "Unknown", expectedError: nil},
		{input: "", isSarifFormat: true, expectedOutput: "Medium", expectedError: nil},
		// Test unsupported severity
		{input: "invalid_severity", expectedOutput: "", expectedError: errors.New("only the following severities are supported")},
	}

	for _, tc := range testCases {
		output, err := ParseSeverity(tc.input, false)
		if err != nil {
			assert.Contains(t, err.Error(), tc.expectedError.Error())
		} else {
			assert.Equal(t, tc.expectedError, err)
		}
		assert.Equal(t, tc.expectedOutput, output)
	}
}