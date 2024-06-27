package severityutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSeverity(t *testing.T) {
	testCases := []struct {
		input          string
		isSarifFormat  bool
		expectedOutput Severity
		expectedError  error
	}{
		// Test supported severity
		{input: "critical", isSarifFormat: false, expectedOutput: "Critical", expectedError: nil},
		{input: "hiGH", isSarifFormat: false, expectedOutput: "High", expectedError: nil},
		{input: "Low", isSarifFormat: false, expectedOutput: "Low", expectedError: nil},
		{input: "MedIum", isSarifFormat: false, expectedOutput: "Medium", expectedError: nil},
		// Test supported sarif level
		{input: "error", isSarifFormat: true, expectedOutput: "High", expectedError: nil},
		{input: "warning", isSarifFormat: true, expectedOutput: "Medium", expectedError: nil},
		{input: "info", isSarifFormat: true, expectedOutput: "Medium", expectedError: nil},
		{input: "note", isSarifFormat: true, expectedOutput: "Low", expectedError: nil},
		{input: "none", isSarifFormat: true, expectedOutput: "Unknown", expectedError: nil},
		{input: "", isSarifFormat: true, expectedOutput: "Medium", expectedError: nil},
		// Test unsupported severity
		{input: "", isSarifFormat: false, expectedOutput: "", expectedError: errors.New("is not supported, only the following severities are supported")},
		{input: "invalid_severity", isSarifFormat: false, expectedOutput: "", expectedError: errors.New("only the following severities are supported")},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s (isSarifInput=%t)", tc.input, tc.isSarifFormat), func(t *testing.T) {
			output, err := ParseSeverity(tc.input, tc.isSarifFormat)
			if tc.expectedError != nil {
				assert.Contains(t, err.Error(), tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}
