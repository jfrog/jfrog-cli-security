package severityutils

import "testing"

func TestConvertToSarifLevel(t *testing.T) {
	tests := []struct {
		severity       string
		expectedOutput string
	}{
		{
			severity:       "Unknown",
			expectedOutput: "none",
		},
		{
			severity:       "Low",
			expectedOutput: "note",
		},
		{
			severity:       "Medium",
			expectedOutput: "warning",
		},
		{
			severity:       "High",
			expectedOutput: "error",
		},
		{
			severity:       "Critical",
			expectedOutput: "error",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, ConvertToSarifLevel(test.severity))
	}
}
