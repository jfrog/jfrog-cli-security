package severityutils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
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
		{input: "inFormation", isSarifFormat: false, expectedOutput: "Information", expectedError: nil},
		{input: "unknown", isSarifFormat: false, expectedOutput: "Unknown", expectedError: nil},
		// Test supported sarif level
		{input: "error", isSarifFormat: true, expectedOutput: "High", expectedError: nil},
		{input: "warning", isSarifFormat: true, expectedOutput: "Medium", expectedError: nil},
		{input: "info", isSarifFormat: true, expectedOutput: "Information", expectedError: nil},
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

func TestGetSeverityScoreFloat64(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		status   jasutils.ApplicabilityStatus
		expected float64
	}{
		{"Critical Applicable", Critical, jasutils.Applicable, 10.0},
		{"High NotApplicable", High, jasutils.NotApplicable, 8.9},
		{"Medium MissingContext", Medium, jasutils.MissingContext, 6.9},
		{"Low NotCovered", Low, jasutils.NotCovered, 3.9},
		{"Unknown NotApplicable", Unknown, jasutils.NotApplicable, 0.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetSeverityScoreFloat64(tc.severity, tc.status)
			assert.NotNil(t, actual)
			assert.InDelta(t, tc.expected, *actual, 0.0001)
		})
	}
}

func TestGetCvssScore(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *float64
	}{
		{"Valid float", "7.1234", func() *float64 { f := 7.1234; return &f }()},
		{"Empty string", "", nil},
		{"Invalid string", "notanumber", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetCvssScore(tc.input)
			if tc.expected == nil {
				assert.Nil(t, actual)
			} else {
				assert.NotNil(t, actual)
				assert.InDelta(t, *tc.expected, *actual, 0.0001)
			}
		})
	}
}

func TestSeverityToCycloneDxSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    Severity
		expected cyclonedx.Severity
	}{
		{"Critical", Critical, cyclonedx.SeverityCritical},
		{"High", High, cyclonedx.SeverityHigh},
		{"Medium", Medium, cyclonedx.SeverityMedium},
		{"Low", Low, cyclonedx.SeverityLow},
		{"Unknown", Unknown, cyclonedx.SeverityUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := SeverityToCycloneDxSeverity(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestCycloneDxSeverityToSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    cyclonedx.Severity
		expected Severity
	}{
		{"Critical", cyclonedx.SeverityCritical, Critical},
		{"High", cyclonedx.SeverityHigh, High},
		{"Medium", cyclonedx.SeverityMedium, Medium},
		{"Low", cyclonedx.SeverityLow, Low},
		{"Unknown", cyclonedx.SeverityUnknown, Unknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := CycloneDxSeverityToSeverity(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestCreateSeverityRating(t *testing.T) {
	tests := []struct {
		name        string
		severity    Severity
		status      jasutils.ApplicabilityStatus
		service     *cyclonedx.Service
		expSeverity cyclonedx.Severity
		expScore    float64
	}{
		{"Critical Applicable", Critical, jasutils.Applicable, &cyclonedx.Service{Name: "testsvc"}, cyclonedx.SeverityCritical, 10.0},
		{"High NotApplicable", High, jasutils.NotApplicable, &cyclonedx.Service{Name: "svc2"}, cyclonedx.SeverityHigh, 8.9},
		{"Low NotCovered", Low, jasutils.NotCovered, &cyclonedx.Service{Name: "svc3"}, cyclonedx.SeverityLow, 3.9},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rating := CreateSeverityRating(tc.severity, tc.status, tc.service)
			assert.Equal(t, tc.service.Name, rating.Source.Name)
			assert.Equal(t, tc.expSeverity, rating.Severity)
			assert.NotNil(t, rating.Score)
			assert.InDelta(t, tc.expScore, *rating.Score, 0.0001)
		})
	}
}
