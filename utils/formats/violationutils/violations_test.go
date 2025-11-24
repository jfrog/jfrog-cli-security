package violationutils

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/stretchr/testify/assert"
)

func TestGetOperationalRiskReadableData(t *testing.T) {
	tests := []struct {
		name            string
		riskReason      string
		isEol           *bool
		eolMsg          string
		cadence         *float64
		commits         *int64
		committers      *int
		latestVersion   string
		newerVersion    *int
		expectedResults OperationalRiskViolationReadableData
	}{
		{
			name:          "all fields populated",
			riskReason:    "High Risk",
			isEol:         utils.NewBoolPtr(true),
			eolMsg:        "This component is end of life.",
			cadence:       utils.NewFloat64Ptr(30),
			commits:       utils.NewInt64Ptr(100),
			committers:    utils.NewIntPtr(5),
			latestVersion: "2.0.0",
			newerVersion:  utils.NewIntPtr(3),
			expectedResults: OperationalRiskViolationReadableData{
				RiskReason:    "High Risk",
				IsEol:         "true",
				EolMessage:    "This component is end of life.",
				Cadence:       "30",
				Commits:       "100",
				Committers:    "5",
				LatestVersion: "2.0.0",
				NewerVersions: "3",
			},
		},
		{
			name:       "only risk reason populated",
			riskReason: "Low Risk",
			expectedResults: OperationalRiskViolationReadableData{
				RiskReason:    "Low Risk",
				IsEol:         "N/A",
				EolMessage:    "",
				Cadence:       "N/A",
				Commits:       "N/A",
				Committers:    "N/A",
				LatestVersion: "N/A",
				NewerVersions: "N/A",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := GetOperationalRiskViolationReadableData(test.riskReason, test.isEol, test.eolMsg, test.cadence, test.commits, test.committers, test.latestVersion, test.newerVersion)
			assert.Equal(t, test.expectedResults, results)
		})
	}
}
