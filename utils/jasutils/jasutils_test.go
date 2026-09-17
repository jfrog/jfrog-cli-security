package jasutils

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/stretchr/testify/assert"
)

func TestCveToApplicabilityRuleId(t *testing.T) {
	assert.Equal(t, "applic_cve", CveToApplicabilityRuleId("cve"))
}

func TestApplicabilityRuleIdToCve(t *testing.T) {
	tests := []struct {
		ruleId         string
		expectedOutput string
	}{
		{
			ruleId:         "rule",
			expectedOutput: "rule",
		},
		{
			ruleId:         "applic_cve",
			expectedOutput: "cve",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, ApplicabilityRuleIdToCve(test.ruleId))
	}
}

func TestSubScanTypeToJasScanType(t *testing.T) {
	assert.Equal(t, Secrets, SubScanTypeToJasScanType(utils.SecretsScan))
	assert.Equal(t, IaC, SubScanTypeToJasScanType(utils.IacScan))
	assert.Equal(t, Services, SubScanTypeToJasScanType(utils.ServicesScan))
	assert.Equal(t, Sast, SubScanTypeToJasScanType(utils.SastScan))
	assert.Equal(t, Applicability, SubScanTypeToJasScanType(utils.ContextualAnalysisScan))
	assert.Equal(t, MaliciousCode, SubScanTypeToJasScanType(utils.MaliciousCodeScan))
}
