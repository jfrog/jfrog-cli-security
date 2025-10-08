package jasutils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCveToApplicabilityRuleId(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "applic_cve", CveToApplicabilityRuleId("cve"))
}

func TestApplicabilityRuleIdToCve(t *testing.T) {
	t.Parallel()
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
