package validations

import (
	"encoding/json"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/stretchr/testify/assert"
)

// Content should be a Json string of formats.ResultsTables and will be unmarshal.
// Value is set as the Actual content in the validation params
func VerifySummaryResults(t *testing.T, content string, params ValidationParams) {
	var results formats.SummaryResults
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err)
	params.Actual = results
	ValidateCommandTableOutput(t, params)
}

func ValidateCommandSummaryOutput(t *testing.T, params ValidationParams) {
	// results, ok := params.Actual.(formats.ResultsTables)
	// if assert.True(t, ok) {
	// 	//
	// }
}
