package validations

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
)

type ValidationParams struct {
	// The actual content to verify.
	Actual interface{}
	// If provided, the test will check if the content matches the expected results.
	Expected interface{}
	// If provided, the test will check exact values and not only the minimum values / existence.
	ExactResultsMatch bool

	// Expected counts of values to validate.
	Vulnerabilities       int
	Licenses              int
	SecurityViolations    int
	LicenseViolations     int
	OperationalViolations int
	Applicable            int
	Undetermined          int
	NotCovered            int
	NotApplicable         int
	Sast                  int
	Iac                   int
	Secrets               int
}

type ValidationPair struct {
	Expected interface{}
	Actual   interface{}
	ErrMsg   string
}

func (vp ValidationPair) ErrMsgs(t *testing.T) []string {
	expectedStr := fmt.Sprintf("%v", vp.Expected)
	var err error
	// If the expected value is a struct, convert it to a JSON string.
	if _, ok := vp.Expected.(string); !ok {
		expectedStr, err = utils.GetAsJsonString(vp.Expected)
		assert.NoError(t, err)
	}
	actualStr := fmt.Sprintf("%v", vp.Actual)
	// If the actual value is a struct, convert it to a JSON string.
	if _, ok := vp.Actual.(string); !ok {
		actualStr, err = utils.GetAsJsonString(vp.Actual)
		assert.NoError(t, err)
	}
	return []string{vp.ErrMsg, fmt.Sprintf("\n* Expected:\n%s\n\n* Actual:\n%s\n", expectedStr, actualStr)}
}

func validatePairs(t *testing.T, exactMatch bool, pairs ...ValidationPair) bool {
	for _, pair := range pairs {
		switch expected := pair.Expected.(type) {
		case string:
			actual, ok := pair.Actual.(string)
			if !ok {
				return assert.Fail(t, "Expected a string value, but got a different type.", pair.ErrMsgs(t))
			}
			if !validateStrContent(t, expected, actual, exactMatch, pair.ErrMsgs(t)) {
				return false
			}
		case *interface{}:
			if !validatePointers(t, expected, pair.Actual, exactMatch, pair.ErrMsgs(t)) {
				return false
			}
		case []interface{}:
			if exactMatch {
				if !assert.ElementsMatch(t, expected, pair.Actual, pair.ErrMsgs(t)) {
					return false
				}
			} else if !assert.Subset(t, expected, pair.Actual, pair.ErrMsgs(t)) {
				return false
			}
		default:
			return assert.Equal(t, expected, pair.Actual, pair.ErrMsgs(t))
		}
	}
	return true
}

func validatePointers(t *testing.T, expected, actual interface{}, actualValue bool, msgAndArgs ...interface{}) bool {
	if actualValue {
		return assert.Equal(t, expected, actual, msgAndArgs...)
	}
	if expected != nil {
		return assert.NotNil(t, actual, msgAndArgs...)
	}
	return assert.Nil(t, actual, msgAndArgs...)
}

func validateStrContent(t *testing.T, expected, actual string, actualValue bool, msgAndArgs ...interface{}) bool {
	if actualValue {
		return assert.Equal(t, expected, actual, msgAndArgs...)
	}
	if expected != "" {
		return assert.NotEmpty(t, actual, msgAndArgs...)
	} else {
		return assert.Empty(t, actual, msgAndArgs...)
	}
}