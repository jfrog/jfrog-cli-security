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

type Validation interface {
	Validate(t *testing.T, exactMatch bool) bool
	ErrMsgs(t *testing.T) []string
}

type StringValidation struct {
	Expected string
	Actual   string
	Msg      string
}

func (sv StringValidation) Validate(t *testing.T, exactMatch bool) bool {
	return validateStrContent(t, sv.Expected, sv.Actual, exactMatch, sv.ErrMsgs(t))
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

func (sv StringValidation) ErrMsgs(_ *testing.T) []string {
	return []string{sv.Msg}
}

type NumberValidation[T any] struct {
	Expected T
	Actual   T
	Msg      string
}

func (nvp NumberValidation[T]) Validate(t *testing.T, exactMatch bool) bool {
	return validateNumberContent(t, nvp.Expected, nvp.Actual, exactMatch, nvp.ErrMsgs(t))
}

func validateNumberContent(t *testing.T, expected, actual interface{}, actualValue bool, msgAndArgs ...interface{}) bool {
	if actualValue {
		return assert.Equal(t, expected, actual, msgAndArgs...)
	}
	if expected != 0 {
		return assert.NotZero(t, actual, msgAndArgs...)
	} else {
		return assert.Zero(t, actual, msgAndArgs...)
	}
}

func (nvp NumberValidation[T]) ErrMsgs(_ *testing.T) []string {
	return []string{nvp.Msg}
}

type PointerValidation[T any] struct {
	Expected *T
	Actual   *T
	Msg      string
}

func (pvp PointerValidation[T]) Validate(t *testing.T, exactMatch bool) bool {
	return validatePointers(t, pvp.Expected, pvp.Actual, exactMatch, pvp.ErrMsgs(t))
}

func ValidatePointersAndNotNil[T any](t *testing.T, exactMatch bool, pair PointerValidation[T]) bool {
	return validatePointers(t, pair.Expected, pair.Actual, exactMatch, pair.Msg) && pair.Expected != nil
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

func (pvp PointerValidation[T]) ErrMsgs(t *testing.T) []string {
	return jsonErrMsg(t, pvp.Expected, pvp.Actual, pvp.Msg)
}

type ListValidation[T any] struct {
	Expected []T
	Actual   []T
	Msg      string
}

func (lvp ListValidation[T]) Validate(t *testing.T, exactMatch bool) bool {
	return validateLists(t, lvp.Expected, lvp.Actual, exactMatch, lvp.ErrMsgs(t))
}

func validateLists(t *testing.T, expected, actual interface{}, exactMatch bool, msgAndArgs ...interface{}) bool {
	if exactMatch {
		return assert.ElementsMatch(t, expected, actual, msgAndArgs...)
	}
	return assert.Subset(t, actual, expected, msgAndArgs...)
}

func (lvp ListValidation[T]) ErrMsgs(t *testing.T) []string {
	return jsonErrMsg(t, lvp.Expected, lvp.Actual, lvp.Msg)
}

func jsonErrMsg(t *testing.T, expected, actual any, msg string) []string {
	var expectedStr, actualStr string
	var err error
	if expected != nil {
		expectedStr, err = utils.GetAsJsonString(expected)
		assert.NoError(t, err)
	}
	if actual != nil {
		actualStr, err = utils.GetAsJsonString(actual)
		assert.NoError(t, err)
	}
	return errMsg(expectedStr, actualStr, msg)
}

func errMsg(expected, actual string, msg string) []string {
	return []string{msg, fmt.Sprintf("\n* Expected:\n'%s'\n\n* Actual:\n%s\n", expected, actual)}
}

func validateContent(t *testing.T, exactMatch bool, pairs ...Validation) bool {
	for _, pair := range pairs {
		if !pair.Validate(t, exactMatch) {
			return false
		}
	}
	return true
}
