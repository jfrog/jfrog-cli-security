package validations

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
)

const (
	ErrCountFormat = "Expected%s %d %s in %s, but got %d %s."
)

func GetValidationCountErrMsg(what, where string, exactMatch bool, expectedCount, actualCount int) string {
	if exactMatch {
		return fmt.Sprintf(ErrCountFormat, "", expectedCount, what, where, actualCount, what)
	}
	return fmt.Sprintf(ErrCountFormat, " at least", expectedCount, what, where, actualCount, what)
}

// ValidationParams holds validation/assertion parameters for tests.
type ValidationParams struct {
	// The actual content to verify.
	Actual interface{}
	// If provided, the test will check if the content matches the expected results.
	Expected interface{}
	// If provided, the test will check exact values and not only the minimum values / existence.
	ExactResultsMatch bool
	// Expected issues for each type to check if the content has the correct amount of issues.
	Vulnerabilities       int
	Licenses              int
	SecurityViolations    int
	LicenseViolations     int
	OperationalViolations int
	Applicable            int
	Undetermined          int
	NotCovered            int
	NotApplicable         int
	MissingContext        int
	Inactive              int
	Sast                  int
	Iac                   int
	Secrets               int
}

// Validation allows to validate/assert a content with expected values.
// Using the Validation interfaces implementations allows you to assert content for exact value or not exact match (changes base on the implementation).
type Validation interface {
	Validate(t *testing.T, exactMatch bool) bool
	ErrMsgs(t *testing.T) []string
}

// Validate a string content.
// Not ExactMatch: The actual content must not be empty if the expected content is not empty.
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

// CountValidation validates the content of the given numbers.
// Not ExactMatch: The actual content must be greater or equal to the expected content.
type CountValidation[T any] struct {
	Expected int
	Actual   int
	Msg      string
}

func (cv CountValidation[T]) Validate(t *testing.T, exactMatch bool) bool {
	return validateNumberCount(t, cv.Expected, cv.Actual, exactMatch, cv.ErrMsgs(t))
}

func validateNumberCount(t *testing.T, expected, actual interface{}, actualValue bool, msgAndArgs ...interface{}) bool {
	if actualValue {
		return assert.Equal(t, expected, actual, msgAndArgs...)
	}
	return assert.GreaterOrEqual(t, actual, expected, msgAndArgs...)
}

func (cv CountValidation[T]) ErrMsgs(_ *testing.T) []string {
	return []string{cv.Msg}
}

// NumberValidation validates the content of the given numbers.
// Not ExactMatch: The actual content must not be zero if the expected content is not zero.
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

// PointerValidation validates the content of the given pointers.
// Not ExactMatch: The actual content must not be nil if the expected content is not nil.
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

// ListValidation validates the content of the given lists.
// Not ExactMatch: The expected content must be subset of the actual content.
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
		expectedStr, err = utils.GetAsJsonString(expected, false, true)
		assert.NoError(t, err)
	}
	if actual != nil {
		actualStr, err = utils.GetAsJsonString(actual, false, true)
		assert.NoError(t, err)
	}
	return errMsg(expectedStr, actualStr, msg)
}

func errMsg(expected, actual string, msg string) []string {
	return []string{msg, fmt.Sprintf("\n* Expected:\n'%s'\n\n* Actual:\n%s\n", expected, actual)}
}

// ValidateContent validates the content of the given Validations.
// If exactMatch is true, the content must match exactly.
// If at least one validation fails, the function returns false and stops validating the rest of the pairs.
func ValidateContent(t *testing.T, exactMatch bool, validations ...Validation) bool {
	for _, validation := range validations {
		if !validation.Validate(t, exactMatch) {
			return false
		}
	}
	return true
}
