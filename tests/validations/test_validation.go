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

	// Validate total number of licenses, vulnerabilities and violations
	Total *TotalCount
	// Validate number of vulnerabilities in different contexts
	Vulnerabilities *VulnerabilityCount
	// Validate number of violations in different contexts
	Violations *ViolationCount
	// Validate number of components in the sbom
	SbomComponents *SbomCount
}

type TotalCount struct {
	// Expected number of licenses
	Licenses int
	// Expected number of total vulnerabilities (sca + sast + iac + secrets)
	Vulnerabilities int
	// Expected number of total violations (sca security + sca license + sca operational + sast + iac + secrets)
	Violations int
	// Expected number of components in the sbom
	BomComponents int
}

type ScanCount struct {
	// Expected number of Sca issues
	Sca int
	// Expected number of Sast issues
	Sast int
	// Expected number of Iac issues
	Iac int
	// Expected number of Secrets issues
	Secrets int
}

type SbomCount struct {
	// Expected number of direct components
	Direct int
	// Expected number of transitive components
	Transitive int
	// Expected number of root components
	Root int
}

type VulnerabilityCount struct {
	// If exists, validate the total amount of issues in different scan types (SCA/SAST/SECRETS/IAC)
	ValidateScan *ScanCount
	// If exists, validate the total amount of contextual statuses for the issues (sca/secrets)
	ValidateApplicabilityStatus *ApplicabilityStatusCount
}

type ViolationCount struct {
	// Expected number of violations by scan type (SCA/JAS)
	ValidateScan *ScanCount
	// Expected number of contextual statuses for violations (sca/secrets)
	ValidateApplicabilityStatus *ApplicabilityStatusCount
	// Expected number of violations by violation type (license, operational, security: SCA+JAS)
	ValidateType *ScaViolationCount
}

type ScaViolationCount struct {
	// Expected number of security violations (Sca, JAS)
	Security int
	// Expected number of license violations
	License int
	// Expected number of operational violations
	Operational int
}

type ApplicabilityStatusCount struct {
	// Expected number of 'Applicable' contextual-analysis statuses for the issues (sca)
	Applicable int
	// Expected number of 'Undetermined' contextual-analysis statuses for the issues (sca)
	Undetermined int
	// Expected number of 'NotCovered' contextual-analysis statuses for the issues (sca)
	NotCovered int
	// Expected number of 'NotApplicable' contextual-analysis statuses for the issues (sca)
	NotApplicable int
	// Expected number of 'MissingContext' contextual-analysis statuses for the issues (sca)
	MissingContext int
	// Expected number of 'Inactive' contextual-analysis statuses for the issues (secrets)
	Inactive int
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
	validationSuccess := true
	for _, validation := range validations {
		if !validation.Validate(t, exactMatch) {
			validationSuccess = false
		}
	}
	return validationSuccess
}

type validationCountActualValues struct {
	// Total counts
	Vulnerabilities, Violations, Licenses, SbomComponents int
	// Vulnerabilities counts
	SastVulnerabilities, SecretsVulnerabilities, IacVulnerabilities, ScaVulnerabilities                                                                                            int
	ApplicableVulnerabilities, UndeterminedVulnerabilities, NotCoveredVulnerabilities, NotApplicableVulnerabilities, MissingContextVulnerabilities, InactiveSecretsVulnerabilities int
	// Violations counts
	SastViolations, SecretsViolations, IacViolations, ScaViolations                                                                                  int
	SecurityViolations, LicenseViolations, OperationalViolations                                                                                     int
	ApplicableViolations, UndeterminedViolations, NotCoveredViolations, NotApplicableViolations, MissingContextViolations, InactiveSecretsViolations int
	// Sbom counts
	RootComponents, DirectComponents, TransitiveComponents int
}

func ValidateCount(t *testing.T, outputType string, params ValidationParams, actual validationCountActualValues) {
	ValidateTotalCount(t, outputType, params.ExactResultsMatch, params.Total, actual.Vulnerabilities, actual.Violations, actual.Licenses, actual.SbomComponents)
	ValidateVulnerabilitiesCount(t, outputType, params.ExactResultsMatch, params.Vulnerabilities, actual)
	ValidateViolationCount(t, outputType, params.ExactResultsMatch, params.Violations, actual)
	ValidateSbomComponentsCount(t, outputType, params.ExactResultsMatch, params.SbomComponents, actual.RootComponents, actual.DirectComponents, actual.TransitiveComponents)
}

func ValidateTotalCount(t *testing.T, outputType string, exactMatch bool, params *TotalCount, vulnerabilities, violations, license, sbomComponents int) {
	if params == nil {
		return
	}
	ValidateContent(t, exactMatch,
		CountValidation[int]{Expected: params.Vulnerabilities, Actual: vulnerabilities, Msg: GetValidationCountErrMsg("vulnerabilities", outputType, exactMatch, params.Vulnerabilities, vulnerabilities)},
		CountValidation[int]{Expected: params.Violations, Actual: violations, Msg: GetValidationCountErrMsg("violations", outputType, exactMatch, params.Violations, violations)},
		CountValidation[int]{Expected: params.Licenses, Actual: license, Msg: GetValidationCountErrMsg("licenses", outputType, exactMatch, params.Licenses, license)},
		CountValidation[int]{Expected: params.BomComponents, Actual: sbomComponents, Msg: GetValidationCountErrMsg("sbom components", outputType, exactMatch, params.BomComponents, sbomComponents)},
	)
}

func ValidateVulnerabilitiesCount(t *testing.T, outputType string, exactMatch bool, params *VulnerabilityCount, actual validationCountActualValues) {
	if params == nil {
		return
	}
	ValidateScanTypeCount(t, outputType, false, exactMatch, params.ValidateScan, actual.ScaVulnerabilities, actual.SastVulnerabilities, actual.SecretsVulnerabilities, actual.IacVulnerabilities)
	ValidateApplicabilityStatusCount(t, outputType, false, exactMatch, params.ValidateApplicabilityStatus, actual.ApplicableVulnerabilities, actual.UndeterminedVulnerabilities, actual.NotCoveredVulnerabilities, actual.NotApplicableVulnerabilities, actual.MissingContextVulnerabilities, actual.InactiveSecretsVulnerabilities)
}

func ValidateViolationCount(t *testing.T, outputType string, exactMatch bool, params *ViolationCount, actual validationCountActualValues) {
	if params == nil {
		return
	}
	ValidateScanTypeCount(t, outputType, true, exactMatch, params.ValidateScan, actual.ScaViolations, actual.SastViolations, actual.SecretsViolations, actual.IacViolations)
	ValidateApplicabilityStatusCount(t, outputType, true, exactMatch, params.ValidateApplicabilityStatus, actual.ApplicableViolations, actual.UndeterminedViolations, actual.NotCoveredViolations, actual.NotApplicableViolations, actual.MissingContextViolations, actual.InactiveSecretsViolations)
	ValidateScaViolationCount(t, outputType, exactMatch, params.ValidateType, actual.SecurityViolations, actual.LicenseViolations, actual.OperationalViolations)
}

func ValidateScanTypeCount(t *testing.T, outputType string, violation, exactMatch bool, params *ScanCount, scaViolations, sastViolations, secretsViolations, iacViolations int) {
	if params == nil {
		return
	}
	suffix := "vulnerabilities"
	if violation {
		suffix = "violations"
	}
	ValidateContent(t, exactMatch,
		CountValidation[int]{Expected: params.Sast, Actual: sastViolations, Msg: GetValidationCountErrMsg(fmt.Sprintf("sast %s", suffix), outputType, exactMatch, params.Sast, sastViolations)},
		CountValidation[int]{Expected: params.Secrets, Actual: secretsViolations, Msg: GetValidationCountErrMsg(fmt.Sprintf("secrets %s", suffix), outputType, exactMatch, params.Secrets, secretsViolations)},
		CountValidation[int]{Expected: params.Iac, Actual: iacViolations, Msg: GetValidationCountErrMsg(fmt.Sprintf("IaC %s", suffix), outputType, exactMatch, params.Iac, iacViolations)},
		CountValidation[int]{Expected: params.Sca, Actual: scaViolations, Msg: GetValidationCountErrMsg(fmt.Sprintf("Sca %s", suffix), outputType, exactMatch, params.Sca, scaViolations)},
	)
}

func ValidateApplicabilityStatusCount(t *testing.T, outputType string, violation, exactMatch bool, params *ApplicabilityStatusCount, applicableResults, undeterminedResults, notCoveredResults, notApplicableResults, missingContextResults, inactiveSecrets int) {
	if params == nil {
		return
	}
	suffix := "vulnerabilities"
	if violation {
		suffix = "violations"
	}
	ValidateContent(t, exactMatch,
		CountValidation[int]{Expected: params.Applicable, Actual: applicableResults, Msg: GetValidationCountErrMsg(fmt.Sprintf("applicable %s", suffix), outputType, exactMatch, params.Applicable, applicableResults)},
		CountValidation[int]{Expected: params.Undetermined, Actual: undeterminedResults, Msg: GetValidationCountErrMsg(fmt.Sprintf("undetermined %s", suffix), outputType, exactMatch, params.Undetermined, undeterminedResults)},
		CountValidation[int]{Expected: params.NotCovered, Actual: notCoveredResults, Msg: GetValidationCountErrMsg(fmt.Sprintf("not covered %s", suffix), outputType, exactMatch, params.NotCovered, notCoveredResults)},
		CountValidation[int]{Expected: params.NotApplicable, Actual: notApplicableResults, Msg: GetValidationCountErrMsg(fmt.Sprintf("not applicable %s", suffix), outputType, exactMatch, params.NotApplicable, notApplicableResults)},
		CountValidation[int]{Expected: params.MissingContext, Actual: missingContextResults, Msg: GetValidationCountErrMsg(fmt.Sprintf("missing context %s", suffix), outputType, exactMatch, params.MissingContext, missingContextResults)},
		CountValidation[int]{Expected: params.Inactive, Actual: inactiveSecrets, Msg: GetValidationCountErrMsg(fmt.Sprintf("inactive secrets %s", suffix), outputType, exactMatch, params.Inactive, inactiveSecrets)},
	)
}

func ValidateScaViolationCount(t *testing.T, outputType string, exactMatch bool, params *ScaViolationCount, securityViolations, licenseViolations, operationalViolations int) {
	if params == nil {
		return
	}
	ValidateContent(t, exactMatch,
		CountValidation[int]{Expected: params.Security, Actual: securityViolations, Msg: GetValidationCountErrMsg("security violations", outputType, exactMatch, params.Security, securityViolations)},
		CountValidation[int]{Expected: params.License, Actual: licenseViolations, Msg: GetValidationCountErrMsg("license violations", outputType, exactMatch, params.License, licenseViolations)},
		CountValidation[int]{Expected: params.Operational, Actual: operationalViolations, Msg: GetValidationCountErrMsg("operational risk violations", outputType, exactMatch, params.Operational, operationalViolations)},
	)
}

func ValidateSbomComponentsCount(t *testing.T, outputType string, exactMatch bool, params *SbomCount, rootComponents, directComponents, transitiveComponents int) {
	if params == nil {
		return
	}
	ValidateContent(t, exactMatch,
		CountValidation[int]{Expected: params.Root, Actual: rootComponents, Msg: GetValidationCountErrMsg("root components", outputType, exactMatch, params.Root, rootComponents)},
		CountValidation[int]{Expected: params.Direct, Actual: directComponents, Msg: GetValidationCountErrMsg("direct components", outputType, exactMatch, params.Direct, directComponents)},
		CountValidation[int]{Expected: params.Transitive, Actual: transitiveComponents, Msg: GetValidationCountErrMsg("transitive components", outputType, exactMatch, params.Transitive, transitiveComponents)},
	)
}
