package jasutils

import (
	"strings"

	"github.com/gookit/color"
	"github.com/jfrog/jfrog-cli-security/utils"
)

const (
	ApplicabilityRuleIdPrefix     = "applic_"
	ApplicabilitySarifPropertyKey = "applicability"

	DynamicTokenValidationMinXrayVersion = "3.101.0"
	TokenValidationStatusForNonTokens    = "Not a token"
)

const (
	Applicability JasScanType = "Applicability"
	Secrets       JasScanType = "Secrets"
	IaC           JasScanType = "IaC"
	Sast          JasScanType = "Sast"
	MaliciousCode JasScanType = "MaliciousCode"
)

const (
	Active      TokenValidationStatus = "Active"
	Inactive    TokenValidationStatus = "Inactive"
	Unsupported TokenValidationStatus = "Unsupported"
	Unavailable TokenValidationStatus = "Unavailable"
	NotAToken   TokenValidationStatus = TokenValidationStatusForNonTokens
)

type TokenValidationStatus string

type JasScanType string

func (jst JasScanType) String() string {
	return string(jst)
}

func GetJasScanTypes() []JasScanType {
	return []JasScanType{Applicability, Secrets, IaC, Sast, MaliciousCode}
}

func (tvs TokenValidationStatus) String() string { return string(tvs) }

func (tvs TokenValidationStatus) ToString() string {
	switch tvs {
	case Active:
		return color.New(color.Red).Render(tvs)
	case Inactive:
		return color.New(color.Green).Render(tvs)
	default:
		return tvs.String()
	}
}

type ApplicabilityStatus string

const (
	Applicable                ApplicabilityStatus = "Applicable"
	NotApplicable             ApplicabilityStatus = "Not Applicable"
	ApplicabilityUndetermined ApplicabilityStatus = "Undetermined"
	NotCovered                ApplicabilityStatus = "Not Covered"
	MissingContext            ApplicabilityStatus = "Missing Context"
	NotScanned                ApplicabilityStatus = ""
)

const SastFingerprintKey = "precise_sink_and_sink_function"

func (as ApplicabilityStatus) String() string {
	return string(as)
}

func (as ApplicabilityStatus) ToString(pretty bool) string {
	if !pretty {
		return as.String()
	}
	switch as {
	case Applicable:
		return color.New(color.Red).Render(as)
	case NotApplicable:
		return color.New(color.Green).Render(as)
	default:
		return as.String()
	}
}

func SubScanTypeToJasScanType(subScanType utils.SubScanType) JasScanType {
	switch subScanType {
	case utils.SastScan:
		return Sast
	case utils.IacScan:
		return IaC
	case utils.SecretsScan:
		return Secrets
	case utils.ContextualAnalysisScan:
		return Applicability
	case utils.MaliciousCodeScan:
		return MaliciousCode
	}
	return ""
}

func ConvertToApplicabilityStatus(status string) ApplicabilityStatus {
	switch status {
	case Applicable.String():
		return Applicable
	case NotApplicable.String():
		return NotApplicable
	case ApplicabilityUndetermined.String():
		return ApplicabilityUndetermined
	case NotCovered.String():
		return NotCovered
	case MissingContext.String():
		return MissingContext
	default:
		return NotScanned
	}
}

func CveToApplicabilityRuleId(cveId string) string {
	return ApplicabilityRuleIdPrefix + cveId
}

func ApplicabilityRuleIdToCve(sarifRuleId string) string {
	return strings.TrimPrefix(sarifRuleId, ApplicabilityRuleIdPrefix)
}

var applicableMapToScore = map[string]int{
	"Applicable":                5,
	"ApplicabilityUndetermined": 4,
	"NotScanned":                3,
	"MissingContext":            2,
	"NotCovered":                1,
	"NotApplicable":             0,
}

var TokenValidationOrder = map[string]int{
	"Active":      1,
	"Unsupported": 2,
	"Unavailable": 3,
	"Inactive":    4,
	"Not a token": 5,
	"":            6,
}

func ConvertApplicableToScore(applicability string) int {
	if level, ok := applicableMapToScore[strings.ToLower(applicability)]; ok {
		return level
	}
	return -1
}
