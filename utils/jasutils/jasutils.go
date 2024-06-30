package jasutils

import (
	"strings"

	"github.com/gookit/color"
)

const (
	ApplicabilityRuleIdPrefix = "applic_"
)

const (
	Applicability JasScanType = "Applicability"
	Secrets       JasScanType = "Secrets"
	IaC           JasScanType = "IaC"
	Sast          JasScanType = "Sast"
)

type JasScanType string

func (jst JasScanType) String() string {
	return string(jst)
}

type ApplicabilityStatus string

const (
	Applicable                ApplicabilityStatus = "Applicable"
	NotApplicable             ApplicabilityStatus = "Not Applicable"
	ApplicabilityUndetermined ApplicabilityStatus = "Undetermined"
	NotCovered                ApplicabilityStatus = "Not Covered"
	NotScanned                ApplicabilityStatus = ""
)

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
