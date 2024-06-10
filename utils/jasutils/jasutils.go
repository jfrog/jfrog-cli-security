package jasutils

const (
	EntitlementsMinVersion                    = "3.66.5"
	ApplicabilityFeatureId                    = "contextual_analysis"
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



