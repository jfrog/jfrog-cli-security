package utils

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
)

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityUnknown  Severity = "Unknown"
)

type Severity string

func (s Severity) String() string {
	return string(s)
}

const (
	SarifSeverityError  SarifSeverityLevel = "error"
	SarifSeverityWarning SarifSeverityLevel = "warning"
	SarifSeverityInfo    SarifSeverityLevel = "info"
	SarifSeverityNote    SarifSeverityLevel = "note"
	SarifSeverityNone    SarifSeverityLevel = "none"
)

type SarifSeverityLevel string

func (s SarifSeverityLevel) String() string {
	return string(s)
}

type SeverityDetails struct {
	Priority int
	// for GitHub Security Alerts
	Score    float32
}

var Severities = map[Severity]map[jasutils.ApplicabilityStatus]*SeverityDetails{
	SeverityCritical: {
		jasutils.Applicable: &SeverityDetails{Priority: 20, Score: 10},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 19, Score: 10},
		jasutils.NotCovered: &SeverityDetails{Priority: 18, Score: 10},
		jasutils.NotApplicable: &SeverityDetails{Priority: 5, Score: 10},
	},
	SeverityHigh: {
		jasutils.Applicable: &SeverityDetails{Priority: 17, Score: 8.9},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 16, Score: 8.9},
		jasutils.NotCovered: &SeverityDetails{Priority: 15, Score: 8.9},
		jasutils.NotApplicable: &SeverityDetails{Priority: 4, Score: 8.9},
	},
	SeverityMedium: {
		jasutils.Applicable: &SeverityDetails{Priority: 14, Score: 6.9},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 13, Score: 6.9},
		jasutils.NotCovered: &SeverityDetails{Priority: 12, Score: 6.9},
		jasutils.NotApplicable: &SeverityDetails{Priority: 3, Score: 6.9},
	},
	SeverityLow: {
		jasutils.Applicable: &SeverityDetails{Priority: 11, Score: 3.9},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 10, Score: 3.9},
		jasutils.NotCovered: &SeverityDetails{Priority: 9, Score: 3.9},
		jasutils.NotApplicable: &SeverityDetails{Priority: 2, Score: 3.9},
	},
	SeverityUnknown: {
		jasutils.Applicable: &SeverityDetails{Priority: 8, Score: 0},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 7, Score: 0},
		jasutils.NotCovered: &SeverityDetails{Priority: 6, Score: 0},
		jasutils.NotApplicable: &SeverityDetails{Priority: 1, Score: 0},
	},
}

func GetSeverityDetails(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus) *SeverityDetails {
	// If invalid severity is provided, return default severity details
	if _, ok := Severities[severity]; !ok {
		return &SeverityDetails{Priority: 0, Score: 0}
	}
	return Severities[severity][applicabilityStatus]
}

func GetSeverityScore(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus) string {
	return fmt.Sprintf("%.1f", GetSeverityDetails(severity,applicabilityStatus).Score)
}

func GetSeverityPriority(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus) int {
	return GetSeverityDetails(severity, applicabilityStatus).Priority
}

// CompareSeverity compares two severities and returns the difference in priority
// If severity1 is more severe than severity2, the result will be positive
func CompareSeverity(severity1, severity2 Severity) int {
	return GetSeverityDetails(severity1, jasutils.Applicable).Priority - GetSeverityDetails(severity2, jasutils.Applicable).Priority
}

func ParseToSeverity(severity string) Severity {
	switch severity {
	case SeverityCritical.String():
		return SeverityCritical
	case SeverityHigh.String():
		return SeverityHigh
	case SeverityMedium.String():
		return SeverityMedium
	case SeverityLow.String():
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

func ParseToSarifSeverityLevel(sarifSeverity string) SarifSeverityLevel {
	switch sarifSeverity {
	case SarifSeverityError.String():
		return SarifSeverityError
	case SarifSeverityWarning.String():
		return SarifSeverityWarning
	case SarifSeverityInfo.String():
		return SarifSeverityInfo
	case SarifSeverityNote.String():
		return SarifSeverityNote
	default:
		return SarifSeverityNone
	}
}

// -- Severity conversion functions --

func SeverityToSarifSeverityLevel(severity Severity) SarifSeverityLevel {
	switch severity {
	case SeverityCritical:
		return SarifSeverityError
	case SeverityHigh:
		return SarifSeverityError
	case SeverityMedium:
		return SarifSeverityWarning
	case SeverityLow:
		return SarifSeverityNote
	default:
		return SarifSeverityNone
	}
}

func SarifSeverityLevelToSeverity(level SarifSeverityLevel) Severity {
	switch level {
	case SarifSeverityError:
		return SeverityHigh
	case SarifSeverityNote:
		return SeverityLow
	case SarifSeverityNone:
		return SeverityUnknown
	default:
		return SeverityMedium
	}
}