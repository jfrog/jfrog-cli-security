package severityutils

import (
	_ "embed"
	"strconv"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/gookit/color"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	MinCveScore float32 = 0.0
	MaxCveScore float32 = 10.0
	// When parsing Sarif level to severity,
	// If the level is not provided, the value is defaulted to be 'Medium'
	SeverityDefaultValue      = Medium
	SarifSeverityRuleProperty = "security-severity"
)

const (
	Critical    Severity = "Critical"
	High        Severity = "High"
	Medium      Severity = "Medium"
	Low         Severity = "Low"
	Information Severity = "Information"
	Unknown     Severity = "Unknown"
)

func GetSeverityIcon(severity Severity) string {
	return getSeverityEmojiIcon(severity)
}

func getSeverityEmojiIcon(severity Severity) string {
	switch severity {
	case Critical:
		return "❗️"
	case High:
		return "🔴"
	case Medium:
		return "🟠"
	case Low:
		return "🟡"
	case Information:
		return "ℹ️"
	default:
		return "❔"
	}
}

type Severity string

func (s Severity) String() string {
	return string(s)
}

// CompareSeverity compares two severities and returns the difference in priority
// If severity1 is more severe than severity2, the result will be positive
func CompareSeverity(severity1, severity2 Severity) int {
	return GetSeverityPriority(severity1, jasutils.Applicable) - GetSeverityPriority(severity2, jasutils.Applicable)
}

const (
	LevelError   SarifSeverityLevel = "error"
	LevelWarning SarifSeverityLevel = "warning"
	LevelInfo    SarifSeverityLevel = "info"
	LevelNote    SarifSeverityLevel = "note"
	LevelNone    SarifSeverityLevel = "none"
)

type SarifSeverityLevel string

func (s SarifSeverityLevel) String() string {
	return string(s)
}

func supportedSarifSeverities() []string {
	return []string{
		LevelError.String(),
		LevelWarning.String(),
		LevelInfo.String(),
		LevelNote.String(),
		LevelNone.String(),
	}
}

type SeverityDetails struct {
	Priority int
	// for GitHub Security Alerts
	Score float32
	// Pretty format
	Emoji string
	style color.Style
}

func (sd SeverityDetails) ToString(severity Severity, pretty bool) string {
	if !pretty {
		return severity.String()
	}
	return sd.style.Render(sd.Emoji + severity.String())
}

func (sd SeverityDetails) ToDetails(severity Severity, pretty bool) formats.SeverityDetails {
	return formats.SeverityDetails{Severity: sd.ToString(severity, pretty), SeverityNumValue: sd.Priority}
}

var Severities = map[Severity]map[jasutils.ApplicabilityStatus]*SeverityDetails{
	Critical: {
		jasutils.Applicable:                &SeverityDetails{Priority: 30, Score: MaxCveScore, Emoji: "💀", style: color.New(color.BgLightRed, color.LightWhite)},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 29, Score: MaxCveScore, Emoji: "💀", style: color.New(color.BgLightRed, color.LightWhite)},
		jasutils.MissingContext:            &SeverityDetails{Priority: 28, Score: MaxCveScore, Emoji: "💀", style: color.New(color.BgLightRed, color.LightWhite)},
		jasutils.NotCovered:                &SeverityDetails{Priority: 27, Score: MaxCveScore, Emoji: "💀", style: color.New(color.BgLightRed, color.LightWhite)},
		jasutils.NotApplicable:             &SeverityDetails{Priority: 6, Score: MaxCveScore, Emoji: "💀", style: color.New(color.Gray)},
	},
	High: {
		jasutils.Applicable:                &SeverityDetails{Priority: 26, Score: 8.9, Emoji: "🔥", style: color.New(color.Red)},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 25, Score: 8.9, Emoji: "🔥", style: color.New(color.Red)},
		jasutils.MissingContext:            &SeverityDetails{Priority: 24, Score: 8.9, Emoji: "🔥", style: color.New(color.Red)},
		jasutils.NotCovered:                &SeverityDetails{Priority: 23, Score: 8.9, Emoji: "🔥", style: color.New(color.Red)},
		jasutils.NotApplicable:             &SeverityDetails{Priority: 5, Score: 8.9, Emoji: "🔥", style: color.New(color.Gray)},
	},
	Medium: {
		jasutils.Applicable:                &SeverityDetails{Priority: 22, Score: 6.9, Emoji: "🎃", style: color.New(color.Yellow)},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 21, Score: 6.9, Emoji: "🎃", style: color.New(color.Yellow)},
		jasutils.MissingContext:            &SeverityDetails{Priority: 20, Score: 6.9, Emoji: "🎃", style: color.New(color.Yellow)},
		jasutils.NotCovered:                &SeverityDetails{Priority: 19, Score: 6.9, Emoji: "🎃", style: color.New(color.Yellow)},
		jasutils.NotApplicable:             &SeverityDetails{Priority: 4, Score: 6.9, Emoji: "🎃", style: color.New(color.Gray)},
	},
	Low: {
		jasutils.Applicable:                &SeverityDetails{Priority: 18, Score: 3.9, Emoji: "👻"},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 17, Score: 3.9, Emoji: "👻"},
		jasutils.MissingContext:            &SeverityDetails{Priority: 16, Score: 3.9, Emoji: "👻"},
		jasutils.NotCovered:                &SeverityDetails{Priority: 15, Score: 3.9, Emoji: "👻"},
		jasutils.NotApplicable:             &SeverityDetails{Priority: 3, Score: 3.9, Emoji: "👻", style: color.New(color.Gray)},
	},
	Information: {
		jasutils.Applicable:                &SeverityDetails{Priority: 14, Score: MinCveScore, Emoji: "ℹ️", style: color.New(color.Blue)},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 13, Score: MinCveScore, Emoji: "ℹ️", style: color.New(color.Blue)},
		jasutils.MissingContext:            &SeverityDetails{Priority: 12, Score: MinCveScore, Emoji: "ℹ️", style: color.New(color.Blue)},
		jasutils.NotCovered:                &SeverityDetails{Priority: 11, Score: MinCveScore, Emoji: "ℹ️", style: color.New(color.Blue)},
		jasutils.NotApplicable:             &SeverityDetails{Priority: 2, Score: MinCveScore, Emoji: "ℹ️", style: color.New(color.Gray)},
	},
	Unknown: {
		jasutils.Applicable:                &SeverityDetails{Priority: 10, Score: MinCveScore, Emoji: "😐"},
		jasutils.ApplicabilityUndetermined: &SeverityDetails{Priority: 9, Score: MinCveScore, Emoji: "😐"},
		jasutils.MissingContext:            &SeverityDetails{Priority: 8, Score: MinCveScore, Emoji: "😐"},
		jasutils.NotCovered:                &SeverityDetails{Priority: 7, Score: MinCveScore, Emoji: "😐"},
		jasutils.NotApplicable:             &SeverityDetails{Priority: 1, Score: MinCveScore, Emoji: "😐", style: color.New(color.Gray)},
	},
}

func supportedSeverities() (severities []string) {
	for severity := range Severities {
		severities = append(severities, severity.String())
	}
	return
}

func supportedApplicabilityStatuses() []string {
	set := datastructures.MakeSet[string]()
	for status := range Severities[Critical] {
		set.Add(status.String())
	}
	return set.ToSlice()
}

// -- Parsing functions, only for supported values --

func ParseToSeverity(severity string) (parsed Severity, err error) {
	formattedSeverity := cases.Title(language.Und).String(severity)
	switch formattedSeverity {
	case Critical.String():
		parsed = Critical
	case High.String():
		parsed = High
	case Medium.String():
		parsed = Medium
	case Low.String():
		parsed = Low
	case Information.String():
		parsed = Information
	case Unknown.String():
		parsed = Unknown
	default:
		err = errorutils.CheckErrorf("severity '%s' is not supported, only the following severities are supported: %s", severity, coreutils.ListToText(supportedSeverities()))
	}
	return
}

func ParseToSarifSeverityLevel(sarifSeverity string) (parsed SarifSeverityLevel, err error) {
	formattedSeverity := strings.ToLower(sarifSeverity)
	switch formattedSeverity {
	case LevelError.String():
		parsed = LevelError
	case LevelWarning.String():
		parsed = LevelWarning
	case LevelInfo.String():
		parsed = LevelInfo
	case LevelNote.String():
		parsed = LevelNote
	case LevelNone.String():
		parsed = LevelNone
	case "":
		// Default value for Sarif severity level is 'Warning' (Medium) if not provided
		parsed = LevelWarning
	default:
		err = errorutils.CheckErrorf("Sarif level '%s' is not supported, only the following levels are supported: %s", sarifSeverity, coreutils.ListToText(supportedSarifSeverities()))
	}
	return
}

func ParseSeverity(severity string, sarifSeverity bool) (parsed Severity, err error) {
	if !sarifSeverity {
		return ParseToSeverity(severity)
	}
	sarifLevel, err := ParseToSarifSeverityLevel(severity)
	if err != nil {
		parsed = SeverityDefaultValue
	} else {
		parsed = sarifSeverityLevelToSeverity(sarifLevel)
	}
	return
}

func ParseForDetails(severity string, sarifSeverity bool, applicabilityStatus jasutils.ApplicabilityStatus) (details *SeverityDetails, err error) {
	if applicabilityStatus == jasutils.NotScanned {
		err = errorutils.CheckErrorf("only the following severities are supported: %s", coreutils.ListToText(supportedApplicabilityStatuses()))
		return
	}
	parsed, err := ParseSeverity(severity, sarifSeverity)
	if err != nil {
		return
	}
	details = Severities[parsed][applicabilityStatus]
	return
}

// -- Getters functions (With default values) --

func GetAsDetails(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus, pretty bool) formats.SeverityDetails {
	if applicabilityStatus == jasutils.NotScanned {
		// Pass 'NotCovered' as default value to get priority, since 'NotScanned' returns 0 priority for all severities
		applicabilityStatus = jasutils.NotCovered
	}
	return GetSeverityDetails(severity, applicabilityStatus).ToDetails(severity, pretty)
}

func GetSeverityDetails(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus) *SeverityDetails {
	if applicabilityStatus == jasutils.NotScanned {
		applicabilityStatus = jasutils.Applicable
	}
	details, err := ParseForDetails(severity.String(), false, applicabilityStatus)
	if err != nil {
		return &SeverityDetails{Priority: 0, Score: 0}
	}
	return details
}

func GetSeverityScore(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus) float32 {
	return GetSeverityDetails(severity, applicabilityStatus).Score
}

func GetSeverityScoreFloat64(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus) *float64 {
	score := GetSeverityScore(severity, applicabilityStatus)
	// convert score to have up to 1 digits after the decimal point
	convertedScore := float64(int(score*10)) / 10
	return &convertedScore
}

func GetCvssScore(cvssScore string) *float64 {
	if cvssScore == "" {
		return nil
	}
	// convert score to float64
	scoreFloat, err := strconv.ParseFloat(cvssScore, 64)
	if err != nil {
		return nil
	}
	return &scoreFloat
}

func GetSeverityPriority(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus) int {
	return GetSeverityDetails(severity, applicabilityStatus).Priority
}

func GetSeverity(severity string) Severity {
	parsed, err := ParseToSeverity(severity)
	if err != nil {
		return Unknown
	}
	return parsed
}

func GetSarifSeverityLevel(severity string) SarifSeverityLevel {
	sarifLevel, err := ParseToSarifSeverityLevel(severity)
	if err != nil {
		return LevelNone
	}
	return sarifLevel
}

// -- Conversion functions --

func SeverityToSarifSeverityLevel(severity Severity) SarifSeverityLevel {
	switch severity {
	case Critical:
		return LevelError
	case High:
		return LevelError
	case Medium:
		return LevelWarning
	case Low:
		return LevelNote
	case Information:
		return LevelInfo
	default:
		return LevelNone
	}
}

func sarifSeverityLevelToSeverity(level SarifSeverityLevel) Severity {
	switch level {
	case LevelError:
		return High
	case LevelNote:
		return Low
	case LevelInfo:
		return Information
	case LevelNone:
		return Unknown
	default:
		// All other values (include default) mapped as 'Medium' severity
		return Medium
	}
}

func SeverityToCycloneDxSeverity(severity Severity) cyclonedx.Severity {
	switch severity {
	case Critical:
		return cyclonedx.SeverityCritical
	case High:
		return cyclonedx.SeverityHigh
	case Medium:
		return cyclonedx.SeverityMedium
	case Low:
		return cyclonedx.SeverityLow
	case Information:
		return cyclonedx.SeverityInfo
	default:
		return cyclonedx.SeverityUnknown
	}
}

func CycloneDxSeverityToSeverity(severity cyclonedx.Severity) Severity {
	switch severity {
	case cyclonedx.SeverityCritical:
		return Critical
	case cyclonedx.SeverityHigh:
		return High
	case cyclonedx.SeverityMedium:
		return Medium
	case cyclonedx.SeverityLow:
		return Low
	case cyclonedx.SeverityInfo:
		return Information
	default:
		return Unknown
	}
}

func XraySeverityToSeverity(severity xrayUtils.Severity) Severity {
	switch severity {
	case xrayUtils.Critical:
		return Critical
	case xrayUtils.High:
		return High
	case xrayUtils.Medium:
		return Medium
	case xrayUtils.Low:
		return Low
	case xrayUtils.Information:
		return Information
	default:
		return Unknown
	}
}

func CreateSeverityRating(severity Severity, applicabilityStatus jasutils.ApplicabilityStatus, service *cyclonedx.Service) cyclonedx.VulnerabilityRating {
	return cyclonedx.VulnerabilityRating{
		Source: &cyclonedx.Source{
			Name: service.Name,
		},
		Severity: SeverityToCycloneDxSeverity(severity),
		Score:    GetSeverityScoreFloat64(severity, applicabilityStatus),
		Method:   cyclonedx.ScoringMethodOther,
	}
}

func MostSevereSeverity(severities ...Severity) Severity {
	if len(severities) == 0 {
		return Unknown
	}
	mostSevere := severities[0]
	for _, severity := range severities[1:] {
		if CompareSeverity(severity, mostSevere) > 0 {
			mostSevere = severity
		}
	}
	return mostSevere
}
