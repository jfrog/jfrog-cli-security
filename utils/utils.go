package utils

import (
	"fmt"
	"strings"
)

const (
	NodeModulesPattern     = "**/*node_modules*/**"
	JfMsiEnvVariable       = "JF_MSI"
	EntitlementsMinVersion = "3.66.5"
)

var (
	// Exclude pattern for files.
	DefaultJasExcludePatterns = []string{"**/.git/**", "**/*test*/**", "**/*venv*/**", NodeModulesPattern, "**/target/**"}
	// Exclude pattern for directories.
	DefaultScaExcludePatterns = []string{"*.git*", "*node_modules*", "*target*", "*venv*", "*test*"}
)

const (
	ContextualAnalysisScan SubScanType = "contextual_analysis"
	ScaScan                SubScanType = "sca"
	IacScan                SubScanType = "iac"
	SastScan               SubScanType = "sast"
	SecretsScan            SubScanType = "secrets"

	ViolationTypeSecurity        ViolationIssueType = "security"
	ViolationTypeLicense         ViolationIssueType = "license"
	ViolationTypeOperationalRisk ViolationIssueType = "operational_risk"
)

type ViolationIssueType string

func (v ViolationIssueType) String() string {
	return string(v)
}

type SubScanType string

func (s SubScanType) String() string {
	return string(s)
}

func GetAllSupportedScans() []SubScanType {
	return []SubScanType{ScaScan, ContextualAnalysisScan, IacScan, SastScan, SecretsScan}
}

// map[string]string to []string (key=value format)
func ToCommandEnvVars(envVarsMap map[string]string) (converted []string) {
	converted = make([]string, 0, len(envVarsMap))
	for key, value := range envVarsMap {
		converted = append(converted, fmt.Sprintf("%s=%s", key, value))
	}
	return
}

// []string (key=value format) to map[string]string
func ToEnvVarsMap(envVars []string) (converted map[string]string) {
	converted = make(map[string]string)
	for _, envVar := range envVars {
		key, value := splitEnvVar(envVar)
		converted[key] = value
	}
	return
}

// Merge multiple maps into one, the last map will override the previous ones
func MergeMaps(maps ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}

func splitEnvVar(envVar string) (key, value string) {
	split := strings.Split(envVar, "=")
	if len(split) == 1 {
		return split[0], ""
	}
	return split[0], strings.Join(split[1:], "=")
}

// This is a general error message for the CLI commands.
// Due to the way we parse the commands, in some cases flags might be mistaken as arguments and therefore they will not go though the command's flags verifications.
// When this happens it could prevent the flag from affecting the command as intended. This error message informes the user about this issue
func GetCliTooManyArgsErrorMessage(numberOfArguments int, commandName string) string {
	return fmt.Sprintf("Too many arguments provided (%d in total).\n"+
		"Some flags might be mistaken as arguments and ignored, which could prevent them from affecting the command as intended.\n"+
		"Please ensure all provided flags are valid and provided correct order. For more details: 'jf %s --help'", numberOfArguments, commandName)
}
