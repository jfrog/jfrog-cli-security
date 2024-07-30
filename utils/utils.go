package utils

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const (
	NodeModulesPattern = "**/*node_modules*/**"
	JfMsiEnvVariable   = "JF_MSI"

	BaseDocumentationURL = "https://docs.jfrog-applications.jfrog.io/jfrog-security-features/"
	JasInfoURL           = "https://jfrog.com/xray/"
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
)

type SubScanType string

func (s SubScanType) String() string {
	return string(s)
}

func GetAllSupportedScans() []SubScanType {
	return []SubScanType{ScaScan, ContextualAnalysisScan, IacScan, SastScan, SecretsScan}
}

// UniqueUnion returns a new slice of strings that contains elements from both input slices without duplicates
func UniqueUnion[T comparable](arr []T, others ...T) []T {
	uniqueSet := datastructures.MakeSet[T]()
	var result []T
	for _, str := range arr {
		uniqueSet.Add(str)
		result = append(result, str)
	}
	for _, str := range others {
		if exist := uniqueSet.Exists(str); !exist {
			result = append(result, str)
		}
	}
	return result
}

func GetAsJsonString(output interface{}) (string, error) {
	results, err := json.Marshal(output)
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	return clientUtils.IndentJson(results), nil
}

func NewBoolPtr(v bool) *bool {
	return &v
}

func NewIntPtr(v int) *int {
	return &v
}

func NewInt64Ptr(v int64) *int64 {
	return &v
}

func NewFloat64Ptr(v float64) *float64 {
	return &v
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

func SplitAndTrim(s, sep string) []string {
	split := strings.Split(s, sep)
	for i, str := range split {
		split[i] = strings.TrimSpace(str)
	}
	return split
}