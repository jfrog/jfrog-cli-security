package utils

import (
	"encoding/json"

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