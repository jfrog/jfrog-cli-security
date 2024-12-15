package utils

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	orderedJson "github.com/virtuald/go-ordered-json"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"

	"time"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const (
	NodeModulesPattern = "**/*node_modules*/**"
	JfMsiEnvVariable   = "JF_MSI"

	BaseDocumentationURL   = "https://docs.jfrog-applications.jfrog.io/jfrog-security-features/"
	JasInfoURL             = "https://jfrog.com/xray/"
	EntitlementsMinVersion = "3.66.5"
)

var (
	// Exclude pattern for files.
	DefaultJasExcludePatterns = []string{"**/.git/**", "**/*test*/**", "**/*venv*/**", NodeModulesPattern, "**/target/**", "**/dist/**"}
	// Exclude pattern for directories.
	DefaultScaExcludePatterns = []string{"*.git*", "*node_modules*", "*target*", "*venv*", "*test*", "dist"}
)

const (
	ContextualAnalysisScan       SubScanType        = "contextual_analysis"
	ScaScan                      SubScanType        = "sca"
	IacScan                      SubScanType        = "iac"
	SastScan                     SubScanType        = "sast"
	SecretsScan                  SubScanType        = "secrets"
	SecretTokenValidationScan    SubScanType        = "secrets_token_validation"
	ViolationTypeSecurity        ViolationIssueType = "security"
	ViolationTypeLicense         ViolationIssueType = "license"
	ViolationTypeOperationalRisk ViolationIssueType = "operational_risk"
)

type ViolationIssueType string

func (v ViolationIssueType) String() string {
	return string(v)
}

type SubScanType string

const (
	SourceCode  CommandType = "source_code"
	Binary      CommandType = "binary"
	DockerImage CommandType = "docker_image"
	Build       CommandType = "build"
	Curation    CommandType = "curation"
	SBOM        CommandType = "SBOM"
)

type CommandType string

func (s SubScanType) String() string {
	return string(s)
}

func (s CommandType) IsTargetBinary() bool {
	return s == Binary || s == DockerImage
}

func GetAllSupportedScans() []SubScanType {
	return []SubScanType{ScaScan, ContextualAnalysisScan, IacScan, SastScan, SecretsScan, SecretTokenValidationScan}
}

// IsScanRequested returns true if the scan is requested, otherwise false. If requestedScans is empty, all scans are considered requested.
func IsScanRequested(cmdType CommandType, subScan SubScanType, requestedScans ...SubScanType) bool {
	if cmdType.IsTargetBinary() && (subScan == IacScan || subScan == SastScan) {
		return false
	}
	return len(requestedScans) == 0 || slices.Contains(requestedScans, subScan)
}

func IsCI() bool {
	return strings.ToLower(os.Getenv(coreutils.CI)) == "true"
}

// UniqueIntersection returns a new slice of strings that contains elements from both input slices without duplicates
func UniqueIntersection[T comparable](arr []T, others ...T) []T {
	uniqueSet := datastructures.MakeSetFromElements(arr...)
	uniqueIntersection := datastructures.MakeSet[T]()
	for _, other := range others {
		if exist := uniqueSet.Exists(other); exist {
			uniqueIntersection.Add(other)
		}
	}
	return uniqueIntersection.ToSlice()
}

// UniqueUnion returns a new slice of strings that contains elements from the input slice and the elements provided without duplicates
func UniqueUnion[T comparable](arr []T, elements ...T) []T {
	uniqueSet := datastructures.MakeSetFromElements(arr...)
	uniqueSet.AddElements(elements...)
	return uniqueSet.ToSlice()
}

func GetAsJsonBytes(output interface{}, escapeValues, indent bool) (results []byte, err error) {
	if escapeValues {
		if results, err = orderedJson.Marshal(output); errorutils.CheckError(err) != nil {
			return
		}
	} else {
		buffer := &bytes.Buffer{}
		encoder := json.NewEncoder(buffer)
		encoder.SetEscapeHTML(false)
		if err = encoder.Encode(output); err != nil {
			return
		}
		results = buffer.Bytes()
	}
	if indent {
		return doIndent(results)
	}
	return
}

func doIndent(bytesRes []byte) ([]byte, error) {
	var content bytes.Buffer
	if err := json.Indent(&content, bytesRes, "", "  "); errorutils.CheckError(err) != nil {
		return content.Bytes(), err
	}
	return content.Bytes(), nil
}

func GetAsJsonString(output interface{}, escapeValues, indent bool) (string, error) {
	results, err := GetAsJsonBytes(output, escapeValues, indent)
	if err != nil {
		return "", err
	}
	return string(results), nil
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

func Md5Hash(values ...string) (string, error) {
	return toHash(crypto.MD5, values...)
}

func Sha1Hash(values ...string) (string, error) {
	return toHash(crypto.SHA1, values...)
}

func toHash(hash crypto.Hash, values ...string) (string, error) {
	h := hash.New()
	for _, ob := range values {
		_, err := fmt.Fprint(h, ob)
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

func DumpContentToFile(fileContent []byte, scanResultsOutputDir string, scanType string) (err error) {
	// TODO this function should be in utils/results/results.go after the refactor, since it is a common code for Jas and SCA scanners
	// TODO AFTER merging the refactor - make sure to create a new directory for every Scan Target and convert results to Sarif before writing them to file
	var curTimeHash string
	if curTimeHash, err = Md5Hash(time.Now().String()); err != nil {
		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
	}

	resultsFileName := strings.ToLower(scanType) + "_results_" + curTimeHash + ".json"
	resultsFileFullPath := filepath.Join(scanResultsOutputDir, resultsFileName)
	log.Debug(fmt.Sprintf("Scans output directory was provided, saving %s scan results to file '%s'...", scanType, resultsFileFullPath))
	if err = os.WriteFile(resultsFileFullPath, fileContent, 0644); err != nil {
		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
	}
	return
}
