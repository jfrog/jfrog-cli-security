package utils

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	return []SubScanType{ScaScan, ContextualAnalysisScan, IacScan, SastScan, SecretsScan}
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
