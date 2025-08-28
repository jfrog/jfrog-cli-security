package utils

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"
	orderedJson "github.com/virtuald/go-ordered-json"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"

	"time"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/dependencies"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const (
	NodeModulesPattern = "**/*node_modules*/**"
	JfMsiEnvVariable   = "JF_MSI"

	BaseDocumentationURL          = "https://docs.jfrog-applications.jfrog.io/jfrog-security-features/"
	JasInfoURL                    = "https://jfrog.com/xray/"
	EntitlementsMinVersion        = "3.66.5"
	GitRepoKeyAnalyticsMinVersion = "3.114.0"

	XrayToolName = "JFrog Xray Scanner"

	JfrogExternalRunIdEnv   = "JFROG_CLI_USAGE_RUN_ID"
	JfrogExternalJobIdEnv   = "JFROG_CLI_USAGE_JOB_ID"
	JfrogExternalGitRepoEnv = "JFROG_CLI_USAGE_GIT_REPO"

	CurrentGithubWorkflowNameEnvVar      = "GITHUB_WORKFLOW"
	CurrentGithubWorkflowRunNumberEnvVar = "GITHUB_RUN_NUMBER"
	CurrentGithubWorkflowWorkspaceEnvVar = "GITHUB_WORKSPACE"
	CurrentGithubWorkflowJobEnvVar       = "GITHUB_JOB"
	CurrentGithubShaEnvVar               = "GITHUB_SHA"
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

var subScanTypeToText = map[SubScanType]string{
	ContextualAnalysisScan: "Contextual Analysis",
	ScaScan:                "SCA",
	IacScan:                "IaC",
	SastScan:               "SAST",
	SecretsScan:            "Secrets",
}

func (subScan SubScanType) ToTextString() string {
	if text, ok := subScanTypeToText[subScan]; ok {
		return text
	}
	return string(subScan)
}

type ViolationIssueType string

func (v ViolationIssueType) String() string {
	return string(v)
}

type SubScanType string

func (s SubScanType) String() string {
	return string(s)
}

const (
	SourceCode  CommandType = "source_code"
	Binary      CommandType = "binary"
	DockerImage CommandType = "docker_image"
	Build       CommandType = "build"
	Curation    CommandType = "curation"
	SBOM        CommandType = "SBOM"
)

type CommandType string

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

func IsJASRequested(cmdType CommandType, requestedScans ...SubScanType) bool {
	return IsScanRequested(cmdType, ContextualAnalysisScan, requestedScans...) ||
		IsScanRequested(cmdType, SecretsScan, requestedScans...) ||
		IsScanRequested(cmdType, IacScan, requestedScans...) ||
		IsScanRequested(cmdType, SastScan, requestedScans...)
}

func GetScanFindingsLog(scanType SubScanType, vulnerabilitiesCount, violationsCount int) string {

	if vulnerabilitiesCount == 0 && violationsCount == 0 {
		return fmt.Sprintf("No %s findings", subScanTypeToText[scanType])
	}
	msg := "Found"
	hasVulnerabilities := vulnerabilitiesCount > 0
	if hasVulnerabilities {
		if scanType == SecretsScan {
			msg += fmt.Sprintf(" %d %s exposures", vulnerabilitiesCount, subScanTypeToText[scanType])
		} else {
			msg += fmt.Sprintf(" %d %s vulnerabilities", vulnerabilitiesCount, subScanTypeToText[scanType])
		}
	}
	if violationsCount > 0 {
		if hasVulnerabilities {
			msg = fmt.Sprintf("%s (%d violations)", msg, violationsCount)
		} else {
			msg += fmt.Sprintf(" %d %s violations", violationsCount, subScanTypeToText[scanType])
		}
	}
	return msg
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

func NewStringPtr(v string) *string {
	return &v
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

func NewStrPtr(v string) *string {
	return &v
}

func Md5Hash(values ...string) (string, error) {
	return toHash(crypto.MD5, values...)
}

func Sha1Hash(values ...string) (string, error) {
	return toHash(crypto.SHA1, values...)
}

func Sha256Hash(values ...string) (string, error) {
	return toHash(crypto.SHA256, values...)
}

func FileSha256(filePath string) (string, error) {
	// Read the file content
	content, err := fileutils.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return Sha256Hash(string(content))
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

func ReadSbomFromFile(cdxFilePath string) (bom *cyclonedx.BOM, err error) {
	bom = cyclonedx.NewBOM()
	file, err := os.Open(cdxFilePath)
	if errorutils.CheckError(err) != nil {
		return nil, fmt.Errorf("failed to open cdx file %s: %w", cdxFilePath, err)
	}
	defer func() {
		err = errors.Join(err, file.Close())
	}()
	if err = cyclonedx.NewBOMDecoder(file, cyclonedx.BOMFileFormatJSON).Decode(bom); err != nil {
		return nil, fmt.Errorf("failed to decode provided cdx file %s: %w", cdxFilePath, err)
	}
	return bom, nil
}

func DumpCdxContentToFile(bom *cyclonedx.BOM, scanResultsOutputDir, filePrefix string, threadId int) (err error) {
	logPrefix := ""
	if threadId >= 0 {
		logPrefix = clientutils.GetLogMsgPrefix(threadId, false)
	}
	pathToSave := filepath.Join(scanResultsOutputDir, fmt.Sprintf("%s_%s.cdx.json", filePrefix, GetCurrentTimeUnix()))
	log.Debug(fmt.Sprintf("%sScans output directory was provided, saving CycloneDX SBOM to file '%s'...", logPrefix, pathToSave))
	return SaveCdxContentToFile(pathToSave, bom)
}

func SaveCdxContentToFile(pathToSave string, bom *cyclonedx.BOM) (err error) {
	file, err := os.Create(pathToSave)
	if err != nil {
		return errorutils.CheckError(err)
	}
	defer func() {
		err = errors.Join(err, file.Close())
	}()
	return cyclonedx.NewBOMEncoder(file, cyclonedx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
}

func DumpJsonContentToFile(fileContent []byte, scanResultsOutputDir string, scanType string, threadId int) (err error) {
	return DumpContentToFile(fileContent, scanResultsOutputDir, scanType, "json", threadId)
}

func DumpSarifContentToFile(fileContent []byte, scanResultsOutputDir string, scanType string, threadId int) (err error) {
	return DumpContentToFile(fileContent, scanResultsOutputDir, scanType, "sarif", threadId)
}

func DumpContentToFile(fileContent []byte, scanResultsOutputDir string, scanType, suffix string, threadId int) (err error) {
	logPrefix := ""
	if threadId >= 0 {
		logPrefix = clientutils.GetLogMsgPrefix(threadId, false)
	}
	resultsFileFullPath := filepath.Join(scanResultsOutputDir, fmt.Sprintf("%s_%s.%s", strings.ToLower(scanType), GetCurrentTimeUnix(), suffix))
	log.Debug(fmt.Sprintf("%sScans output directory was provided, saving %s scan results to file '%s'...", logPrefix, scanType, resultsFileFullPath))
	if err = os.WriteFile(resultsFileFullPath, fileContent, 0644); errorutils.CheckError(err) != nil {
		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
	}
	return
}

func GetCurrentTimeUnix() string {
	return fmt.Sprintf("%d", time.Now().UnixMilli())
}

// Returns the key for the git reop Url, as expected by the Analyzer Manager and the Analytics event report
func GetGitRepoUrlKey(gitRepoHttpsCloneUrl string) string {
	if gitRepoHttpsCloneUrl == "" {
		return ""
	}
	return xscutils.GetGitRepoUrlKey(gitRepoHttpsCloneUrl)
}

func DownloadResourceFromPlatformIfNeeded(resourceName, downloadPath, targetDir, targetArtifactName string, explodeArtifact bool, threadId int) error {
	// Get JPD / Releases remote details to download the resource from.
	artDetails, remotePath, err := GetReleasesRemoteDetails(resourceName, downloadPath)
	if err != nil {
		return err
	}
	// Check if the resource should be downloaded.
	// First get the latest resource checksum from Artifactory.
	client, httpClientDetails, err := dependencies.CreateHttpClient(artDetails)
	if err != nil {
		return err
	}
	downloadUrl := artDetails.ArtifactoryUrl + remotePath
	remoteFileDetails, _, err := client.GetRemoteFileDetails(downloadUrl, &httpClientDetails)
	if err != nil {
		return fmt.Errorf("couldn't get remote file details for %s: %s", downloadUrl, err.Error())
	}
	// Find current resource checksum.
	checksumFilePath := filepath.Join(targetDir, dependencies.ChecksumFileName)
	if match, err := isArtifactChecksumsMatch(remoteFileDetails, checksumFilePath, true); err != nil || match {
		// If the checksums are identical, there's no need to download.
		return err
	}
	// Download & unzip the resource files
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + fmt.Sprintf("The '%s' app is not cached locally. Downloading it now...", resourceName))
	if err = dependencies.DownloadDependency(artDetails, remotePath, filepath.Join(targetDir, targetArtifactName), explodeArtifact); err != nil {
		return err
	}
	return dependencies.CreateChecksumFile(checksumFilePath, remoteFileDetails.Checksum.Sha256)
}

func isArtifactChecksumsMatch(remoteFileDetails *fileutils.FileDetails, localFilePath string, contentIsTheChecksum bool) (match bool, err error) {
	if remoteFileDetails == nil {
		return false, fmt.Errorf("remote file details are nil for %s", localFilePath)
	}
	// Find current checksum.
	if exist, err := fileutils.IsFileExists(localFilePath, false); err != nil || !exist {
		return false, err
	}
	// Read the file content
	content, err := fileutils.ReadFile(localFilePath)
	if err != nil {
		return false, fmt.Errorf("failed to read file %s: %w", localFilePath, err)
	}
	if contentIsTheChecksum {
		// File content is the checksum value, compare the local checksum with the remote one.
		return remoteFileDetails.Checksum.Sha256 == string(content), nil
	}
	// File content is the actual file, calculate the checksum and compare it with the remote one.
	sha256, err := Sha256Hash(string(content))
	if err != nil {
		return false, fmt.Errorf("failed to calculate the local file checksum: %w", err)
	}
	return remoteFileDetails.Checksum.Sha256 == sha256, nil
}
