package utils

import (
	// #nosec G505 -- Not in use for secrets.
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const (
	BaseDocumentationURL = "https://docs.jfrog-applications.jfrog.io/jfrog-security-features/"
	JasInfoURL           = "https://jfrog.com/xray/"

	ScaScan     SubScanType = "sca"
	SecretsScan SubScanType = "secrets"
	IacScan     SubScanType = "iac"
	SastScan    SubScanType = "sast"

	JfrogCurationDirName = "curation"
	CurationsDir         = "JFROG_CLI_CURATION_DIR"
	// TODO: remove this environment variable and start using a general one for all curation types.
	// #nosec G101 -- Not credentials.
	CurationMavenSupport = "JFROG_CLI_CURATION_MAVEN"
	CurationPipSupport   = "JFROG_CLI_CURATION_PIP"
)

type SubScanType string

func (s SubScanType) String() string {
	return string(s)
}

// UniqueUnion returns a new slice of strings that contains elements from both input slices without duplicates
func UniqueUnion(arr []string, others ...string) []string {
	uniqueSet := datastructures.MakeSet[string]()
	var result []string
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

func getJfrogCurationFolder() (string, error) {
	dependenciesDir := os.Getenv(CurationsDir)
	if dependenciesDir != "" {
		return dependenciesDir, nil
	}
	jfrogHome, err := coreutils.GetJfrogHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(jfrogHome, JfrogCurationDirName), nil
}

func GetCurationCacheFolder() (string, error) {
	curationFolder, err := getJfrogCurationFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(curationFolder, "cache"), nil
}

func GetCurationMavenCacheFolder() (projectDir string, err error) {
	curationFolder, err := GetCurationCacheFolder()
	if err != nil {
		return "", err
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// #nosec G401 -- Not a secret hash.
	hasher := sha1.New()
	_, err = hasher.Write([]byte(workingDir))
	if err != nil {
		return "", err
	}
	projectDir = filepath.Join(curationFolder, "maven", hex.EncodeToString(hasher.Sum(nil)))
	return
}

func GetCurationPipCacheFolder() (string, error) {
	curationFolder, err := GetCurationCacheFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(curationFolder, "pip"), nil
}
