package utils

import (
	// #nosec G505 -- Not in use for secrets.
	"crypto/sha1"
	"encoding/hex"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"os"
	"path/filepath"
)

const (
	JfrogCurationDirName = "curation"

	CurationsDir = "JFROG_CLI_CURATION_DIR"

	// #nosec G101 -- Not credentials.
	CurationMavenSupport = "JFROG_CLI_CURATION_MAVEN"

	CurationGoSupport  = "JFROG_CLI_CURATION_GO"
	CurationPipSupport = "JFROG_CLI_CURATION_PIP"
)

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

func GetCurationCacheFolderByTech(tech coreutils.Technology) (projectDir string, err error) {
	pathHash, errFromHash := getProjectPathHash(err)
	if errFromHash != nil {
		err = errFromHash
		return
	}
	curationFolder, err := GetCurationCacheFolder()
	if err != nil {
		return "", err
	}
	projectDir = filepath.Join(curationFolder, tech.String(), pathHash)
	return
}

func getProjectPathHash(err error) (string, error) {
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
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func GetCurationPipCacheFolder() (string, error) {
	curationFolder, err := GetCurationCacheFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(curationFolder, "pip"), nil
}
