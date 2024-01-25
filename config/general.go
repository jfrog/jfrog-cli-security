package config

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils"
	"os"
	"path/filepath"
)

const (
	JfrogCurationDirName = "curation"

	CurationsDir         = "JFROG_CLI_CURATION_DIR"
	CurationMavenSupport = "JFROG_CLI_CURATION_MAVEN"
)

func GetJfrogCurationFolder() (string, error) {
	dependenciesDir := os.Getenv(CurationsDir)
	if dependenciesDir != "" {
		return utils.AddTrailingSlashIfNeeded(dependenciesDir), nil
	}
	jfrogHome, err := coreutils.GetJfrogHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(jfrogHome, JfrogCurationDirName), nil
}

func GetCurationCacheFolder() (string, error) {
	curationFolder, err := GetJfrogCurationFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(curationFolder, "cache"), nil
}

func GetCurationMavenCacheFolder() (string, error) {
	curationFolder, err := GetCurationCacheFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(curationFolder, "maven"), nil
}
