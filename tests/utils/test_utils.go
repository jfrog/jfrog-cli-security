package utils

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	configTests "github.com/jfrog/jfrog-cli-security/tests"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
)

func InitSecurityTest(t *testing.T, xrayMinVersion string) {
	if !*configTests.TestSecurity {
		t.Skip("Skipping Security test. To run Security test add the '-test.security=true' option.")
	}
	ValidateXrayVersion(t, xrayMinVersion)
}

func GetTestResourcesPath() string {
	dir, _ := os.Getwd()
	return filepath.ToSlash(dir + "/tests/testdata/")
}

func CleanTestsHomeEnv() {
	os.Unsetenv(coreutils.HomeDir)
	CleanFileSystem()
}

func CleanFileSystem() {
	removeDirs(configTests.Out, configTests.Temp)
}

func removeDirs(dirs ...string) {
	for _, dir := range dirs {
		isExist, err := fileutils.IsDirExists(dir, false)
		if err != nil {
			log.Error(err)
		}
		if isExist {
			err = fileutils.RemoveTempDir(dir)
			if err != nil {
				log.Error(errors.New("Cannot remove path: " + dir + " due to: " + err.Error()))
			}
		}
	}
}

func getXrayVersion() (version.Version, error) {
	xrayVersion, err := configTests.XrAuth.GetVersion()
	return *version.NewVersion(xrayVersion), err
}

func getXscVersion() (version.Version, error) {
	xscVersion, err := configTests.XscAuth.GetVersion()
	return *version.NewVersion(xscVersion), err
}

func ChangeWD(t *testing.T, newPath string) string {
	prevDir, err := os.Getwd()
	assert.NoError(t, err, "Failed to get current dir")
	clientTests.ChangeDirAndAssert(t, newPath)
	return prevDir
}
