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

func InitUnitTest(t *testing.T) {
	if !*configTests.TestUnit {
		t.Skip("Skipping unit tests.")
	}
}

func InitArtifactoryTest(t *testing.T) {
	if !*configTests.TestArtifactory {
		t.Skip("Skipping Artifactory test. To run Artifactory test add the '-test.artifactory=true' option.")
	}
}

func InitXrayTest(t *testing.T, minVersion string) {
	if !*configTests.TestXray {
		t.Skip("Skipping Xray test. To run Xray test add the '-test.xray=true' option.")
	}
	ValidateXrayVersion(t, minVersion)
}

func InitAuditTest(t *testing.T, minVersion string) {
	if !*configTests.TestAudit {
		t.Skip("Skipping audit test. To run Audit test add the '-test.audit=true' option.")
	}
	ValidateXrayVersion(t, minVersion)
}

func InitScanTest(t *testing.T, minVersion string) {
	if !*configTests.TestScan {
		t.Skip("Skipping scan test. To run Scan test add the '-test.scan=true' option.")
	}
	ValidateXrayVersion(t, minVersion)
}

func InitDockerScanTest(t *testing.T, minVersion string) {
	if !*configTests.TestDockerScan || !*configTests.TestScan {
		t.Skip("Skipping Docker scan test. To run Xray Docker test add the '-test.dockerScan=true' and '-test.scan=true' options.")
	}
	ValidateXrayVersion(t, minVersion)
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

func ChangeWD(t *testing.T, newPath string) string {
	prevDir, err := os.Getwd()
	assert.NoError(t, err, "Failed to get current dir")
	clientTests.ChangeDirAndAssert(t, newPath)
	return prevDir
}
