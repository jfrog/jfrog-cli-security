package maliciouscode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/stretchr/testify/require"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
)

func TestNewMaliciousScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	maliciousScanManager := newMaliciousScanManager(scanner, MaliciousScannerType, "temoDirPath")

	assert.NotEmpty(t, maliciousScanManager)
	assert.NotEmpty(t, maliciousScanManager.configFileName)
	assert.NotEmpty(t, maliciousScanManager.resultsFileName)
	assert.Equal(t, &jas.FakeServerDetails, maliciousScanManager.scanner.ServerDetails)
}

func TestMaliciousScan_CreateConfigFile_VerifyFileWasCreated(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.MaliciousCode.String())
	require.NoError(t, err)
	MaliciouscanManager := newMaliciousScanManager(scanner, MaliciousScannerType, scannerTempDir)

	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = MaliciouscanManager.createConfigFile(jfrogappsconfig.Module{SourceRoot: currWd})
	assert.NoError(t, err)

	defer func() {
		err = os.Remove(MaliciouscanManager.configFileName)
		assert.NoError(t, err)
	}()

	_, fileNotExistError := os.Stat(MaliciouscanManager.configFileName)
	assert.NoError(t, fileNotExistError)
	fileContent, err := os.ReadFile(MaliciouscanManager.configFileName)
	assert.NoError(t, err)
	assert.True(t, len(fileContent) > 0)
}

func TestRunAnalyzerManager_ReturnsGeneralError(t *testing.T) {
	defer func() {
		os.Clearenv()
	}()

	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	MaliciouscanManager := newMaliciousScanManager(scanner, MaliciousScannerType, "temoDirPath")
	assert.Error(t, MaliciouscanManager.runAnalyzerManager())
}

func TestParseResults_EmptyResults(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	// Arrange
	MaliciouscanManager := newMaliciousScanManager(scanner, MaliciousScannerType, "temoDirPath")
	MaliciouscanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "Malicious-scan", "no-Malicious.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(MaliciouscanManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, maliciousDocsUrlSuffix, scanner.MinSeverity)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
	}

}

func TestParseResults_ResultsContainMalicious(t *testing.T) {
	// Arrange
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)

	MaliciouscanManager := newMaliciousScanManager(scanner, MaliciousScannerType, "temoDirPath")
	MaliciouscanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "Malicious-scan", "contain-Malicious.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(MaliciouscanManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, maliciousDocsUrlSuffix, severityutils.Medium)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.NotEmpty(t, vulnerabilitiesResults[0].Results)
	}
	assert.NoError(t, err)

}

func TestGetMaliciousScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	vulnerabilitiesResults, _, err := RunMaliciousScan(scanner, MaliciousScannerType, jfrogAppsConfigForTest.Modules[0], 0)
	assert.Error(t, err)
	assert.ErrorContains(t, jas.ParseAnalyzerManagerError(jasutils.MaliciousCode, err), "failed to run MaliciousCode scan")
	assert.Nil(t, vulnerabilitiesResults)
}
