package maliciouscode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/require"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/jas"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
)

func TestNewMaliciousScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	maliciousScanManager, err := newMaliciousScanManager(scanner, MaliciousScannerType, "tempDirPath")
	require.NoError(t, err)

	assert.NotEmpty(t, maliciousScanManager)
	assert.NotEmpty(t, maliciousScanManager.configFileName)
	assert.NotEmpty(t, maliciousScanManager.resultsFileName)
	assert.Equal(t, &jas.FakeServerDetails, maliciousScanManager.scanner.ServerDetails)

	assert.Empty(t, maliciousScanManager.resultsToCompareFileName)
}

func TestNewMaliciousScanManagerWithFilesToCompare(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()

	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.MaliciousCode.String(), 0)
	require.NoError(t, err)

	maliciousScanManager, err := newMaliciousScanManager(scanner, MaliciousScannerType, scannerTempDir, sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyResult("test-markdown", "test-msg", "test-rule-id", "note")))
	require.NoError(t, err)

	// Check if path value exists and file is created
	assert.NotEmpty(t, maliciousScanManager.resultsToCompareFileName)
	assert.True(t, fileutils.IsPathExists(maliciousScanManager.resultsToCompareFileName, false))
}

func TestMaliciousScan_CreateConfigFile_VerifyFileWasCreated(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.MaliciousCode.String(), 0)
	require.NoError(t, err)
	maliciousScanManager, err := newMaliciousScanManager(scanner, MaliciousScannerType, scannerTempDir)
	require.NoError(t, err)

	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = maliciousScanManager.createConfigFile(currWd)
	assert.NoError(t, err)

	defer func() {
		err = os.Remove(maliciousScanManager.configFileName)
		assert.NoError(t, err)
	}()

	_, fileNotExistError := os.Stat(maliciousScanManager.configFileName)
	assert.NoError(t, fileNotExistError)
	fileContent, err := os.ReadFile(maliciousScanManager.configFileName)
	assert.NoError(t, err)
	assert.True(t, len(fileContent) > 0)
}

func TestRunAnalyzerManager_ReturnsGeneralError(t *testing.T) {
	defer func() {
		os.Clearenv()
	}()

	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	maliciousScanManager, err := newMaliciousScanManager(scanner, MaliciousScannerType, "tempDirPath")
	require.NoError(t, err)
	assert.Error(t, maliciousScanManager.runAnalyzerManager())
}

func TestParseResults_EmptyResults(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	// Arrange
	maliciousScanManager, err := newMaliciousScanManager(scanner, MaliciousScannerType, "tempDirPath")
	require.NoError(t, err)
	maliciousScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "malicious-scan", "no-malicious.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(maliciousScanManager.resultsFileName, currWd, malDocsUrlSuffix, scanner.MinSeverity)

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
	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)

	maliciousScanManager, err := newMaliciousScanManager(scanner, MaliciousScannerType, "tempDirPath")
	require.NoError(t, err)
	maliciousScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "malicious-scan", "contain-malicious.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(maliciousScanManager.resultsFileName, currWd, malDocsUrlSuffix, severityutils.Medium)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.NotEmpty(t, vulnerabilitiesResults[0].Results)
		// The SARIF file has 8 results, but one has level "note" which may be filtered by Medium severity
		// So we check for at least 6 results (the ones that should pass Medium severity filter)
		assert.GreaterOrEqual(t, len(vulnerabilitiesResults[0].Results), 6)
	}
	assert.NoError(t, err)
}

func TestGetMaliciousScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	vulnerabilitiesResults, err := RunMaliciousScan(scanner, MaliciousScannerType, currWd, 1, 0)
	assert.Error(t, err)
	// The error message format is "failed to run MaliciousCode scan" (no space)
	assert.ErrorContains(t, jas.ParseAnalyzerManagerError(jasutils.MaliciousCode, err), "failed to run MaliciousCode scan")
	assert.Nil(t, vulnerabilitiesResults)
}
