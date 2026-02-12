package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/require"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/jas"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
)

func TestNewSecretsScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	secretScanManager, err := newSecretsScanManager(scanner, SecretsScannerType, "temoDirPath")
	require.NoError(t, err)

	assert.NotEmpty(t, secretScanManager)
	assert.NotEmpty(t, secretScanManager.configFileName)
	assert.NotEmpty(t, secretScanManager.resultsFileName)
	assert.Equal(t, &jas.FakeServerDetails, secretScanManager.scanner.ServerDetails)

	assert.Empty(t, secretScanManager.resultsToCompareFileName)
}

func TestNewSecretsScanManagerWithFilesToCompare(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()

	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Secrets.String(), 0)
	require.NoError(t, err)

	secretScanManager, err := newSecretsScanManager(scanner, SecretsScannerType, scannerTempDir, sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyResult("test-markdown", "test-msg", "test-rule-id", "note")))
	require.NoError(t, err)

	// Check if path value exists and file is created
	assert.NotEmpty(t, secretScanManager.resultsToCompareFileName)
	assert.True(t, fileutils.IsPathExists(secretScanManager.resultsToCompareFileName, false))
}

func TestSecretsScan_CreateConfigFile_VerifyFileWasCreated(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Secrets.String(), 0)
	require.NoError(t, err)
	secretScanManager, err := newSecretsScanManager(scanner, SecretsScannerType, scannerTempDir)
	require.NoError(t, err)

	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = secretScanManager.createConfigFile(jfrogappsconfig.Module{SourceRoot: currWd}, []string{})
	assert.NoError(t, err)

	defer func() {
		err = os.Remove(secretScanManager.configFileName)
		assert.NoError(t, err)
	}()

	_, fileNotExistError := os.Stat(secretScanManager.configFileName)
	assert.NoError(t, fileNotExistError)
	fileContent, err := os.ReadFile(secretScanManager.configFileName)
	assert.NoError(t, err)
	assert.True(t, len(fileContent) > 0)
}

func TestRunAnalyzerManager_ReturnsGeneralError(t *testing.T) {
	defer func() {
		os.Clearenv()
	}()

	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	secretScanManager, err := newSecretsScanManager(scanner, SecretsScannerType, "temoDirPath")
	require.NoError(t, err)
	assert.Error(t, secretScanManager.runAnalyzerManager())
}

func TestParseResults_EmptyResults(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	// Arrange
	secretScanManager, err := newSecretsScanManager(scanner, SecretsScannerType, "temoDirPath")
	require.NoError(t, err)
	secretScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "secrets-scan", "no-secrets.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(secretScanManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, secretsDocsUrlSuffix, scanner.MinSeverity)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
		vulnerabilitiesResults = processSecretScanRuns(vulnerabilitiesResults)
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
	}

}

func TestParseResults_ResultsContainSecrets(t *testing.T) {
	// Arrange
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)

	secretScanManager, err := newSecretsScanManager(scanner, SecretsScannerType, "temoDirPath")
	require.NoError(t, err)
	secretScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "secrets-scan", "contain-secrets.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(secretScanManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, secretsDocsUrlSuffix, severityutils.Medium)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.NotEmpty(t, vulnerabilitiesResults[0].Results)
		vulnerabilitiesResults = processSecretScanRuns(vulnerabilitiesResults)
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Len(t, vulnerabilitiesResults[0].Results, 6)
	}
	assert.NoError(t, err)

}

func TestGetSecretsScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	vulnerabilitiesResults, _, err := RunSecretsScan(scanner, SecretsScannerType, jfrogAppsConfigForTest.Modules[0], 1, 0)
	assert.Error(t, err)
	assert.ErrorContains(t, jas.ParseAnalyzerManagerError(jasutils.Secrets, err), "failed to run Secrets scan")
	assert.Nil(t, vulnerabilitiesResults)
}

func TestHideSecret(t *testing.T) {
	tests := []struct {
		secret         string
		expectedOutput string
	}{
		{secret: "", expectedOutput: "***"},
		{secret: "12", expectedOutput: "***"},
		{secret: "123", expectedOutput: "***"},
		{secret: "123456789", expectedOutput: "123************"},
		// jfrog-ignore: dummy token for test case
		{secret: "3478hfnkjhvd848446gghgfh", expectedOutput: "347************"}, // #nosec G101 -- dummy token for test case
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, maskSecret(test.secret))
	}
}
