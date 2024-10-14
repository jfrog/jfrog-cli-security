package iac

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/stretchr/testify/require"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
)

func TestNewIacScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{"currentDir"})
	assert.NoError(t, err)
	// Act

	iacScanManager := newIacScanManager(scanner, "temoDirPath")

	// Assert
	if assert.NotNil(t, iacScanManager) {
		assert.NotEmpty(t, iacScanManager.configFileName)
		assert.NotEmpty(t, iacScanManager.resultsFileName)
		assert.NotEmpty(t, jfrogAppsConfigForTest.Modules[0].SourceRoot)
		assert.Equal(t, &jas.FakeServerDetails, iacScanManager.scanner.ServerDetails)
	}
}

func TestIacScan_CreateConfigFile_VerifyFileWasCreated(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.IaC.String())
	require.NoError(t, err)
	iacScanManager := newIacScanManager(scanner, scannerTempDir)

	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = iacScanManager.createConfigFile(jfrogappsconfig.Module{SourceRoot: currWd})

	defer func() {
		err = os.Remove(iacScanManager.configFileName)
		assert.NoError(t, err)
	}()

	_, fileNotExistError := os.Stat(iacScanManager.configFileName)
	assert.NoError(t, fileNotExistError)
	fileContent, err := os.ReadFile(iacScanManager.configFileName)
	assert.NoError(t, err)
	assert.True(t, len(fileContent) > 0)
}

func TestIacParseResults_EmptyResults(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)

	// Arrange
	iacScanManager := newIacScanManager(scanner, "temoDirPath")
	iacScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "iac-scan", "no-violations.sarif")

	// Act
	iacScanManager.iacScannerResults, err = jas.ReadJasScanRunsFromFile(iacScanManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, iacDocsUrlSuffix, scanner.MinSeverity)
	if assert.NoError(t, err) && assert.NotNil(t, iacScanManager.iacScannerResults) {
		assert.Len(t, iacScanManager.iacScannerResults, 1)
		assert.Empty(t, iacScanManager.iacScannerResults[0].Results)
	}
}

func TestIacParseResults_ResultsContainIacViolations(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	// Arrange
	iacScanManager := newIacScanManager(scanner, "temoDirPath")
	iacScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "iac-scan", "contains-iac-violations.sarif")

	// Act
	iacScanManager.iacScannerResults, err = jas.ReadJasScanRunsFromFile(iacScanManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, iacDocsUrlSuffix, scanner.MinSeverity)
	if assert.NoError(t, err) && assert.NotNil(t, iacScanManager.iacScannerResults) {
		assert.Len(t, iacScanManager.iacScannerResults, 1)
		assert.Len(t, iacScanManager.iacScannerResults[0].Results, 4)
	}
}
