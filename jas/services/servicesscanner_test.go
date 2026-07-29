package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/require"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/stretchr/testify/assert"
)

func TestNewServicesScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{"currentDir"})
	assert.NoError(t, err)

	servicesScanManager, err := newServicesScanManager(scanner, "temoDirPath")
	assert.NoError(t, err)

	if assert.NotNil(t, servicesScanManager) {
		assert.NotEmpty(t, servicesScanManager.configFileName)
		assert.NotEmpty(t, servicesScanManager.resultsFileName)
		assert.NotEmpty(t, jfrogAppsConfigForTest.Modules[0].SourceRoot)
		assert.Equal(t, &jas.FakeServerDetails, servicesScanManager.scanner.ServerDetails)
	}
}

func TestNewServicesScanManagerWithFilesToCompare(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()

	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Services.String(), 0)
	require.NoError(t, err)

	servicesScanManager, err := newServicesScanManager(scanner, scannerTempDir, sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyResult("test-markdown", "test-msg", "test-rule-id", "note")))
	require.NoError(t, err)

	assert.NotEmpty(t, servicesScanManager.resultsToCompareFileName)
	assert.True(t, fileutils.IsPathExists(servicesScanManager.resultsToCompareFileName, false))
}

func TestServicesScan_CreateDeprecatedConfigFile_VerifyFileWasCreated(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Services.String(), 0)
	require.NoError(t, err)
	servicesScanManager, err := newServicesScanManager(scanner, scannerTempDir)
	require.NoError(t, err)

	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = servicesScanManager.deprecatedCreateConfigFile(jfrogappsconfig.Module{SourceRoot: currWd}, []string{})

	defer func() {
		err = os.Remove(servicesScanManager.configFileName)
		assert.NoError(t, err)
	}()

	_, fileNotExistError := os.Stat(servicesScanManager.configFileName)
	assert.NoError(t, fileNotExistError)
	fileContent, err := os.ReadFile(servicesScanManager.configFileName)
	assert.NoError(t, err)
	assert.True(t, len(fileContent) > 0)
	assert.Contains(t, string(fileContent), servicesScannerType)
}

func TestServicesScan_CreateConfigFile_VerifyFileWasCreated(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()

	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Services.String(), 0)
	require.NoError(t, err)

	servicesScanManager, err := newServicesScanManager(scanner, scannerTempDir)
	require.NoError(t, err)

	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = servicesScanManager.createConfigFileForTarget(results.ScanTarget{Target: currWd})
	assert.NoError(t, err)

	defer func() {
		err = os.Remove(servicesScanManager.configFileName)
		assert.NoError(t, err)
	}()

	_, fileNotExistError := os.Stat(servicesScanManager.configFileName)
	assert.NoError(t, fileNotExistError)
	fileContent, err := os.ReadFile(servicesScanManager.configFileName)
	assert.NoError(t, err)
	assert.True(t, len(fileContent) > 0)
	assert.Contains(t, string(fileContent), servicesScannerType)
}

func TestServicesParseResults_EmptyResults(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)

	servicesScanManager, err := newServicesScanManager(scanner, "temoDirPath")
	require.NoError(t, err)
	servicesScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "services-scan", "no-violations.sarif")

	vulnerabilitiesResults, violationResults, err := jas.ReadJasScanRunsFromFile(servicesScanManager.resultsFileName, servicesDocsUrlSuffix, scanner.MinSeverity, jfrogAppsConfigForTest.Modules[0].SourceRoot)
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
	}
	assert.Empty(t, violationResults)
}

func TestServicesParseResults_ResultsContainServicesIssues(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)

	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	servicesScanManager, err := newServicesScanManager(scanner, "temoDirPath")
	require.NoError(t, err)
	assert.NoError(t, biutils.CopyDir(filepath.Join(jas.GetTestDataPath(), "services-scan"), tempDirPath, true, nil))
	servicesScanManager.resultsFileName = filepath.Join(tempDirPath, "contains-services-issues.sarif")

	vulnerabilitiesResults, violationResults, err := jas.ReadJasScanRunsFromFile(servicesScanManager.resultsFileName, servicesDocsUrlSuffix, scanner.MinSeverity, jfrogAppsConfigForTest.Modules[0].SourceRoot)
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Len(t, vulnerabilitiesResults[0].Results, 4)
	}
	if assert.NotNil(t, violationResults) {
		assert.Len(t, violationResults, 1)
		assert.Len(t, violationResults[0].Results, 1)
	}
}

func TestGetServicesScanResults_AnalyzerManagerReturnsError(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	servicesScanParams := ServicesScanParams{
		TargetCount: 1,
		Target:      results.ScanTarget{Target: jfrogAppsConfigForTest.Modules[0].SourceRoot, DeprecatedAppsConfigModule: &jfrogAppsConfigForTest.Modules[0]},
	}
	vulnerabilitiesResults, _, err := RunServicesScan(scanner, servicesScanParams)
	assert.Error(t, err)
	assert.ErrorContains(t, jas.ParseAnalyzerManagerError(jasutils.Services, err), "failed to run Services scan")
	assert.Nil(t, vulnerabilitiesResults)
}
