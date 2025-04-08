package sast

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
)

func TestNewSastScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{"currentDir"})
	assert.NoError(t, err)
	// Act
	sastScanManager, err := newSastScanManager(scanner, "temoDirPath", true)
	assert.NoError(t, err)

	// Assert
	if assert.NotNil(t, sastScanManager) {
		assert.NotEmpty(t, sastScanManager.configFileName)
		assert.True(t, sastScanManager.signedDescriptions)
		assert.NotEmpty(t, sastScanManager.resultsFileName)
		assert.NotEmpty(t, jfrogAppsConfigForTest.Modules[0].SourceRoot)
		assert.Equal(t, &jas.FakeServerDetails, sastScanManager.scanner.ServerDetails)
	}
}

func TestNewSastScanManagerWithFilesToCompare(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	tempDir, cleanUpTempDir :=  coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanUpTempDir()

	scanner.TempDir = tempDir
	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, jasutils.Secrets.String())
	require.NoError(t, err)
	
	sastScanManager, err := newSastScanManager(scanner, scannerTempDir, false, sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyResult("test-markdown", "test-msg", "test-rule-id", "note")))
	require.NoError(t, err)

	// Check if path value exists and file is created
	assert.NotEmpty(t, sastScanManager.resultsToCompareFileName)
	assert.True(t, fileutils.IsPathExists(sastScanManager.resultsToCompareFileName, false))
}

func TestSastParseResults_EmptyResults(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)

	// Arrange
	sastScanManager, err := newSastScanManager(scanner, "temoDirPath", true)
	assert.NoError(t, err)
	sastScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "sast-scan", "no-violations.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(sastScanManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, sastDocsUrlSuffix, scanner.MinSeverity)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
		groupResultsByLocation(vulnerabilitiesResults)
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.Empty(t, vulnerabilitiesResults[0].Results)
	}
}

func TestSastParseResults_ResultsContainIacViolations(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)
	// Arrange
	sastScanManager, err := newSastScanManager(scanner, "temoDirPath", false)
	assert.NoError(t, err)
	sastScanManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "sast-scan", "contains-sast-violations.sarif")

	// Act
	vulnerabilitiesResults, _, err := jas.ReadJasScanRunsFromFile(sastScanManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, sastDocsUrlSuffix, scanner.MinSeverity)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, vulnerabilitiesResults) {
		assert.Len(t, vulnerabilitiesResults, 1)
		assert.NotEmpty(t, vulnerabilitiesResults[0].Results)
		groupResultsByLocation(vulnerabilitiesResults)
		// File has 4 results, 2 of them at the same location different codeFlow
		assert.Len(t, vulnerabilitiesResults[0].Results, 3)
	}
}

func TestGroupResultsByLocation(t *testing.T) {
	tests := []struct {
		run            *sarif.Run
		expectedOutput *sarif.Run
	}{
		{
			run:            sarifutils.CreateRunWithDummyResults(),
			expectedOutput: sarifutils.CreateRunWithDummyResults(),
		},
		{
			// No similar groups at all
			run: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "note"),
				sarifutils.CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						sarifutils.CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule2", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other2", 1, 1, 1, 1, "other-snippet2"),
						sarifutils.CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
			),
			expectedOutput: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "note"),
				sarifutils.CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						sarifutils.CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file2", 1, 2, 3, 4, "snippet", "rule2", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other2", 1, 1, 1, 1, "other-snippet2"),
						sarifutils.CreateLocation("file2", 1, 2, 3, 4, "snippet"),
					)),
				}),
			),
		},
		{
			// With similar groups
			run: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						sarifutils.CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other2", 1, 1, 1, 1, "other-snippet"),
						sarifutils.CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info"),
			),
			expectedOutput: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 1, 2, 3, 4, "snippet", "rule1", "info").WithCodeFlows([]*sarif.CodeFlow{
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other", 0, 0, 0, 0, "other-snippet"),
						sarifutils.CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
					sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(
						sarifutils.CreateLocation("other2", 1, 1, 1, 1, "other-snippet"),
						sarifutils.CreateLocation("file", 1, 2, 3, 4, "snippet"),
					)),
				}),
				sarifutils.CreateResultWithOneLocation("file", 5, 6, 7, 8, "snippet", "rule1", "info"),
			),
		},
	}

	for _, test := range tests {
		groupResultsByLocation([]*sarif.Run{test.run})
		assert.ElementsMatch(t, test.expectedOutput.Results, test.run.Results)
	}
}
