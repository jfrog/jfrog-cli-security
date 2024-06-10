package sast

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/stretchr/testify/assert"
)

func TestNewSastScanManager(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t, "currentDir")
	defer cleanUp()
	// Act
	sastScanManager := newSastScanManager(scanner)

	// Assert
	if assert.NotNil(t, sastScanManager) {
		assert.NotEmpty(t, sastScanManager.scanner.ConfigFileName)
		assert.NotEmpty(t, sastScanManager.scanner.ResultsFileName)
		assert.NotEmpty(t, sastScanManager.scanner.JFrogAppsConfig.Modules[0].SourceRoot)
		assert.Equal(t, &jas.FakeServerDetails, sastScanManager.scanner.ServerDetails)
	}
}

func TestSastParseResults_EmptyResults(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	// Arrange
	sastScanManager := newSastScanManager(scanner)
	sastScanManager.scanner.ResultsFileName = filepath.Join(jas.GetTestDataPath(), "sast-scan", "no-violations.sarif")

	// Act
	var err error
	sastScanManager.sastScannerResults, err = jas.ReadJasScanRunsFromFile(sastScanManager.scanner.ResultsFileName, scanner.JFrogAppsConfig.Modules[0].SourceRoot, sastDocsUrlSuffix)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, sastScanManager.sastScannerResults) {
		assert.Len(t, sastScanManager.sastScannerResults, 1)
		assert.Empty(t, sastScanManager.sastScannerResults[0].Results)
		groupResultsByLocation(sastScanManager.sastScannerResults)
		assert.Len(t, sastScanManager.sastScannerResults, 1)
		assert.Empty(t, sastScanManager.sastScannerResults[0].Results)
	}
}

func TestSastParseResults_ResultsContainIacViolations(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	// Arrange
	sastScanManager := newSastScanManager(scanner)
	sastScanManager.scanner.ResultsFileName = filepath.Join(jas.GetTestDataPath(), "sast-scan", "contains-sast-violations.sarif")

	// Act
	var err error
	sastScanManager.sastScannerResults, err = jas.ReadJasScanRunsFromFile(sastScanManager.scanner.ResultsFileName, scanner.JFrogAppsConfig.Modules[0].SourceRoot, sastDocsUrlSuffix)

	// Assert
	if assert.NoError(t, err) && assert.NotNil(t, sastScanManager.sastScannerResults) {
		assert.Len(t, sastScanManager.sastScannerResults, 1)
		assert.NotEmpty(t, sastScanManager.sastScannerResults[0].Results)
		groupResultsByLocation(sastScanManager.sastScannerResults)
		// File has 4 results, 2 of them at the same location different codeFlow
		assert.Len(t, sastScanManager.sastScannerResults[0].Results, 3)
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
