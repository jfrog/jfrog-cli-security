package applicability

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

var mockDirectDependencies = []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"}
var mockMultiRootDirectDependencies = []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency", "issueId_3_direct_dependency", "issueId_4_direct_dependency"}

func TestNewApplicabilityScanManager_InputIsValid(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	// Act
	applicabilityManager := newApplicabilityScanManager(jas.FakeBasicXrayResults, mockDirectDependencies, scanner, false, ApplicabilityScannerType, "temoDirPath")

	// Assert
	if assert.NotNil(t, applicabilityManager) {
		assert.NotEmpty(t, applicabilityManager.configFileName)
		assert.NotEmpty(t, applicabilityManager.resultsFileName)
		assert.Len(t, applicabilityManager.directDependenciesCves, 5)
	}
}

func TestNewApplicabilityScanManager_DependencyTreeDoesntExist(t *testing.T) {
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	// Act
	applicabilityManager := newApplicabilityScanManager(jas.FakeBasicXrayResults, nil, scanner, false, ApplicabilityScannerType, "tempDirPath")

	// Assert
	if assert.NotNil(t, applicabilityManager) {
		assert.NotNil(t, applicabilityManager.scanner.ScannerDirCleanupFunc)
		assert.NotEmpty(t, applicabilityManager.configFileName)
		assert.NotEmpty(t, applicabilityManager.resultsFileName)
		assert.Empty(t, applicabilityManager.directDependenciesCves)
	}
}

func TestNewApplicabilityScanManager_NoDirectDependenciesInScan(t *testing.T) {
	// Arrange
	var noDirectDependenciesResults = []services.ScanResponse{
		{
			ScanId: "scanId_1",
			Vulnerabilities: []services.Vulnerability{
				{IssueId: "issueId_1", Technology: techutils.Pipenv.String(),
					Cves: []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}, {Id: "testCve3"}},
					Components: map[string]services.Component{
						"issueId_1_non_direct_dependency": {}}},
			},
			Violations: []services.Violation{
				{IssueId: "issueId_2", Technology: techutils.Pipenv.String(),
					Cves: []services.Cve{{Id: "testCve4"}, {Id: "testCve5"}},
					Components: map[string]services.Component{
						"issueId_2_non_direct_dependency": {}}},
			},
		},
	}
	jas.FakeBasicXrayResults[0].Vulnerabilities[0].Components["issueId_1_non_direct_dependency"] = services.Component{}
	jas.FakeBasicXrayResults[0].Violations[0].Components["issueId_2_non_direct_dependency"] = services.Component{}

	// Act
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	applicabilityManager := newApplicabilityScanManager(noDirectDependenciesResults, mockDirectDependencies, scanner, false, ApplicabilityScannerType, "temoDirPath")
	assertApplicabilityScanner(t, applicabilityManager)
	// ThirdPartyContextual shouldn't change anything here as this is not npm.
	applicabilityManager = newApplicabilityScanManager(noDirectDependenciesResults, mockDirectDependencies, scanner, true, ApplicabilityScannerType, "temoDirPath")
	assertApplicabilityScanner(t, applicabilityManager)
}

func assertApplicabilityScanner(t *testing.T, applicabilityManager *ApplicabilityScanManager) {
	if assert.NotNil(t, applicabilityManager) {
		assert.NotEmpty(t, applicabilityManager.configFileName)
		assert.NotEmpty(t, applicabilityManager.resultsFileName)
		// Non-direct dependencies should not be added
		assert.Empty(t, applicabilityManager.directDependenciesCves)
	}
}

func TestNewApplicabilityScanManager_MultipleDependencyTrees(t *testing.T) {
	// Arrange
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	// Act
	applicabilityManager := newApplicabilityScanManager(jas.FakeBasicXrayResults, mockMultiRootDirectDependencies, scanner, false, ApplicabilityScannerType, "temoDirPath")

	// Assert
	if assert.NotNil(t, applicabilityManager) {
		assert.NotEmpty(t, applicabilityManager.configFileName)
		assert.NotEmpty(t, applicabilityManager.resultsFileName)
		assert.Len(t, applicabilityManager.directDependenciesCves, 5)
	}
}

func TestNewApplicabilityScanManager_ViolationsDontExistInResults(t *testing.T) {
	// Arrange
	noViolationScanResponse := []services.ScanResponse{
		{
			ScanId: "scanId_1",
			Vulnerabilities: []services.Vulnerability{
				{IssueId: "issueId_1", Technology: techutils.Pipenv.String(),
					Cves:       []services.Cve{{Id: "test_cve_1"}, {Id: "test_cve_2"}, {Id: "test_cve_3"}},
					Components: map[string]services.Component{"issueId_1_direct_dependency": {}}},
			},
		},
	}
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	// Act
	applicabilityManager := newApplicabilityScanManager(noViolationScanResponse, mockDirectDependencies, scanner, false, ApplicabilityScannerType, "temoDirPath")

	// Assert
	if assert.NotNil(t, applicabilityManager) {
		assert.NotEmpty(t, applicabilityManager.configFileName)
		assert.NotEmpty(t, applicabilityManager.resultsFileName)
		assert.Len(t, applicabilityManager.directDependenciesCves, 3)
	}
}

func TestNewApplicabilityScanManager_VulnerabilitiesDontExist(t *testing.T) {
	// Arrange
	noVulnerabilitiesScanResponse := []services.ScanResponse{
		{
			ScanId: "scanId_1",
			Violations: []services.Violation{
				{IssueId: "issueId_2", Technology: techutils.Pipenv.String(),
					Cves:       []services.Cve{{Id: "test_cve_3"}, {Id: "test_cve_4"}},
					Components: map[string]services.Component{"issueId_2_direct_dependency": {}}},
			},
		},
	}
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	// Act
	applicabilityManager := newApplicabilityScanManager(noVulnerabilitiesScanResponse, mockDirectDependencies, scanner, false, ApplicabilityScannerType, "temoDirPath")

	// Assert
	if assert.NotNil(t, applicabilityManager) {
		assert.NotEmpty(t, applicabilityManager.configFileName)
		assert.NotEmpty(t, applicabilityManager.resultsFileName)
		assert.Len(t, applicabilityManager.directDependenciesCves, 2)
	}
}

func TestExtractXrayDirectViolations(t *testing.T) {
	var xrayResponseForDirectViolationsTest = []services.ScanResponse{
		{
			Violations: []services.Violation{
				{IssueId: "issueId_2", Technology: techutils.Pipenv.String(),
					Cves:       []services.Cve{{Id: "testCve4"}, {Id: "testCve5"}},
					Components: map[string]services.Component{"issueId_2_direct_dependency": {}}},
			},
		},
	}
	tests := []struct {
		directDependencies []string
		directCvesCount    int
		indirectCvesCount  int
	}{
		{directDependencies: []string{"issueId_2_direct_dependency", "issueId_1_direct_dependency"},
			directCvesCount:   2,
			indirectCvesCount: 0,
		},
		// Vulnerability dependency, should be ignored by function
		{directDependencies: []string{"issueId_1_direct_dependency"},
			directCvesCount:   0,
			indirectCvesCount: 2,
		},
		{directDependencies: []string{},
			directCvesCount:   0,
			indirectCvesCount: 2,
		},
	}

	for _, test := range tests {
		directCves, indirectCves := extractDependenciesCvesFromScan(xrayResponseForDirectViolationsTest, test.directDependencies)
		assert.Len(t, directCves, test.directCvesCount)
		assert.Len(t, indirectCves, test.indirectCvesCount)
	}
}

func TestExtractXrayDirectVulnerabilities(t *testing.T) {
	var xrayResponseForDirectVulnerabilitiesTest = []services.ScanResponse{
		{
			ScanId: "scanId_1",
			Vulnerabilities: []services.Vulnerability{
				{
					IssueId: "issueId_1", Technology: techutils.Pipenv.String(),
					Cves:       []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}, {Id: "testCve3"}},
					Components: map[string]services.Component{"issueId_1_direct_dependency": {}},
				},
				{
					IssueId: "issueId_2", Technology: techutils.Pipenv.String(),
					Cves:       []services.Cve{{Id: "testCve4"}, {Id: "testCve5"}},
					Components: map[string]services.Component{"issueId_2_direct_dependency": {}},
				},
			},
		},
	}
	tests := []struct {
		directDependencies []string
		directCvesCount    int
		indirectCvesCount  int
	}{
		{
			directDependencies: []string{"issueId_1_direct_dependency"},
			directCvesCount:    3,
			indirectCvesCount:  2,
		},
		{
			directDependencies: []string{"issueId_2_direct_dependency"},
			directCvesCount:    2,
			indirectCvesCount:  3,
		},
		{directDependencies: []string{},
			directCvesCount:   0,
			indirectCvesCount: 5,
		},
	}

	for _, test := range tests {
		directCves, indirectCves := extractDependenciesCvesFromScan(xrayResponseForDirectVulnerabilitiesTest, test.directDependencies)
		assert.Len(t, directCves, test.directCvesCount)
		assert.Len(t, indirectCves, test.indirectCvesCount)
	}
}

func TestCreateConfigFile_VerifyFileWasCreated(t *testing.T) {
	// Arrange
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()

	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, string(jasutils.Applicability))
	require.NoError(t, err)
	applicabilityManager := newApplicabilityScanManager(jas.FakeBasicXrayResults, []string{"issueId_1_direct_dependency", "issueId_2_direct_dependency"}, scanner, false, ApplicabilityScannerType, scannerTempDir)

	currWd, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = applicabilityManager.createConfigFile(jfrogappsconfig.Module{SourceRoot: currWd})
	assert.NoError(t, err)

	defer func() {
		err = os.Remove(applicabilityManager.configFileName)
		assert.NoError(t, err)
	}()

	_, fileNotExistError := os.Stat(applicabilityManager.configFileName)
	assert.NoError(t, fileNotExistError)
	fileContent, err := os.ReadFile(applicabilityManager.configFileName)
	assert.NoError(t, err)
	assert.True(t, len(fileContent) > 0)
}

func TestParseResults_NewApplicabilityStatuses(t *testing.T) {
	testCases := []struct {
		name                          string
		fileName                      string
		expectedResults               int
		expectedApplicabilityStatuses []string
	}{
		{
			name:            "empty results - all cves should get unknown",
			fileName:        "empty-results.sarif",
			expectedResults: 0,
		},
		{
			name:            "applicable cve exist",
			fileName:        "applicable-cve-results.sarif",
			expectedResults: 2,
		},
		{
			name:            "all cves not applicable",
			fileName:        "no-applicable-cves-results.sarif",
			expectedResults: 5,
		},

		{
			name:                          "new applicability statuses",
			fileName:                      "new_ca_status.sarif",
			expectedResults:               5,
			expectedApplicabilityStatuses: []string{"applicable", "undetermined", "not_covered", "missing_context", "not_applicable"},
		},
	}

	// Arrange
	scanner, cleanUp := jas.InitJasTest(t)
	defer cleanUp()
	jfrogAppsConfigForTest, err := jas.CreateJFrogAppsConfig([]string{})
	assert.NoError(t, err)

	scannerTempDir, err := jas.CreateScannerTempDirectory(scanner, string(jasutils.Applicability))
	require.NoError(t, err)
	applicabilityManager := newApplicabilityScanManager(jas.FakeBasicXrayResults, mockDirectDependencies, scanner, false, ApplicabilityScannerType, scannerTempDir)

	// Act
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			applicabilityManager.resultsFileName = filepath.Join(jas.GetTestDataPath(), "applicability-scan", tc.fileName)
			var err error
			applicabilityManager.applicabilityScanResults, err = jas.ReadJasScanRunsFromFile(applicabilityManager.resultsFileName, jfrogAppsConfigForTest.Modules[0].SourceRoot, applicabilityDocsUrlSuffix, scanner.MinSeverity)
			if assert.NoError(t, err) && assert.NotNil(t, applicabilityManager.applicabilityScanResults) {
				assert.Len(t, applicabilityManager.applicabilityScanResults, 1)
				assert.Len(t, applicabilityManager.applicabilityScanResults[0].Results, tc.expectedResults)
				if tc.name == "new applicability statuses" {
					assert.Len(t, applicabilityManager.applicabilityScanResults[0].Tool.Driver.Rules, len(tc.expectedApplicabilityStatuses))
					for i, value := range tc.expectedApplicabilityStatuses {
						assert.Equal(t, value, applicabilityManager.applicabilityScanResults[0].Tool.Driver.Rules[i].Properties["applicability"])
					}
				}
			}
		})
	}
}
