package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

func TestGetVulnerabilityOrViolationSarifHeadline(t *testing.T) {
	assert.Equal(t, "[CVE-2022-1234] loadsh 1.4.1", getXrayIssueSarifHeadline("loadsh", "1.4.1", "CVE-2022-1234"))
	assert.NotEqual(t, "[CVE-2022-1234] loadsh 1.4.1", getXrayIssueSarifHeadline("loadsh", "1.2.1", "CVE-2022-1234"))
}

func TestGetIssueIdentifier(t *testing.T) {
	issueId := "XRAY-123456"
	cvesRow := []formats.CveRow{{Id: "CVE-2022-1234"}}
	assert.Equal(t, "CVE-2022-1234", GetIssueIdentifier(cvesRow, issueId))
	cvesRow = append(cvesRow, formats.CveRow{Id: "CVE-2019-1234"})
	assert.Equal(t, "CVE-2022-1234, CVE-2019-1234", GetIssueIdentifier(cvesRow, issueId))
	assert.Equal(t, issueId, GetIssueIdentifier(nil, issueId))
}

func TestGetDirectDependenciesFormatted(t *testing.T) {
	testCases := []struct {
		name           string
		directDeps     []formats.ComponentRow
		expectedOutput string
	}{
		{
			name: "Single direct dependency",
			directDeps: []formats.ComponentRow{
				{Name: "example-package", Version: "1.0.0"},
			},
			expectedOutput: "`example-package 1.0.0`",
		},
		{
			name: "Multiple direct dependencies",
			directDeps: []formats.ComponentRow{
				{Name: "dependency1", Version: "1.0.0"},
				{Name: "dependency2", Version: "2.0.0"},
			},
			expectedOutput: "`dependency1 1.0.0`<br/>`dependency2 2.0.0`",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := getDirectDependenciesFormatted(tc.directDeps)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestGetSarifTableDescription(t *testing.T) {
	testCases := []struct {
		name                string
		formattedDeps       string
		maxCveScore         string
		status              jasutils.ApplicabilityStatus
		fixedVersions       []string
		expectedDescription string
	}{
		{
			name:                "Applicable vulnerability",
			formattedDeps:       "`example-package 1.0.0`",
			maxCveScore:         "7.5",
			status:              "Applicable",
			fixedVersions:       []string{"1.0.1", "1.0.2"},
			expectedDescription: "| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| 7.5      | Applicable       | `example-package 1.0.0`       | 1.0.1, 1.0.2   |",
		},
		{
			name:                "Not-scanned vulnerability",
			formattedDeps:       "`example-package 2.0.0`",
			maxCveScore:         "6.2",
			status:              "",
			fixedVersions:       []string{"2.0.1"},
			expectedDescription: "| Severity Score | Direct Dependencies | Fixed Versions     |\n| :---:        |    :----:   |          :---: |\n| 6.2      | `example-package 2.0.0`       | 2.0.1   |",
		},
		{
			name:                "No fixed versions",
			formattedDeps:       "`example-package 3.0.0`",
			maxCveScore:         "3.0",
			status:              "",
			fixedVersions:       []string{},
			expectedDescription: "| Severity Score | Direct Dependencies | Fixed Versions     |\n| :---:        |    :----:   |          :---: |\n| 3.0      | `example-package 3.0.0`       | No fix available   |",
		},
		{
			name:                "Not-covered vulnerability",
			formattedDeps:       "`example-package 3.0.0`",
			maxCveScore:         "3.0",
			status:              "Not covered",
			fixedVersions:       []string{"3.0.1"},
			expectedDescription: "| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| 3.0      | Not covered       | `example-package 3.0.0`       | 3.0.1   |",
		},
		{
			name:                "Undetermined vulnerability",
			formattedDeps:       "`example-package 3.0.0`",
			maxCveScore:         "3.0",
			status:              "Undetermined",
			fixedVersions:       []string{"3.0.1"},
			expectedDescription: "| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| 3.0      | Undetermined       | `example-package 3.0.0`       | 3.0.1   |",
		},
		{
			name:                "Not-status vulnerability",
			formattedDeps:       "`example-package 3.0.0`",
			maxCveScore:         "3.0",
			status:              "Not status",
			fixedVersions:       []string{"3.0.1"},
			expectedDescription: "| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| 3.0      | Not status       | `example-package 3.0.0`       | 3.0.1   |",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getSarifTableDescription(tc.formattedDeps, tc.maxCveScore, tc.status.String(), tc.fixedVersions)
			assert.Equal(t, tc.expectedDescription, output)
		})
	}
}

func TestFindMaxCVEScore(t *testing.T) {
	testCases := []struct {
		name           string
		cves           []formats.CveRow
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "CVEScore with valid float values",
			cves: []formats.CveRow{
				{Id: "CVE-2021-1234", CvssV3: "7.5"},
				{Id: "CVE-2021-5678", CvssV3: "9.2"},
			},
			expectedOutput: "9.2",
		},
		{
			name: "CVEScore with invalid float value",
			cves: []formats.CveRow{
				{Id: "CVE-2022-4321", CvssV3: "invalid"},
			},
			expectedOutput: "",
			expectedError:  true,
		},
		{
			name:           "CVEScore without values",
			cves:           []formats.CveRow{},
			expectedOutput: "0.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := findMaxCVEScore(tc.cves)
			assert.False(t, tc.expectedError && err == nil)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestGetXrayIssueLocationIfValidExists(t *testing.T) {
	testDir, cleanup := tests.CreateTempDirWithCallbackAndAssert(t)
	defer cleanup()
	invocation := sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(testDir))
	file, err := os.Create(filepath.Join(testDir, "go.mod"))
	assert.NoError(t, err)
	assert.NotNil(t, file)
	defer func() { assert.NoError(t, file.Close()) }()
	file2, err := os.Create(filepath.Join(testDir, "build.gradle.kts"))
	assert.NoError(t, err)
	assert.NotNil(t, file2)
	defer func() { assert.NoError(t, file2.Close()) }()

	testCases := []struct {
		name           string
		tech           techutils.Technology
		run            *sarif.Run
		expectedOutput *sarif.Location
	}{
		{
			name:           "No descriptor information",
			tech:           techutils.Pip,
			run:            sarifutils.CreateRunWithDummyResults().WithInvocations([]*sarif.Invocation{invocation}),
			expectedOutput: sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://Package-Descriptor"))),
		},
		{
			name:           "One descriptor information",
			tech:           techutils.Go,
			run:            sarifutils.CreateRunWithDummyResults().WithInvocations([]*sarif.Invocation{invocation}),
			expectedOutput: sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://" + filepath.Join(testDir, "go.mod")))),
		},
		{
			name:           "One descriptor information - no invocation",
			tech:           techutils.Go,
			run:            sarifutils.CreateRunWithDummyResults(),
			expectedOutput: sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://go.mod"))),
		},
		{
			name:           "Multiple descriptor information",
			tech:           techutils.Gradle,
			run:            sarifutils.CreateRunWithDummyResults().WithInvocations([]*sarif.Invocation{invocation}),
			expectedOutput: sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://" + filepath.Join(testDir, "build.gradle.kts")))),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := getXrayIssueLocationIfValidExists(tc.tech, tc.run)
			if assert.NoError(t, err) {
				assert.Equal(t, tc.expectedOutput, output)
			}
		})
	}
}

func TestConvertXrayScanToSimpleJson(t *testing.T) {
	vulnerabilities := []services.Vulnerability{
		{
			IssueId:    "XRAY-1",
			Summary:    "summary-1",
			Severity:   "high",
			Components: map[string]services.Component{"component-A": {}, "component-B": {}},
		},
		{
			IssueId:    "XRAY-2",
			Summary:    "summary-2",
			Severity:   "low",
			Components: map[string]services.Component{"component-B": {}},
		},
	}
	expectedVulnerabilities := []formats.VulnerabilityOrViolationRow{
		{
			Summary: "summary-1",
			IssueId: "XRAY-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "High"},
				ImpactedDependencyName: "component-A",
			},
		},
		{
			Summary: "summary-1",
			IssueId: "XRAY-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "High"},
				ImpactedDependencyName: "component-B",
			},
		},
		{
			Summary: "summary-2",
			IssueId: "XRAY-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
				ImpactedDependencyName: "component-B",
			},
		},
	}

	violations := []services.Violation{
		{
			IssueId:       "XRAY-1",
			Summary:       "summary-1",
			Severity:      "high",
			WatchName:     "watch-1",
			ViolationType: "security",
			Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
		},
		{
			IssueId:       "XRAY-2",
			Summary:       "summary-2",
			Severity:      "low",
			WatchName:     "watch-1",
			ViolationType: "license",
			LicenseKey:    "license-1",
			Components:    map[string]services.Component{"component-B": {}},
		},
	}
	expectedSecViolations := []formats.VulnerabilityOrViolationRow{
		{
			Summary: "summary-1",
			IssueId: "XRAY-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "High"},
				ImpactedDependencyName: "component-A",
			},
		},
		{
			Summary: "summary-1",
			IssueId: "XRAY-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "High"},
				ImpactedDependencyName: "component-B",
			},
		},
	}
	expectedLicViolations := []formats.LicenseRow{
		{
			LicenseKey: "license-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
				ImpactedDependencyName: "component-B",
			},
		},
	}

	licenses := []services.License{
		{
			Key:        "license-1",
			Name:       "license-1-name",
			Components: map[string]services.Component{"component-A": {}, "component-B": {}},
		},
		{
			Key:        "license-2",
			Name:       "license-2-name",
			Components: map[string]services.Component{"component-B": {}},
		},
	}
	expectedLicenses := []formats.LicenseRow{
		{
			LicenseKey:                "license-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "component-A"},
		},
		{
			LicenseKey:                "license-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "component-B"},
		},
		{
			LicenseKey:                "license-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "component-B"},
		},
	}

	testCases := []struct {
		name            string
		result          services.ScanResponse
		includeLicenses bool
		allowedLicenses []string
		expectedOutput  formats.SimpleJsonResults
	}{
		{
			name:            "Vulnerabilities only",
			includeLicenses: false,
			allowedLicenses: nil,
			result:          services.ScanResponse{Vulnerabilities: vulnerabilities, Licenses: licenses},
			expectedOutput:  formats.SimpleJsonResults{Vulnerabilities: expectedVulnerabilities},
		},
		{
			name:            "Vulnerabilities with licenses",
			includeLicenses: true,
			allowedLicenses: nil,
			result:          services.ScanResponse{Vulnerabilities: vulnerabilities, Licenses: licenses},
			expectedOutput:  formats.SimpleJsonResults{Vulnerabilities: expectedVulnerabilities, Licenses: expectedLicenses},
		},
		{
			name:            "Vulnerabilities only - with allowed licenses",
			includeLicenses: false,
			allowedLicenses: []string{"license-1"},
			result:          services.ScanResponse{Vulnerabilities: vulnerabilities, Licenses: licenses},
			expectedOutput: formats.SimpleJsonResults{
				Vulnerabilities: expectedVulnerabilities,
				LicensesViolations: []formats.LicenseRow{
					{
						LicenseKey:                "license-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "component-B"},
					},
				},
			},
		},
		{
			name:            "Violations only",
			includeLicenses: false,
			allowedLicenses: nil,
			result:          services.ScanResponse{Violations: violations, Licenses: licenses},
			expectedOutput:  formats.SimpleJsonResults{SecurityViolations: expectedSecViolations, LicensesViolations: expectedLicViolations},
		},
		{
			name:            "Violations - override allowed licenses",
			includeLicenses: false,
			allowedLicenses: []string{"license-1"},
			result:          services.ScanResponse{Violations: violations, Licenses: licenses},
			expectedOutput:  formats.SimpleJsonResults{SecurityViolations: expectedSecViolations, LicensesViolations: expectedLicViolations},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := NewAuditResults(SourceCode)
			scaScanResult := ScaScanResult{XrayResults: []services.ScanResponse{tc.result}}
			results.ScaResults = append(results.ScaResults, &scaScanResult)
			output, err := ConvertXrayScanToSimpleJson(results, false, tc.includeLicenses, true, tc.allowedLicenses)
			if assert.NoError(t, err) {
				assert.ElementsMatch(t, tc.expectedOutput.Vulnerabilities, output.Vulnerabilities)
				assert.ElementsMatch(t, tc.expectedOutput.SecurityViolations, output.SecurityViolations)
				assert.ElementsMatch(t, tc.expectedOutput.LicensesViolations, output.LicensesViolations)
				assert.ElementsMatch(t, tc.expectedOutput.Licenses, output.Licenses)
				assert.ElementsMatch(t, tc.expectedOutput.OperationalRiskViolations, output.OperationalRiskViolations)
			}
		})
	}
}

func TestJSONMarshall(t *testing.T) {
	testCases := []struct {
		testName       string
		resultString   string
		expectedResult string
	}{
		{
			testName:       "Regular URL",
			resultString:   "http://my-artifactory.jfrog.io/",
			expectedResult: "\"http://my-artifactory.jfrog.io/\"\n",
		},
		{
			testName:       "Regular CVE",
			resultString:   "CVE-2021-4104",
			expectedResult: "\"CVE-2021-4104\"\n",
		},
		{
			testName:       "URL with escape characters ignore rules",
			resultString:   "https://my-artifactory.jfrog.com/ui/admin/xray/policiesGovernance/ignore-rules?graph_scan_id=1babb2d0-42c0-4389-7770-18a6cab8d9a7\u0026issue_id=XRAY-590941\u0026on_demand_scanning=true\u0026show_popup=true\u0026type=security\u0026watch_name=my-watch",
			expectedResult: "\"https://my-artifactory.jfrog.com/ui/admin/xray/policiesGovernance/ignore-rules?graph_scan_id=1babb2d0-42c0-4389-7770-18a6cab8d9a7&issue_id=XRAY-590941&on_demand_scanning=true&show_popup=true&type=security&watch_name=my-watch\"\n",
		},
		{
			testName:       "URL with escape characters build scan data",
			resultString:   "https://my-artifactory.jfrog.com/ui/scans-list/builds-scans/dort1/scan-descendants/1?version=1\u0026package_id=build%3A%2F%2Fdort1\u0026build_repository=artifactory-build-info\u0026component_id=build%3A%2F%2Fshweta1%3A1\u0026page_type=security-vulnerabilities\u0026exposure_status=to_fix",
			expectedResult: "\"https://my-artifactory.jfrog.com/ui/scans-list/builds-scans/dort1/scan-descendants/1?version=1&package_id=build%3A%2F%2Fdort1&build_repository=artifactory-build-info&component_id=build%3A%2F%2Fshweta1%3A1&page_type=security-vulnerabilities&exposure_status=to_fix\"\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			printedString, err := JSONMarshalNotEscaped(tc.resultString)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedResult, string(printedString))
		})
	}
}

func TestGetSummary(t *testing.T) {
	dummyExtendedScanResults := &ExtendedScanResults{
		ApplicabilityScanResults: []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateDummyPassingResult("applic_CVE-2")).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
		},
		SecretsScanResults: []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target1/file", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target2/file", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target2")),
			}),
		},
		SastScanResults: []*sarif.Run{
			sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithLocations("", "", "note", sarifutils.CreateLocation("target1/file2", 0, 0, 0, 0, "snippet"))).WithInvocations([]*sarif.Invocation{
				sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("target1")),
			}),
		},
	}

	expectedVulnerabilities := &formats.ScanResultSummary{
		ScaResults: &formats.ScaScanResultSummary{
			ScanIds:      []string{TestScaScanId},
			MoreInfoUrls: []string{TestMoreInfoUrl},
			Security: formats.ResultSummary{
				"Critical": map[string]int{jasutils.ApplicabilityUndetermined.String(): 1},
				"High":     map[string]int{jasutils.NotApplicable.String(): 1},
			},
		},
		SecretsResults: &formats.ResultSummary{"Low": map[string]int{jasutils.NotScanned.String(): 2}},
		SastResults:    &formats.ResultSummary{"Low": map[string]int{jasutils.NotScanned.String(): 1}},
	}
	expectedViolations := &formats.ScanViolationsSummary{
		Watches:   []string{"test-watch-name", "test-watch-name2"},
		FailBuild: true,
		ScanResultSummary: formats.ScanResultSummary{
			ScaResults: &formats.ScaScanResultSummary{
				ScanIds:      []string{TestScaScanId},
				MoreInfoUrls: []string{TestMoreInfoUrl},
				Security: formats.ResultSummary{
					"Critical": map[string]int{jasutils.ApplicabilityUndetermined.String(): 1},
					"High":     map[string]int{jasutils.NotApplicable.String(): 1},
				},
				License: formats.ResultSummary{"High": map[string]int{jasutils.NotScanned.String(): 1}},
			},
		},
	}

	testCases := []struct {
		name                   string
		results                *Results
		includeVulnerabilities bool
		includeViolations      bool
		expected               formats.ResultsSummary
	}{
		{
			name:                   "Vulnerabilities only",
			includeVulnerabilities: true,
			results: &Results{
				ScaResults: []*ScaScanResult{{
					Target:      "target1",
					XrayResults: getDummyScaTestResults(true, true),
				}},
				ExtendedScanResults: dummyExtendedScanResults,
			},
			expected: formats.ResultsSummary{
				Scans: []formats.ScanSummary{{
					Target:          "target1",
					Vulnerabilities: expectedVulnerabilities,
				}},
			},
		},
		{
			name:              "Violations only",
			includeViolations: true,
			results: &Results{
				ScaResults: []*ScaScanResult{{
					Target:      "target1",
					XrayResults: getDummyScaTestResults(true, true),
				}},
				ExtendedScanResults: dummyExtendedScanResults,
			},
			expected: formats.ResultsSummary{
				Scans: []formats.ScanSummary{{
					Target:     "target1",
					Violations: expectedViolations,
				}},
			},
		},
		{
			name:                   "Vulnerabilities and Violations",
			includeVulnerabilities: true,
			includeViolations:      true,
			results: &Results{
				ScaResults: []*ScaScanResult{{
					Target:      "target1",
					XrayResults: getDummyScaTestResults(true, true),
				}},
				ExtendedScanResults: dummyExtendedScanResults,
			},
			expected: formats.ResultsSummary{
				Scans: []formats.ScanSummary{{
					Target:          "target1",
					Violations:      expectedViolations,
					Vulnerabilities: expectedVulnerabilities,
				}},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			summary := ToSummary(testCase.results, testCase.includeVulnerabilities, testCase.includeViolations)
			for _, scan := range summary.Scans {
				if scan.Vulnerabilities != nil {
					sort.Strings(scan.Vulnerabilities.ScaResults.ScanIds)
					sort.Strings(scan.Vulnerabilities.ScaResults.MoreInfoUrls)
				}
				if scan.Violations != nil {
					sort.Strings(scan.Violations.Watches)
					sort.Strings(scan.Violations.ScanResultSummary.ScaResults.ScanIds)
					sort.Strings(scan.Violations.ScanResultSummary.ScaResults.MoreInfoUrls)
				}
			}
			assert.Equal(t, testCase.expected, summary)
		})
	}
}

func TestGetLayerContentFromComponentId(t *testing.T) {
	testCases := []struct {
		name              string
		path              string
		expectedAlgorithm string
		expectedLayerHash string
	}{
		{
			name:              "Valid path",
			path:              "sha256__cedb364ef937c7e51179d8e514bdd98644bac5fdc82a45d784ef91afe4bc647e.tar",
			expectedAlgorithm: "sha256",
			expectedLayerHash: "cedb364ef937c7e51179d8e514bdd98644bac5fdc82a45d784ef91afe4bc647e",
		},
		{
			name: "Invalid path - not hex",
			path: "sha256__NOT_HEX.tar",
		},
		{
			name: "Invalid path - no algorithm",
			path: "_cedb364ef937c7e51179d8e514bdd98644bac5fdc82a45d784ef91afe4bc647e.tar",
		},
		{
			name: "Invalid path - no suffix",
			path: "sha256__cedb364ef937c7e51179d8e514bdd98644bac5fdc82a45d784ef91afe4bc647e",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			algorithm, layerHash := getLayerContentFromComponentId(tc.path)
			assert.Equal(t, tc.expectedAlgorithm, algorithm)
			assert.Equal(t, tc.expectedLayerHash, layerHash)
		})
	}
}

func preparePatchTestEnv(t *testing.T) (string, string, func()) {
	currentWd, err := os.Getwd()
	assert.NoError(t, err)
	wd, cleanUpTempDir := tests.CreateTempDirWithCallbackAndAssert(t)
	cleanUpWd := clientTests.ChangeDirWithCallback(t, currentWd, wd)
	// Prepare dir content
	// create dir named "DockerfileDir" in the temp dir and add a Dockerfile
	dockerfileDir := filepath.Join(wd, "DockerfileDir")
	err = fileutils.CreateDirIfNotExist(dockerfileDir)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(dockerfileDir, "Dockerfile"), []byte("Dockerfile data"), 0644)
	assert.NoError(t, err)
	err = fileutils.CreateDirIfNotExist(filepath.Join(wd, GithubBaseWorkflowDir))
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(wd, GithubBaseWorkflowDir, "workflowFile.yml"), []byte("workflowFile.yml data"), 0644)
	assert.NoError(t, err)
	return wd, dockerfileDir, func() {
		cleanUpWd()
		cleanUpTempDir()
	}
}

func TestPatchRunsToPassIngestionRules(t *testing.T) {
	wd, dockerfileDir, cleanUp := preparePatchTestEnv(t)
	defer cleanUp()

	testCases := []struct {
		name            string
		cmdResult       *Results
		subScan         SubScanType
		withEnvVars     bool
		withDockerfile  bool
		input           []*sarif.Run
		expectedResults []*sarif.Run
	}{
		{
			name:            "No runs",
			cmdResult:       &Results{ResultType: DockerImage, ScaResults: []*ScaScanResult{{Name: "dockerImage:imageVersion"}}},
			subScan:         SecretsScan,
			input:           []*sarif.Run{},
			expectedResults: []*sarif.Run{},
		},
		{
			name:      "Build scan - SCA",
			cmdResult: &Results{ResultType: Build, ScaResults: []*ScaScanResult{{Name: "buildName (buildNumber)"}}},
			subScan:   ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd, sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "file")))),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd, sarifutils.CreateDummyResultInPath(filepath.Join("dir", "file"))),
			},
		},
		{
			name:      "Docker image scan - SCA",
			cmdResult: &Results{ResultType: DockerImage, ScaResults: []*ScaScanResult{{Name: "dockerImage:imageVersion"}}},
			subScan:   ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithMessage(sarif.NewTextMessage("some-msg")),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithFingerprint("some-msg\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "some-msg", "jfrogFingerprintHash", "6e3bb67c8e688a0507f390fb1af15ce0",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256"),
					),
				),
			},
		},
		{
			name:        "Docker image scan - with env vars",
			cmdResult:   &Results{ResultType: DockerImage, ScaResults: []*ScaScanResult{{Name: "dockerImage:imageVersion"}}},
			subScan:     ScaScan,
			withEnvVars: true,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithMessage(sarif.NewTextMessage("some-msg")),
					// No location, should be removed in the output
					sarifutils.CreateDummyResult("some-markdown", "some-other-msg", "rule", "level"),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithFingerprint("some-msg\nGithub Actions Workflow: workflowFile.yml\nRun: 123\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "some-msg", "jfrogFingerprintHash", "809cc81dc7cb39b84877606faae64f83",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithPhysicalLocation(
							sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewSimpleArtifactLocation(filepath.Join(GithubBaseWorkflowDir, "workflowFile.yml"))),
						),
					),
				),
			},
		},
		{
			name:           "Docker image scan - with Dockerfile in wd",
			cmdResult:      &Results{ResultType: DockerImage, ScaResults: []*ScaScanResult{{Name: "dockerImage:imageVersion"}}},
			subScan:        ScaScan,
			withEnvVars:    true,
			withDockerfile: true,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(dockerfileDir,
					sarifutils.CreateDummyResultWithPathAndLogicalLocation("sha256__f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithMessage(sarif.NewTextMessage("some-msg")),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(dockerfileDir,
					sarifutils.CreateDummyResultWithFingerprint("some-msg\nGithub Actions Workflow: workflowFile.yml\nRun: 123\nImage: dockerImage:imageVersion\nLayer (sha256): f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "some-msg", "jfrogFingerprintHash", "d5ff6a34398ff643223c1a09b06f29c4",
						sarifutils.CreateDummyLocationWithPathAndLogicalLocation("", "f752cb05a39e65f231a3c47c2e08cbeac1c15e4daff0188cb129c12a3ea3049d", "layer", "algorithm", "sha256").WithPhysicalLocation(
							sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewSimpleArtifactLocation("Dockerfile")),
						),
					),
				),
			},
		},
		{
			name:      "Docker image scan - Secrets",
			cmdResult: &Results{ResultType: DockerImage, ScaResults: []*ScaScanResult{{Name: "dockerImage:imageVersion"}}},
			subScan:   SecretsScan,
			input: []*sarif.Run{
				sarifutils.CreateRunNameWithResults("some tool name",
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "unpacked", "filesystem", "blobs", "sha1", "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "usr", "src", "app", "server", "index.js"))),
				).WithInvocations([]*sarif.Invocation{
					sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd)),
				}),
			},
			expectedResults: []*sarif.Run{
				{
					Tool: sarif.Tool{
						Driver: sarifutils.CreateDummyDriver(patchedBinarySecretScannerToolName, "", &sarif.ReportingDescriptor{
							ID:               "rule",
							ShortDescription: sarif.NewMultiformatMessageString("[Secret in Binary found] "),
						}),
					},
					Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd))},
					Results: []*sarif.Result{
						sarifutils.CreateDummyResultWithFingerprint(fmt.Sprintf("🔒 Found Secrets in Binary docker scanning:\nImage: dockerImage:imageVersion\nLayer (sha1): 9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0\nFilepath: %s\nEvidence: snippet", filepath.Join("usr", "src", "app", "server", "index.js")), "", "jfrogFingerprintHash", "879a3a246050efbcbea370e231982539",
							sarifutils.CreateDummyLocationWithPathAndLogicalLocation(filepath.Join("usr", "src", "app", "server", "index.js"), "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "layer", "algorithm", "sha1"),
						),
					},
				},
			},
		},
		{
			name:      "Binary scan - SCA",
			cmdResult: &Results{ResultType: Binary, ScaResults: []*ScaScanResult{{Target: filepath.Join(wd, "dir", "binary")}}},
			subScan:   ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "binary"))),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultWithFingerprint("", "", "jfrogFingerprintHash", "ed4b376f7038150eb3e391b3f7114ef8", sarifutils.CreateDummyLocationInPath(filepath.Join("dir", "binary"))),
				),
			},
		},
		{
			name:      "Audit scan - SCA",
			cmdResult: &Results{ResultType: SourceCode, ScaResults: []*ScaScanResult{{Target: wd}}},
			subScan:   ScaScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath(filepath.Join(wd, "Package-Descriptor")),
					// No location, should be removed in the output
					sarifutils.CreateDummyResult("some-markdown", "some-other-msg", "rule", "level"),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath("Package-Descriptor"),
				),
			},
		},
		{
			name:      "Audit scan - Secrets",
			cmdResult: &Results{ResultType: SourceCode, ScaResults: []*ScaScanResult{{Target: wd}}},
			subScan:   SecretsScan,
			input: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath(fmt.Sprintf("file://%s", filepath.Join(wd, "dir", "file"))),
					// No location, should be removed in the output
					sarifutils.CreateDummyResult("some-markdown", "some-other-msg", "rule", "level"),
				),
			},
			expectedResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultsInWd(wd,
					sarifutils.CreateDummyResultInPath(filepath.Join("dir", "file")),
				),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.withEnvVars {
				cleanFileEnv := clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowNameEnvVar, "workflowFile.yml")
				defer cleanFileEnv()
				cleanRunNumEnv := clientTests.SetEnvWithCallbackAndAssert(t, CurrentWorkflowRunNumberEnvVar, "123")
				defer cleanRunNumEnv()
			}
			if tc.withDockerfile {
				revertWd := clientTests.ChangeDirWithCallback(t, wd, dockerfileDir)
				defer revertWd()
			}
			patchRunsToPassIngestionRules(tc.subScan, tc.cmdResult, tc.input...)
			assert.ElementsMatch(t, tc.expectedResults, tc.input)
		})
	}
}

func getDummyScaTestResults(vulnerability, violation bool) (responses []services.ScanResponse) {
	response := services.ScanResponse{}
	if vulnerability {
		response.Vulnerabilities = []services.Vulnerability{
			{IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
	}
	if violation {
		response.Violations = []services.Violation{
			{ViolationType: ViolationTypeSecurity.String(), WatchName: "test-watch-name", IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{ViolationType: ViolationTypeSecurity.String(), FailBuild: true, WatchName: "test-watch-name", IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{ViolationType: ViolationTypeLicense.String(), WatchName: "test-watch-name2", IssueId: "MIT", Severity: "High", LicenseKey: "MIT", Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
	}
	response.ScanId = TestScaScanId
	response.XrayDataUrl = TestMoreInfoUrl
	responses = append(responses, response)
	return
}
