package utils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

const TestMsi = "27e175b8-e525-11ee-842b-7aa2c69b8f1f"

type restsTestHandler func(w http.ResponseWriter, r *http.Request)

// Create mock server to test REST APIs.
// testHandler - The HTTP handler of the test
func CreateRestsMockServer(testHandler restsTestHandler) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(testHandler))
}
func CreateXscRestsMockServer(t *testing.T, testHandler restsTestHandler) (*httptest.Server, *config.ServerDetails, artifactory.ArtifactoryServicesManager) {
	testServer := CreateRestsMockServer(testHandler)
	serverDetails := &config.ServerDetails{Url: testServer.URL + "/", XrayUrl: testServer.URL + "/xray/"}

	serviceManager, err := utils.CreateServiceManager(serverDetails, -1, 0, false)
	assert.NoError(t, err)
	return testServer, serverDetails, serviceManager
}

func XscServer(t *testing.T, xscVersion string) (*httptest.Server, *config.ServerDetails) {
	serverMock, serverDetails, _ := CreateXscRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/xsc/api/v1/system/version" {
			_, err := w.Write([]byte(fmt.Sprintf(`{"xsc_version": "%s"}`, xscVersion)))
			if err != nil {
				return
			}
		}
		if r.RequestURI == "/xsc/api/v1/event" {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, err := w.Write([]byte(fmt.Sprintf(`{"multi_scan_id": "%s"}`, TestMsi)))
				if err != nil {
					return
				}
			}
		}
	})
	return serverMock, serverDetails
}

func GetOutputFromFile(t *testing.T, path string) string {
	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(content), "\r\n", "\n"), "/", string(filepath.Separator)), "<"+string(filepath.Separator), "</")
}

var NoJasTestResults = &results.ScanCommandResults{
	Scans: []*results.ScanResults{{
		Target: filepath.Join("root", "dir"),
		ScaResults: []results.ScaScanResults{
			{
				Target:     "package.json",
				Technology: techutils.Npm,
				XrayResult: services.ScanResponse{
					Vulnerabilities: []services.Vulnerability{
						{
							Severity: "High",
							Cves: []services.Cve{{
								Id:          "CVE-2021-1234",
								CvssV3Score: "7.0",
							}},
							Components: map[string]services.Component{
								"gav://antparent:ant:1.6.5": services.Component{
									FixedVersions: []string{"1.6.6"},
									// ImpactPaths: ,
								},
							},
						},
					},
					Violations: []services.Violation{
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
						{
							ViolationType: "", IsEol: nil, LatestVersion: "", NewerVersions: nil, Cadence: nil, Commits: nil, Committers: nil, RiskReason: "", EolMessage: "",
						},
						{
							IsEol: NewBoolPtr(true), LatestVersion: "1.2.3", NewerVersions: NewIntPtr(5),
							Cadence: NewFloat64Ptr(3.5), Commits: NewInt64Ptr(55), Committers: NewIntPtr(10), EolMessage: "no maintainers", RiskReason: "EOL",
						},
					},
					Licenses: []services.License{
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
					},
				},
			},
		},
	}},
}

var WithJasTestResults = &results.ScanCommandResults{}

func getDummyScaTestResults(vulnerability, violation bool) (responses []services.ScanResponse) {
	response := services.ScanResponse{}
	switch {
	case vulnerability && violation:
		// Mix
		response.Vulnerabilities = []services.Vulnerability{
			{IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
		response.Violations = []services.Violation{
			{ViolationType: formats.ViolationTypeSecurity.String(), WatchName: "test-watch-name", IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
	case vulnerability:
		// only vulnerability
		response.Vulnerabilities = []services.Vulnerability{
			{IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
	case violation:
		// only violation
		response.Violations = []services.Violation{
			{ViolationType: formats.ViolationTypeSecurity.String(), WatchName: "test-watch-name", IssueId: "XRAY-1", Severity: "Critical", Cves: []services.Cve{{Id: "CVE-1"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{ViolationType: formats.ViolationTypeSecurity.String(), WatchName: "test-watch-name", IssueId: "XRAY-2", Severity: "High", Cves: []services.Cve{{Id: "CVE-2"}}, Components: map[string]services.Component{"issueId_direct_dependency": {}}},
			{ViolationType: formats.ViolationTypeLicense.String(), WatchName: "test-watch-name", IssueId: "MIT", Severity: "High", LicenseKey: "MIT", Components: map[string]services.Component{"issueId_direct_dependency": {}}},
		}
	}
	responses = append(responses, response)
	return
}

func getTestMocks() {
	// vulnerabilities := []services.Vulnerability{
	// 	{
	// 		IssueId:    "XRAY-1",
	// 		Summary:    "summary-1",
	// 		Severity:   "high",
	// 		Components: map[string]services.Component{"component-A": {}, "component-B": {}},
	// 	},
	// 	{
	// 		IssueId:    "XRAY-2",
	// 		Summary:    "summary-2",
	// 		Severity:   "low",
	// 		Components: map[string]services.Component{"component-B": {}},
	// 	},
	// }
	// expectedVulnerabilities := []formats.VulnerabilityOrViolationRow{
	// 	{
	// 		Summary: "summary-1",
	// 		IssueId: "XRAY-1",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
	// 			SeverityDetails:        formats.SeverityDetails{Severity: "high"},
	// 			ImpactedDependencyName: "component-A",
	// 		},
	// 	},
	// 	{
	// 		Summary: "summary-1",
	// 		IssueId: "XRAY-1",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
	// 			SeverityDetails:        formats.SeverityDetails{Severity: "high"},
	// 			ImpactedDependencyName: "component-B",
	// 		},
	// 	},
	// 	{
	// 		Summary: "summary-2",
	// 		IssueId: "XRAY-2",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
	// 			SeverityDetails:        formats.SeverityDetails{Severity: "low"},
	// 			ImpactedDependencyName: "component-B",
	// 		},
	// 	},
	// }

	// violations := []services.Violation{
	// 	{
	// 		IssueId:       "XRAY-1",
	// 		Summary:       "summary-1",
	// 		Severity:      "high",
	// 		WatchName:     "watch-1",
	// 		ViolationType: "security",
	// 		Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
	// 	},
	// 	{
	// 		IssueId:       "XRAY-2",
	// 		Summary:       "summary-2",
	// 		Severity:      "low",
	// 		WatchName:     "watch-1",
	// 		ViolationType: "license",
	// 		LicenseKey:    "license-1",
	// 		Components:    map[string]services.Component{"component-B": {}},
	// 	},
	// }
	// expectedSecViolations := []formats.VulnerabilityOrViolationRow{
	// 	{
	// 		Summary: "summary-1",
	// 		IssueId: "XRAY-1",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
	// 			SeverityDetails:        formats.SeverityDetails{Severity: "high"},
	// 			ImpactedDependencyName: "component-A",
	// 		},
	// 	},
	// 	{
	// 		Summary: "summary-1",
	// 		IssueId: "XRAY-1",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
	// 			SeverityDetails:        formats.SeverityDetails{Severity: "high"},
	// 			ImpactedDependencyName: "component-B",
	// 		},
	// 	},
	// }
	// expectedLicViolations := []formats.LicenseRow{
	// 	{
	// 		LicenseKey: "license-1",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
	// 			SeverityDetails:        formats.SeverityDetails{Severity: "low"},
	// 			ImpactedDependencyName: "component-B",
	// 		},
	// 	},
	// }

	// licenses := []services.License{
	// 	{
	// 		Key:        "license-1",
	// 		Name:       "license-1-name",
	// 		Components: map[string]services.Component{"component-A": {}, "component-B": {}},
	// 	},
	// 	{
	// 		Key:        "license-2",
	// 		Name:       "license-2-name",
	// 		Components: map[string]services.Component{"component-B": {}},
	// 	},
	// }
	// expectedLicenses := []formats.LicenseRow{
	// 	{
	// 		LicenseKey:                "license-1",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "component-A"},
	// 	},
	// 	{
	// 		LicenseKey:                "license-1",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "component-B"},
	// 	},
	// 	{
	// 		LicenseKey:                "license-2",
	// 		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "component-B"},
	// 	},
	// }

}
