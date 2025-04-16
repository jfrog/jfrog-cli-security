package validations

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	coreutils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayutils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

const (
	TestMsi       = "27e175b8-e525-11ee-842b-7aa2c69b8f1f"
	TestScaScanId = "3d90ec4b-cf33-4846-6831-4bf9576f2235"

	TestPlatformUrl = "https://test-platform-url.jfrog.io/"
	TestMoreInfoUrl = "https://test-more-info-url.jfrog.io/"

	TestConfigProfileName = "default-profile"

	VersionApi        = "version"
	EntitlementsApi   = "entitlements"
	GraphScanPostAPI  = "graphScan_post"
	GraphScanGetAPI   = "graphScan_get"
	ConfigProfileAPI  = "config_profile"
	WatchResourcesAPI = "watch_resources"
)

var (
	versionApiUrl = "/%s/%ssystem/version"

	TestMockGitInfo = xscservices.XscGitInfoContext{
		Source: xscservices.CommitContext{
			GitRepoHttpsCloneUrl: "https://github.com/jfrog/dummy-repo.git",
			GitRepoName:          "dummy-repo",
			GitProject:           "jfrog",
			BranchName:           "dev",
			CommitHash:           "4be861f9a585d8ae5dde0b9550669972ee05c9d7",
		},
		GitProvider: "github",
	}
)

type restsTestHandler func(w http.ResponseWriter, r *http.Request)

// Create mock server to test REST APIs.
// testHandler - The HTTP handler of the test
func CreateRestsMockServer(testHandler restsTestHandler) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(testHandler))
}
func CreateXscRestsMockServer(t *testing.T, testHandler restsTestHandler) (*httptest.Server, *config.ServerDetails, artifactory.ArtifactoryServicesManager) {
	testServer := CreateRestsMockServer(testHandler)
	serverDetails := &config.ServerDetails{Url: testServer.URL + "/", XrayUrl: testServer.URL + "/xray/"}

	serviceManager, err := coreutils.CreateServiceManager(serverDetails, -1, 0, false)
	assert.NoError(t, err)
	return testServer, serverDetails, serviceManager
}

func CreateXrayRestsMockServer(testHandler restsTestHandler) (*httptest.Server, *config.ServerDetails) {
	testServer := CreateRestsMockServer(testHandler)
	serverDetails := &config.ServerDetails{Url: testServer.URL + "/", XrayUrl: testServer.URL + "/xray/"}
	return testServer, serverDetails
}

type MockServerParams struct {
	// General params to mock Xray and Xsc (backward compatible and inner service based on the following params)
	XrayVersion  string
	XscVersion   string
	XscNotExists bool
	// Xsc/Event Api
	ReturnMsi string
	// Xsc/Watch/Resource Api
	ReturnMockPlatformWatches xrayutils.ResourcesWatchesBody
	ApiCallCounts             map[string]int
}

// Mock Only Xsc server API (backward compatible)
func XscServer(t *testing.T, params MockServerParams) (*httptest.Server, *config.ServerDetails) {
	if !xscutils.IsXscXrayInnerService(params.XrayVersion) {
		serverMock, serverDetails, _ := CreateXscRestsMockServer(t, getXscServerApiHandler(t, &params))
		return serverMock, serverDetails
	}
	return XrayServer(t, &params)
}

func getXscServerApiHandler(t *testing.T, params *MockServerParams) func(w http.ResponseWriter, r *http.Request) {
	apiUrlPart := "api/v1/"
	var isXrayAfterXscMigration bool
	if isXrayAfterXscMigration = xscutils.IsXscXrayInnerService(params.XrayVersion); isXrayAfterXscMigration {
		apiUrlPart = ""
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if params.XscNotExists {
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte("Xsc service is not enabled"))
			assert.NoError(t, err)
			return
		}

		if r.RequestURI == fmt.Sprintf(versionApiUrl, apiUrlPart, "xsc") {
			_, err := w.Write([]byte(fmt.Sprintf(`{"xsc_version": "%s"}`, params.XscVersion)))
			if !assert.NoError(t, err) {
				return
			}
		}
		if strings.Contains(r.RequestURI, "/xsc/"+apiUrlPart+"event") {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				if params.ReturnMsi == "" {
					params.ReturnMsi = TestMsi
				}
				_, err := w.Write([]byte(fmt.Sprintf(`{"multi_scan_id": "%s"}`, params.ReturnMsi)))
				if !assert.NoError(t, err) {
					return
				}
			}
		}
		if strings.Contains(r.RequestURI, "/xsc/"+apiUrlPart+"profile/"+TestConfigProfileName) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				content, err := os.ReadFile("../../tests/testdata/other/configProfile/configProfileExample.json")
				if !assert.NoError(t, err) {
					return
				}
				_, err = w.Write(content)
				if !assert.NoError(t, err) {
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

// Mock Xray server (with Xsc inner service if supported based on version - not backward compatible to XSC API)
func XrayServer(t *testing.T, params *MockServerParams) (*httptest.Server, *config.ServerDetails) {
	serverMock, serverDetails := CreateXrayRestsMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == fmt.Sprintf(versionApiUrl, "api/v1/", "xray") {
			params.ApiCallCounts[VersionApi]++
			_, err := w.Write([]byte(fmt.Sprintf(`{"xray_version": "%s", "xray_revision": "xxx"}`, params.XrayVersion)))
			if !assert.NoError(t, err) {
				return
			}
		}
		if r.RequestURI == "/xray/api/v1/entitlements/feature/contextual_analysis" {
			if r.Method == http.MethodGet {
				params.ApiCallCounts[EntitlementsApi]++
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"entitled": true, "feature_id": "contextual_analysis"}`))
				if !assert.NoError(t, err) {
					return
				}
			}
		}
		// Scan graph with Xray or Xsc
		if strings.Contains(r.RequestURI, "/scan/graph") {
			if r.Method == http.MethodPost {
				params.ApiCallCounts[GraphScanPostAPI]++
				w.WriteHeader(http.StatusCreated)
				_, err := w.Write([]byte(fmt.Sprintf(`{"scan_id" : "%s"}`, TestScaScanId)))
				if !assert.NoError(t, err) {
					return
				}
			}
			if r.Method == http.MethodGet {
				params.ApiCallCounts[GraphScanGetAPI]++
				w.WriteHeader(http.StatusOK)
				content, err := os.ReadFile("../../tests/testdata/other/graphScanResults/graphScanResult.txt")
				if !assert.NoError(t, err) {
					return
				}
				_, err = w.Write(content)
				if !assert.NoError(t, err) {
					return
				}
			}
		}

		isXrayAfterXscMigration := xscutils.IsXscXrayInnerService(params.XrayVersion)
		if strings.Contains(r.RequestURI, "/xsc/profile_repos") && isXrayAfterXscMigration {
			params.ApiCallCounts[ConfigProfileAPI]++
			assert.Equal(t, http.MethodPost, r.Method)
			w.WriteHeader(http.StatusOK)
			content, err := os.ReadFile("../../tests/testdata/other/configProfile/configProfileExample.json")
			if !assert.NoError(t, err) {
				return
			}
			_, err = w.Write(content)
			if !assert.NoError(t, err) {
				return
			}
		}

		if !isXrayAfterXscMigration {
			return
		}
		// Get defined active watches only supported after xsc was inner service
		if strings.Contains(r.RequestURI, "/api/v1/xsc/watches/resource") {
			params.ApiCallCounts[WatchResourcesAPI]++
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				content, err := utils.GetAsJsonBytes(params.ReturnMockPlatformWatches, false, false)
				if !assert.NoError(t, err) {
					return
				}
				_, err = w.Write(content)
				if !assert.NoError(t, err) {
					return
				}
			}
		}
		getXscServerApiHandler(t, params)(w, r)
	})
	return serverMock, serverDetails
}

func NewMockJasRuns(runs ...*sarif.Run) []results.ScanResult[[]*sarif.Run] {
	return []results.ScanResult[[]*sarif.Run]{{Scan: runs}}
}

func NewMockScaResults(responses ...services.ScanResponse) (converted []results.ScanResult[services.ScanResponse]) {
	for _, response := range responses {
		status := 0
		if response.ScannedStatus == "Failed" {
			status = 1
		}
		converted = append(converted, results.ScanResult[services.ScanResponse]{Scan: response, StatusCode: status})
	}
	return
}

func CreateDummyApplicabilityRule(cve string, applicableStatus jasutils.ApplicabilityStatus) *sarif.ReportingDescriptor {
	return &sarif.ReportingDescriptor{
		ID:               fmt.Sprintf("applic_%s", cve),
		Name:             &cve,
		ShortDescription: sarif.NewMultiformatMessageString(fmt.Sprintf("Scanner for %s", cve)),
		FullDescription:  sarif.NewMultiformatMessageString(fmt.Sprintf("The Scanner checks for %s", cve)),
		Properties:       map[string]interface{}{"applicability": applicableStatus.String()},
	}
}

func CreateDummyApplicableResults(cve string, location formats.Location) *sarif.Result {
	return &sarif.Result{
		Message: *sarif.NewTextMessage("ca msg"),
		RuleID:  utils.NewStrPtr(fmt.Sprintf("applic_%s", cve)),
		Locations: []*sarif.Location{
			sarifutils.CreateLocation(location.File, location.StartLine, location.StartColumn, location.EndLine, location.EndColumn, location.Snippet),
		},
	}
}

func CreateDummyJasRule(id string, cwe ...string) *sarif.ReportingDescriptor {
	descriptor := &sarif.ReportingDescriptor{
		ID:               id,
		Name:             &id,
		ShortDescription: sarif.NewMultiformatMessageString(fmt.Sprintf("Scanner for %s", id)).WithMarkdown(fmt.Sprintf("Scanner for %s", id)),
		FullDescription:  sarif.NewMultiformatMessageString(fmt.Sprintf("The Scanner checks for %s", id)).WithMarkdown(fmt.Sprintf("The Scanner checks for %s", id)),
	}
	if len(cwe) > 0 {
		descriptor.DefaultConfiguration = &sarif.ReportingConfiguration{
			Parameters: &sarif.PropertyBag{
				Properties: map[string]interface{}{"CWE": strings.Join(cwe, ",")},
			},
		}
	}
	return descriptor
}

func CreateDummySecretResult(id string, status jasutils.TokenValidationStatus, metadata string, location formats.Location) *sarif.Result {
	return &sarif.Result{
		Message: *sarif.NewTextMessage(fmt.Sprintf("Secret %s were found", id)),
		RuleID:  utils.NewStrPtr(id),
		Level:   utils.NewStrPtr(severityutils.LevelInfo.String()),
		Locations: []*sarif.Location{
			sarifutils.CreateLocation(location.File, location.StartLine, location.StartColumn, location.EndLine, location.EndColumn, location.Snippet),
		},
		PropertyBag: sarif.PropertyBag{
			Properties: map[string]interface{}{"tokenValidation": status.String(), "metadata": metadata},
		},
	}
}

func CreateDummySecretViolationResult(id string, status jasutils.TokenValidationStatus, metadata, watch, issueId string, policies []string, location formats.Location) *sarif.Result {
	result := CreateDummySecretResult(id, status, metadata, location)
	result.PropertyBag.Properties[sarifutils.WatchSarifPropertyKey] = watch
	result.PropertyBag.Properties[sarifutils.JasIssueIdSarifPropertyKey] = issueId
	result.PropertyBag.Properties[sarifutils.PoliciesSarifPropertyKey] = policies
	return result
}

func CreateDummyJasResult(id string, level severityutils.SarifSeverityLevel, location formats.Location, codeFlows ...[]formats.Location) *sarif.Result {
	result := &sarif.Result{
		Message: *sarif.NewTextMessage(fmt.Sprintf("Vulnerability %s were found", id)),
		RuleID:  utils.NewStrPtr(id),
		Level:   utils.NewStrPtr(level.String()),
		Locations: []*sarif.Location{
			sarifutils.CreateLocation(location.File, location.StartLine, location.StartColumn, location.EndLine, location.EndColumn, location.Snippet),
		},
		PropertyBag: sarif.PropertyBag{Properties: map[string]interface{}{}},
	}
	for _, codeFlow := range codeFlows {
		flows := []*sarif.Location{}
		for _, location := range codeFlow {
			flows = append(flows, sarifutils.CreateLocation(location.File, location.StartLine, location.StartColumn, location.EndLine, location.EndColumn, location.Snippet))
		}
		result.CodeFlows = append(result.CodeFlows, sarifutils.CreateCodeFlow(sarifutils.CreateThreadFlow(flows...)))
	}
	return result
}

func CreateDummySastViolationResult(id string, level severityutils.SarifSeverityLevel, watch, issueId string, policies []string, location formats.Location, codeFlows ...[]formats.Location) *sarif.Result {
	result := CreateDummyJasResult(id, level, location, codeFlows...)
	result.PropertyBag.Properties[sarifutils.WatchSarifPropertyKey] = watch
	result.PropertyBag.Properties[sarifutils.JasIssueIdSarifPropertyKey] = issueId
	result.PropertyBag.Properties[sarifutils.PoliciesSarifPropertyKey] = policies
	return result
}
