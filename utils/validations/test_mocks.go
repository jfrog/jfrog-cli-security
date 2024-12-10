package validations

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory"
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"
	"github.com/stretchr/testify/assert"
)

const (
	TestMsi       = "27e175b8-e525-11ee-842b-7aa2c69b8f1f"
	TestScaScanId = "3d90ec4b-cf33-4846-6831-4bf9576f2235"

	// TestMoreInfoUrl       = "https://www.jfrog.com"
	TestPlatformUrl = "https://test-platform-url.jfrog.io/"
	TestMoreInfoUrl = "https://test-more-info-url.jfrog.io/"

	TestConfigProfileName = "default-profile"
)

var (
	versionApiUrl = "/%s/%ssystem/version"
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

	serviceManager, err := utils.CreateServiceManager(serverDetails, -1, 0, false)
	assert.NoError(t, err)
	return testServer, serverDetails, serviceManager
}

func CreateXrayRestsMockServer(testHandler restsTestHandler) (*httptest.Server, *config.ServerDetails) {
	testServer := CreateRestsMockServer(testHandler)
	serverDetails := &config.ServerDetails{Url: testServer.URL + "/", XrayUrl: testServer.URL + "/xray/"}
	return testServer, serverDetails
}

type MockServerParams struct {
	XrayVersion  string
	XscVersion   string
	XscNotExists bool
	ReturnMsi    string
}

func XscServer(t *testing.T, params MockServerParams) (*httptest.Server, *config.ServerDetails) {
	if !xscutils.IsXscXrayInnerService(params.XrayVersion) {
		serverMock, serverDetails, _ := CreateXscRestsMockServer(t, getXscServerApiHandler(t, params))
		return serverMock, serverDetails
	}
	return XrayServer(t, params)
}

func getXscServerApiHandler(t *testing.T, params MockServerParams) func(w http.ResponseWriter, r *http.Request) {
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
		if strings.Contains(r.RequestURI, "/xsc/profile_repos") && isXrayAfterXscMigration {
			assert.Equal(t, http.MethodPost, r.Method)
			w.WriteHeader(http.StatusOK)
			content, err := os.ReadFile("../../tests/testdata/other/configProfile/configProfileWithRepoExample.json")
			if !assert.NoError(t, err) {
				return
			}
			_, err = w.Write(content)
			if !assert.NoError(t, err) {
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func XrayServer(t *testing.T, params MockServerParams) (*httptest.Server, *config.ServerDetails) {
	serverMock, serverDetails := CreateXrayRestsMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == fmt.Sprintf(versionApiUrl, "api/v1/", "xray") {
			_, err := w.Write([]byte(fmt.Sprintf(`{"xray_version": "%s", "xray_revision": "xxx"}`, params.XrayVersion)))
			if !assert.NoError(t, err) {
				return
			}
		}
		if r.RequestURI == "/xray/api/v1/entitlements/feature/contextual_analysis" {
			if r.Method == http.MethodGet {
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
				w.WriteHeader(http.StatusCreated)
				_, err := w.Write([]byte(fmt.Sprintf(`{"scan_id" : "%s"}`, TestScaScanId)))
				if !assert.NoError(t, err) {
					return
				}
			}
			if r.Method == http.MethodGet {
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
		if !xscutils.IsXscXrayInnerService(params.XrayVersion) {
			return
		}
		getXscServerApiHandler(t, params)(w, r)
	})
	return serverMock, serverDetails
}
