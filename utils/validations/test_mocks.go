package validations

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
	versionApiUrl = "/%s/api/v1/system/version"
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

func XscServer(t *testing.T, xscVersion string) (*httptest.Server, *config.ServerDetails) {
	serverMock, serverDetails, _ := CreateXscRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == fmt.Sprintf(versionApiUrl, "xsc") {
			_, err := w.Write([]byte(fmt.Sprintf(`{"xsc_version": "%s"}`, xscVersion)))
			if !assert.NoError(t, err) {
				return
			}
		}
		if r.RequestURI == "/xsc/api/v1/event" {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, err := w.Write([]byte(fmt.Sprintf(`{"multi_scan_id": "%s"}`, TestMsi)))
				if !assert.NoError(t, err) {
					return
				}
			}
		}
		if r.RequestURI == "/xsc/api/v1/profile/"+TestConfigProfileName {
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
	})
	return serverMock, serverDetails
}

func XrayServer(t *testing.T, xrayVersion string) (*httptest.Server, *config.ServerDetails) {
	serverMock, serverDetails := CreateXrayRestsMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == fmt.Sprintf(versionApiUrl, "xray") {
			_, err := w.Write([]byte(fmt.Sprintf(`{"xray_version": "%s", "xray_revision": "xxx"}`, xrayVersion)))
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
		if strings.HasPrefix(r.RequestURI, "/xray/api/v1/scan/graph") {
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
	})
	return serverMock, serverDetails
}
