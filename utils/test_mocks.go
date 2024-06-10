package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
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
