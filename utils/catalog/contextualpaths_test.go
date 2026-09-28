package catalog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	catalogServices "github.com/jfrog/jfrog-client-go/catalog/services"
	xrayutils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServerDetails(serverUrl string) *config.ServerDetails {
	return &config.ServerDetails{Url: serverUrl + "/"}
}

func testBom() *cyclonedx.BOM {
	return &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21"},
		},
	}
}

func TestGetIndirectCvePaths_EmptyCves_ReturnsNilWithoutError(t *testing.T) {
	result, err := GetIndirectCvePaths(newTestServerDetails("http://unused.invalid"), "", nil, testBom())

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_NilBom_ReturnsNilWithoutError(t *testing.T) {
	result, err := GetIndirectCvePaths(newTestServerDetails("http://unused.invalid"), "", []string{"CVE-2024-1234"}, nil)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_ManagerCreationFails_ReturnsWrappedError(t *testing.T) {
	serverDetails := newTestServerDetails("http://unused.invalid")
	// A client cert path that doesn't exist on disk makes the underlying HTTP client
	// creation fail deterministically, without needing a real network call.
	serverDetails.ClientCertPath = "/path/does/not/exist/cert.pem"
	serverDetails.ClientCertKeyPath = "/path/does/not/exist/key.pem"

	result, err := GetIndirectCvePaths(serverDetails, "", []string{"CVE-2024-1234"}, testBom())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create catalog service manager")
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result, err := GetIndirectCvePaths(newTestServerDetails(server.URL), "", []string{"CVE-2024-1234"}, testBom())

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_ServerReturnsMalformedJson_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	result, err := GetIndirectCvePaths(newTestServerDetails(server.URL), "", []string{"CVE-2024-1234"}, testBom())

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_Success_SendsExpectedRequestAndParsesResponse(t *testing.T) {
	var gotBody struct {
		Cves     []string                      `json:"cves"`
		Packages []xrayutils.PackageVersionKey `json:"packages"`
	}
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]catalogServices.IndirectContextualResponse{
			"CVE-2024-1234": {
				PackageVersionKey: xrayutils.PackageVersionKey{Type: "npm", Name: "lodash", Version: "4.17.21", Ecosystem: xrayutils.GenericEcosystem},
				Functions:         []string{"merge"},
			},
		})
	}))
	defer server.Close()

	result, err := GetIndirectCvePaths(newTestServerDetails(server.URL), "myproj", []string{"CVE-2024-1234"}, testBom())

	require.NoError(t, err)
	assert.Equal(t, []string{"CVE-2024-1234"}, gotBody.Cves)
	assert.Equal(t, []xrayutils.PackageVersionKey{{Type: "npm", Name: "lodash", Version: "4.17.21", Ecosystem: xrayutils.GenericEcosystem}}, gotBody.Packages)
	assert.Equal(t, "projectKey=myproj", gotQuery)
	require.Contains(t, result, "CVE-2024-1234")
	assert.Equal(t, "lodash", result["CVE-2024-1234"].Name)
	assert.Equal(t, []string{"merge"}, result["CVE-2024-1234"].Functions)
}
