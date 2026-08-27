package output

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	clientservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

func newTestServerDetails(serverUrl string) *config.ServerDetails {
	return &config.ServerDetails{XrayUrl: serverUrl + "/"}
}

func TestUploadViaXrayApi_SendsExpectedRequest(t *testing.T) {
	var gotBody clientservices.UploadScanCdxParams
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(clientservices.UploadScanCdxResponse{
			Repository: "myproj-frogbot",
			Path:       "github.com/org/repo/main/commits/source_code.cdx.json",
		})
	}))
	defer server.Close()

	path, err := uploadViaXrayApi(
		newTestServerDetails(server.URL),
		"frogbot",
		"github.com/org/repo/main/commits",
		"source_code.cdx.json",
		"myproj",
		&cdxutils.FullBOM{},
	)

	require.NoError(t, err)
	assert.Equal(t, "github.com/org/repo/main/commits/source_code.cdx.json", path)
	assert.Equal(t, "frogbot", gotBody.RepoName)
	assert.Equal(t, "source_code.cdx.json", gotBody.FileName)
	assert.Equal(t, "projectKey=myproj", gotQuery, "a project-scoped admin token needs projectKey as a URL param, same as other xsc/xray endpoints")
}

func TestUploadViaXrayApi_NoProjectKey_OmitsQueryParam(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(clientservices.UploadScanCdxResponse{Repository: "frogbot", Path: "path/file.cdx.json"})
	}))
	defer server.Close()

	_, err := uploadViaXrayApi(newTestServerDetails(server.URL), "frogbot", "path", "file.cdx.json", "", &cdxutils.FullBOM{})

	require.NoError(t, err)
	assert.Empty(t, gotQuery)
}

func TestUploadViaXrayApi_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := uploadViaXrayApi(newTestServerDetails(server.URL), "frogbot", "path", "file.cdx.json", "", &cdxutils.FullBOM{})
	assert.Error(t, err)
}
