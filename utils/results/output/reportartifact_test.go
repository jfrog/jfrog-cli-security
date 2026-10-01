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

const (
	// #nosec G101 -- dummy JWT (jfrog-client-go/auth's token2 fixture) whose subject has no "/users/" segment, so no username can be extracted // jfrog-ignore
	tokenWithNoExtractableUsername = "eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJIcnU2VHctZk1yOTV3dy12TDNjV3ZBVjJ3Qm9FSHpHdGlwUEFwOE1JdDljIn0.eyJzdWIiOiJqZnJ0QDAwMWMzZ2ZmaGcyZTh3NjE0OWUzYTJxMHc5NyIsImV4cCI6MTU1NjAzNzc2NSwiaWF0IjoxNTU2MDM0MTY1LCJqdGkiOiI1M2FlMzgyMy05NGM3LTQ0OGItOGExOC1iZGVhNDBiZjFlMjAifQ.Bp3sdvppvRxysMlLgqT48nRIHXISj9sJUCXrm7pp8evJGZW1S9hFuK1olPmcSybk2HNzdzoMcwhUmdUzAssiQkQvqd_HanRcfFbrHeg5l1fUQ397ECES-r5xK18SYtG1VR7LNTVzhJqkmRd3jzqfmIK2hKWpEgPfm8DRz3j4GGtDRxhb3oaVsT2tSSi_VfT3Ry74tzmO0GcCvmBE2oh58kUZ4QfEsalgZ8IpYHTxovsgDx_M7ujOSZx_hzpz-iy268-OkrU22PQPCfBmlbEKeEUStUO9n0pj4l1ODL31AGARyJRy46w4yzhw7Fk5P336WmDMXYs5LAX2XxPFNLvNzA"
	// #nosec G101 -- dummy JWT (jfrog-client-go/auth's token1 fixture) whose subject resolves to username "admin" // jfrog-ignore
	tokenWithUsername = "eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJIcnU2VHctZk1yOTV3dy12TDNjV3ZBVjJ3Qm9FSHpHdGlwUEFwOE1JdDljIn0.eyJzdWIiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3XC91c2Vyc1wvYWRtaW4iLCJzY3AiOiJtZW1iZXItb2YtZ3JvdXBzOnJlYWRlcnMgYXBpOioiLCJhdWQiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3IiwiaXNzIjoiamZydEAwMWMzZ2ZmaGcyZTh3NjE0OWUzYTJxMHc5NyIsImV4cCI6MTU1NjAzNzc2NSwiaWF0IjoxNTU2MDM0MTY1LCJqdGkiOiI1M2FlMzgyMy05NGM3LTQ0OGItOGExOC1iZGVhNDBiZjFlMjAifQ.Bp3sdvppvRxysMlLgqT48nRIHXISj9sJUCXrm7pp8evJGZW1S9hFuK1olPmcSybk2HNzdzoMcwhUmdUzAssiQkQvqd_HanRcfFbrHeg5l1fUQ397ECES-r5xK18SYtG1VR7LNTVzhJqkmRd3jzqfmIK2hKWpEgPfm8DRz3j4GGtDRxhb3oaVsT2tSSi_VfT3Ry74tzmO0GcCvmBE2oh58kUZ4QfEsalgZ8IpYHTxovsgDx_M7ujOSZx_hzpz-iy268-OkrU22PQPCfBmlbEKeEUStUO9n0pj4l1ODL31AGARyJRy46w4yzhw7Fk5P336WmDMXYs5LAX2XxPFNLvNzA"
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

func TestGetLocalArtifactPath(t *testing.T) {
	testCases := []struct {
		name           string
		serverDetails  *config.ServerDetails
		expectedResult string
		expectError    bool
	}{
		{
			name:          "nil server details",
			serverDetails: nil,
			expectError:   true,
		},
		{
			name:           "access token with extractable username takes priority over configured user",
			serverDetails:  &config.ServerDetails{User: "configuredUser", AccessToken: tokenWithUsername},
			expectedResult: "admin",
		},
		{
			name:           "access token without extractable username falls back to configured user",
			serverDetails:  &config.ServerDetails{User: "configuredUser", AccessToken: tokenWithNoExtractableUsername},
			expectedResult: "configuredUser",
		},
		{
			name:           "no access token falls back to configured user",
			serverDetails:  &config.ServerDetails{User: "configuredUser"},
			expectedResult: "configuredUser",
		},
		{
			name:           "no username extractable and no configured user falls back to unknown",
			serverDetails:  &config.ServerDetails{AccessToken: tokenWithNoExtractableUsername},
			expectedResult: unknownLocalArtifactPath,
		},
		{
			name:           "no access token and no configured user falls back to unknown",
			serverDetails:  &config.ServerDetails{},
			expectedResult: unknownLocalArtifactPath,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := getLocalArtifactPath(testCase.serverDetails)
			if testCase.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, result)
			assert.Equal(t, testCase.expectedResult, result)
		})
	}
}
