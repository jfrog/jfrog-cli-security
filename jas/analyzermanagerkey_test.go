package jas

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
)

func TestGetAnalyzerManagerKey(t *testing.T) {
	testCases := []struct {
		name        string
		status      int
		response    string
		expectedKey []byte
	}{
		{
			name:        "First of several keys",
			status:      http.StatusOK,
			response:    `{"api_version":"1","explanation":{"XRAY-1103252":"000102030405060708090a0b0c0d0e0f\nffffffffffffffffffffffffffffffff\n"}}`,
			expectedKey: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
		{
			name:     "Keys vulnerability not published",
			status:   http.StatusOK,
			response: `{"api_version":"1"}`,
		},
		{
			name:     "Platform not entitled for contextual analysis",
			status:   http.StatusNotFound,
			response: `"Cve Applicability is not available"`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/xray/api/v1/internal/cve_applicability_input_vulnerabilities", r.URL.Path)
				assert.Equal(t, "my-project", r.URL.Query().Get("projectKey"))
				w.WriteHeader(testCase.status)
				_, err := w.Write([]byte(testCase.response))
				assert.NoError(t, err)
			}))
			defer mockServer.Close()

			key, err := getAnalyzerManagerKey(&config.ServerDetails{XrayUrl: mockServer.URL + "/xray/"}, "my-project")

			assert.Equal(t, testCase.expectedKey, key)
			assert.Equal(t, testCase.expectedKey == nil, err != nil)
		})
	}
}
