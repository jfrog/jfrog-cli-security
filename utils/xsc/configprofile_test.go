package xsc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
)

const (
	testRepoUrl = "https://github.com/jfrog/test-repository.git"
)

func TestGetConfigProfileByName(t *testing.T) {
	testCases := []struct {
		name        string
		mockParams  validations.MockServerParams
		expectError bool
	}{
		{
			name:        "Xsc as inner service in Xray - Xray version too low - invalid request",
			mockParams:  validations.MockServerParams{XrayVersion: "3.111.0"},
			expectError: true,
		},
		{
			name:       "Xsc as inner service in Xray - valid request",
			mockParams: validations.MockServerParams{XrayVersion: services.ConfigProfileNewSchemaMinXrayVersion},
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, serverDetails, _ := validations.XscServer(t, testcase.mockParams)
			defer mockServer.Close()

			configProfile, err := GetConfigProfileByName(testcase.mockParams.XrayVersion, serverDetails, validations.TestConfigProfileName, "")
			if testcase.expectError {
				assert.Error(t, err)
				assert.Nil(t, configProfile)
				return
			}
			// Validate results
			assert.NoError(t, err)
			assert.Equal(t, getComparisonConfigProfile(), configProfile)
		})
	}
}

func TestGetConfigProfileByUrl(t *testing.T) {
	testCases := []struct {
		name        string
		mockParams  validations.MockServerParams
		expectError bool
	}{
		{
			name:        "Xray version too low - error expected",
			mockParams:  validations.MockServerParams{XrayVersion: "3.108.0"},
			expectError: true,
		},
		{
			name:       "Valid request",
			mockParams: validations.MockServerParams{XrayVersion: services.ConfigProfileNewSchemaMinXrayVersion},
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, serverDetails, _ := validations.XrayServer(t, testcase.mockParams)
			defer mockServer.Close()

			configProfile, err := GetConfigProfileByUrl(testcase.mockParams.XrayVersion, serverDetails, testRepoUrl, "", "")
			if testcase.expectError {
				assert.Error(t, err)
				assert.Nil(t, configProfile)
				return
			}
			// Validate results
			assert.NoError(t, err)
			assert.Equal(t, getComparisonConfigProfile(), configProfile)
		})
	}
}

func TestGetConfigProfileByUrlAndWorkspace(t *testing.T) {
	testCases := []struct {
		name          string
		workspaceName string
	}{
		{
			name:          "Non-empty workspace is sent in request body",
			workspaceName: "my-workspace",
		},
		{
			name:          "Empty workspace is omitted from request body",
			workspaceName: "",
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			var capturedBody string
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.RequestURI, "/xsc/profile_repos") {
					assert.Equal(t, http.MethodPost, r.Method)
					body, err := io.ReadAll(r.Body)
					if !assert.NoError(t, err) {
						return
					}
					capturedBody = string(body)
					content, err := os.ReadFile("../../tests/testdata/other/configProfile/configProfileExample.json")
					if !assert.NoError(t, err) {
						return
					}
					w.WriteHeader(http.StatusOK)
					_, err = w.Write(content)
					assert.NoError(t, err)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer mockServer.Close()

			serverDetails := &config.ServerDetails{Url: mockServer.URL + "/", XrayUrl: mockServer.URL + "/xray/"}
			configProfile, err := GetConfigProfileByUrl(services.ConfigProfileNewSchemaMinXrayVersion, serverDetails, testRepoUrl, "", testcase.workspaceName)
			assert.NoError(t, err)
			assert.Equal(t, getComparisonConfigProfile(), configProfile)

			assert.Contains(t, capturedBody, `"repo_url":"`+testRepoUrl+`"`)
			if testcase.workspaceName == "" {
				assert.NotContains(t, capturedBody, "workspace_name")
			} else {
				assert.Contains(t, capturedBody, `"workspace_name":"`+testcase.workspaceName+`"`)
			}
		})
	}
}

func getComparisonConfigProfile() *services.ConfigProfile {
	return &services.ConfigProfile{
		ProfileName: "default-profile",
		GeneralConfig: services.GeneralConfig{
			ScannersDownloadPath:    "https://repo.example.com/releases",
			FailUponAnyScannerError: true,
		},
		FrogbotConfig: services.FrogbotConfig{
			AggregateFixes:                      true,
			HideSuccessBannerForNoIssues:        false,
			BranchNameTemplate:                  "frogbot-${IMPACTED_PACKAGE}-${BRANCH_NAME_HASH}",
			PrTitleTemplate:                     "[🐸 Frogbot] Upgrade {IMPACTED_PACKAGE} to {FIX_VERSION}",
			CommitMessageTemplate:               "Upgrade {IMPACTED_PACKAGE} to {FIX_VERSION}",
			ShowSecretsAsPrComment:              false,
			CreateAutoFixPr:                     true,
			IncludeVulnerabilitiesAndViolations: false,
		},
		Modules: []services.Module{
			{
				ModuleName:   "default-module",
				PathFromRoot: ".",
				ScanConfig: services.ScanConfig{
					ScaScannerConfig: services.ScaScannerConfig{
						EnableScaScan:   true,
						ExcludePatterns: []string{"**/build/**"},
					},
					ContextualAnalysisScannerConfig: services.CaScannerConfig{
						EnableCaScan:    true,
						ExcludePatterns: []string{"**/docs/**"},
					},
					SastScannerConfig: services.SastScannerConfig{
						EnableSastScan:  true,
						ExcludePatterns: []string{"**/_test.go/**"},
						ExcludeRules:    []string{"xss-injection"},
					},
					SecretsScannerConfig: services.SecretsScannerConfig{
						EnableSecretsScan:   true,
						ValidateSecrets:     true,
						ExcludePatterns:     []string{"**/_test.go/**"},
						EnableCustomSecrets: true,
					},
					IacScannerConfig: services.IacScannerConfig{
						EnableIacScan:   true,
						ExcludePatterns: []string{"*.tfstate"},
					},
				},
			},
		},
	}
}
