package xsc

import (
	"encoding/json"
	"os"
	"testing"

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
			mockServer, serverDetails := validations.XscServer(t, testcase.mockParams)
			defer mockServer.Close()

			configProfile, err := GetConfigProfileByName(testcase.mockParams.XrayVersion, serverDetails, validations.TestConfigProfileName)
			if testcase.expectError {
				assert.Error(t, err)
				assert.Nil(t, configProfile)
				return
			}
			// Validate results
			assert.NoError(t, err)

			profileFileContent, err := os.ReadFile("../../tests/testdata/other/configProfile/configProfileExample.json")
			assert.NoError(t, err)

			var configProfileForComparison services.ConfigProfile
			err = json.Unmarshal(profileFileContent, &configProfileForComparison)
			assert.NoError(t, err)

			assert.Equal(t, &configProfileForComparison, configProfile)
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
			mockParams: validations.MockServerParams{XrayVersion: services.ConfigProfileByUrlMinXrayVersion},
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, serverDetails, _ := validations.XrayServer(t, testcase.mockParams)
			defer mockServer.Close()

			configProfile, err := GetConfigProfileByUrl(testcase.mockParams.XrayVersion, serverDetails, testRepoUrl)
			if testcase.expectError {
				assert.Error(t, err)
				assert.Nil(t, configProfile)
				return
			}
			// Validate results
			assert.NoError(t, err)

			profileFileContent, err := os.ReadFile("../../tests/testdata/other/configProfile/configProfileExample.json")
			assert.NoError(t, err)

			var configProfileForComparison services.ConfigProfile
			err = json.Unmarshal(profileFileContent, &configProfileForComparison)
			assert.NoError(t, err)

			assert.Equal(t, &configProfileForComparison, configProfile)
		})
	}
}
