package xsc

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	xscutils "github.com/jfrog/jfrog-client-go/xsc/services/utils"
	"github.com/stretchr/testify/assert"
)

func TestGetConfigProfile(t *testing.T) {
	testCases := []struct {
		name        string
		mockParams  validations.MockServerParams
		expectError bool
	}{
		{
			name:       "Deprecated service",
			mockParams: validations.MockServerParams{XrayVersion: "3.0.0", XscVersion: services.ConfigProfileMinXscVersion},
		},
		{
			name:       "Xsc as inner service in Xray",
			mockParams: validations.MockServerParams{XrayVersion: xscutils.MinXrayVersionXscTransitionToXray, XscVersion: services.ConfigProfileMinXscVersion},
		},
		{
			name:        "Expected error - Xsc version too low",
			mockParams:  validations.MockServerParams{XrayVersion: xscutils.MinXrayVersionXscTransitionToXray, XscVersion: "1.0.0"},
			expectError: true,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			mockServer, serverDetails := validations.XscServer(t, testcase.mockParams)
			defer mockServer.Close()

			configProfile, err := GetConfigProfile(testcase.mockParams.XrayVersion, testcase.mockParams.XscVersion, serverDetails, validations.TestConfigProfileName)
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
