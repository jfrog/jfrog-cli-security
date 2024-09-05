package xsc

import (
	"encoding/json"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGetConfigProfile_ValidRequest_SuccessExpected(t *testing.T) {
	mockServer, serverDetails := utils.XscServer(t, services.ConfigProfileMinXscVersion)
	defer mockServer.Close()

	configProfile, err := GetConfigProfile(serverDetails, utils.TestConfigProfileName)
	assert.NoError(t, err)

	profileFileContent, err := os.ReadFile("../../tests/testdata/other/configProfile/configProfileExample.json")
	assert.NoError(t, err)

	var configProfileForComparison services.ConfigProfile
	err = json.Unmarshal(profileFileContent, &configProfileForComparison)
	assert.NoError(t, err)

	assert.Equal(t, &configProfileForComparison, configProfile)
}

func TestGetConfigProfile_TooLowXscVersion_FailureExpected(t *testing.T) {
	mockServer, serverDetails := utils.XscServer(t, "1.0.0")
	defer mockServer.Close()

	configProfile, err := GetConfigProfile(serverDetails, utils.TestConfigProfileName)
	assert.Error(t, err)
	assert.Nil(t, configProfile)
}
