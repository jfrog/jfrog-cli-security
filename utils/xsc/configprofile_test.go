package xsc

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/validations"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
)

func TestGetConfigProfile_ValidRequest_SuccessExpected(t *testing.T) {
	mockServer, serverDetails := validations.XscServer(t, services.ConfigProfileMinXscVersion)
	defer mockServer.Close()

	configProfile, err := GetConfigProfile(serverDetails, validations.TestConfigProfileName)
	assert.NoError(t, err)

	profileFileContent, err := os.ReadFile("../../tests/testdata/other/configProfile/configProfileExample.json")
	assert.NoError(t, err)

	var configProfileForComparison services.ConfigProfile
	err = json.Unmarshal(profileFileContent, &configProfileForComparison)
	assert.NoError(t, err)

	assert.Equal(t, &configProfileForComparison, configProfile)
}

func TestGetConfigProfile_TooLowXscVersion_FailureExpected(t *testing.T) {
	mockServer, serverDetails := validations.XscServer(t, "1.0.0")
	defer mockServer.Close()

	configProfile, err := GetConfigProfile(serverDetails, validations.TestConfigProfileName)
	assert.Error(t, err)
	assert.Nil(t, configProfile)
}
