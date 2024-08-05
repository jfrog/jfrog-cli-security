package scan

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/stretchr/testify/assert"
)

func TestTrimUrlFunc(t *testing.T) {
	// Test empty string
	emptyUrl := ""
	url, endpoint, err := trimUrl(emptyUrl)
	assert.NoError(t, err)
	assert.True(t, url == "")
	assert.True(t, endpoint == "")

	// Test good url trim
	goodUrl := "http://dort.jfrog.io/xray/random/api"
	url, endpoint, err = trimUrl(goodUrl)
	assert.NoError(t, err)
	assert.True(t, url == "http://dort.jfrog.io/")
	assert.True(t, endpoint == "xray/random/api")

	// Test bad url
	badUrl := "http://dort.jfrog io/xray/random/api"
	_, _, err = trimUrl(badUrl)
	assert.NotNil(t, err)
}

func TestGetActualUrl(t *testing.T) {
	buildScanCommand := NewBuildScanCommand()
	testServerDetails := &config.ServerDetails{
		Url:            "http://dort.jfrog.io/",
		ArtifactoryUrl: "http://dort.jfrog.io/artifactory",
		XrayUrl:        "http://dort.jfrog.io/xray",
	}

	// test when JFrog URL is provided
	buildScanCommand.SetServerDetails(testServerDetails)
	expectedUrl := "http://dort.jfrog.io/"
	actualUrl, err := getActualUrl(*buildScanCommand.serverDetails)
	assert.NoError(t, err)
	assert.Equal(t, expectedUrl, actualUrl)

	// test when only Artifactory URL and Xray URL are provided and URL is empty
	buildScanCommand.serverDetails.Url = ""
	actualUrl, err = getActualUrl(*buildScanCommand.serverDetails)
	assert.NoError(t, err)
	assert.Equal(t, expectedUrl, actualUrl)
}
