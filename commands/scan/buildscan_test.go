package scan

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/xray/services"
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
	expectedUrl := "http://dort.jfrog.io/"
	testCases := []struct {
		name          string
		serverDetails config.ServerDetails
	}{
		{
			name: "JFrog URL is provided",
			serverDetails: config.ServerDetails{
				Url:            "http://dort.jfrog.io/",
				ArtifactoryUrl: "http://dort.jfrog.io/artifactory",
				XrayUrl:        "http://dort.jfrog.io/xray",
			},
		},
		{
			name: "No JFrog URL",
			serverDetails: config.ServerDetails{
				ArtifactoryUrl: "http://dort.jfrog.io/artifactory",
				XrayUrl:        "http://dort.jfrog.io/xray",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualUrl, err := getActualUrl(tc.serverDetails)
			assert.NoError(t, err)
			assert.Equal(t, expectedUrl, actualUrl)
		})
	}
}

func TestBinaryGraphParamsKeepXscIds(t *testing.T) {
	cmd := &ScanCommand{
		xrayVersion: "3.120.0",
		xscVersion:  "1.16.0",
		multiScanId: "msi-from-analytics",
	}
	params := cmd.getXrayScanGraphParams().XrayGraphScanParams()
	assert.Equal(t, services.Binary, params.ScanType)
	assert.Equal(t, "1.16.0", params.XscVersion)
	assert.Equal(t, "msi-from-analytics", params.MultiScanId)
}
