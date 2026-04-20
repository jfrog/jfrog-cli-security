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

func TestEffectiveBuildScanIncludeViolations(t *testing.T) {
	tests := []struct {
		name            string
		violationsFlag  bool
		projectProvided bool
		want            bool
	}{
		{"default path: flag true, no project", true, false, true},
		{"flag false, no project", false, false, false},
		{"flag false, project overrides", false, true, true},
		{"flag true, project", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, EffectiveBuildScanIncludeViolations(tt.violationsFlag, tt.projectProvided))
		})
	}
}
