package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractBaseGitPath(t *testing.T) {
	testCases := []struct {
		name   string
		url    string
		branch string
		want   string
	}{
		{
			name:   "HTTPS",
			url:    "https://github.com/jfrog/xray-url-canonical-e2e.git",
			branch: "main",
			want:   "github.com/jfrog/xray-url-canonical-e2e/main",
		},
		{
			name:   "HTTPS credentials and port",
			url:    "https://user:token@git.example.com:8443/jfrog/xray-url-canonical-e2e.git",
			branch: "main",
			want:   "git.example.com:8443/jfrog/xray-url-canonical-e2e/main",
		},
		{
			name:   "SCP",
			url:    "git@github.com:JFROG/xray-url-canonical-e2e.git",
			branch: "main",
			want:   "github.com/JFROG/xray-url-canonical-e2e/main",
		},
		{
			name:   "SSH with port",
			url:    "ssh://git@github.com:22/jfrog/xray-url-canonical-e2e.git",
			branch: "main",
			want:   "github.com/jfrog/xray-url-canonical-e2e/main",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := extractBaseGitPath(testCase.url, testCase.branch)
			require.NoError(t, err)
			assert.Equal(t, testCase.want, got)
		})
	}
}
