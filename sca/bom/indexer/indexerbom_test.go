package indexer

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetIndexerEnvVars(t *testing.T) {
	tests := []struct {
		name          string
		serverDetails *config.ServerDetails
		wantKeys      map[string]string
		wantAbsent    []string
	}{
		{
			name:          "nil server details",
			serverDetails: nil,
			wantAbsent:    []string{XrayUrlEnvVariable, XrayUserEnvVariable, XrayPasswordEnvVariable, XrayTokenEnvVariable},
		},
		{
			name: "access token preferred",
			serverDetails: &config.ServerDetails{
				XrayUrl:     "https://xray.example/",
				AccessToken: "tok",
				User:        "u",
				Password:    "p",
			},
			wantKeys: map[string]string{
				XrayUrlEnvVariable:   "https://xray.example/",
				XrayTokenEnvVariable: "tok",
			},
			wantAbsent: []string{XrayUserEnvVariable, XrayPasswordEnvVariable},
		},
		{
			name: "user and password",
			serverDetails: &config.ServerDetails{
				XrayUrl:  "https://xray.example/",
				User:     "u",
				Password: "p",
			},
			wantKeys: map[string]string{
				XrayUrlEnvVariable:      "https://xray.example/",
				XrayUserEnvVariable:     "u",
				XrayPasswordEnvVariable: "p",
			},
			wantAbsent: []string{XrayTokenEnvVariable},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ibg := &IndexerBomGenerator{serverDetails: tt.serverDetails}
			env := ibg.getIndexerEnvVars()
			for k, v := range tt.wantKeys {
				assert.Equal(t, v, env[k], "key %s", k)
			}
			for _, k := range tt.wantAbsent {
				_, ok := env[k]
				assert.False(t, ok, "key %s should be absent", k)
			}
			// When server details are set, env must include process env (PATH at minimum).
			if tt.serverDetails != nil {
				require.NotEmpty(t, env["PATH"])
			}
		})
	}
}
