package packageupdaters

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFixedDescriptor(t *testing.T) {
	npm := &NpmPackageUpdater{}

	testcases := []struct {
		name            string
		originalContent string
		packageName     string
		newVersion      string
		expectedContent string
		expectError     bool
	}{
		{
			name:            "update exact version",
			originalContent: `{"dependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "update version with caret prefix - removes prefix",
			originalContent: `{"dependencies": {"lodash": "^4.17.0"}}`,
			packageName:     "lodash",
			newVersion:      "4.17.21",
			expectedContent: `{"dependencies": {"lodash": "4.17.21"}}`,
			expectError:     false,
		},
		{
			name:            "update version with tilde prefix - removes prefix",
			originalContent: `{"dependencies": {"express": "~4.18.0"}}`,
			packageName:     "express",
			newVersion:      "4.18.2",
			expectedContent: `{"dependencies": {"express": "4.18.2"}}`,
			expectError:     false,
		},
		{
			name:            "update scoped package",
			originalContent: `{"dependencies": {"@types/node": "18.0.0"}}`,
			packageName:     "@types/node",
			newVersion:      "18.11.0",
			expectedContent: `{"dependencies": {"@types/node": "18.11.0"}}`,
			expectError:     false,
		},
		{
			name:            "package not found",
			originalContent: `{"dependencies": {"lodash": "4.17.0"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: "",
			expectError:     true,
		},
		{
			name:            "update in devDependencies",
			originalContent: `{"devDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"devDependencies": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "update in optionalDependencies",
			originalContent: `{"optionalDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"optionalDependencies": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "update in overrides section",
			originalContent: `{"dependencies": {"express": "4.18.0"}, "overrides": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"express": "4.18.0"}, "overrides": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "update in both dependencies and overrides",
			originalContent: `{"dependencies": {"minimist": "1.2.5"}, "overrides": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"minimist": "1.2.6"}, "overrides": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "skip peerDependencies section - package only in peerDependencies",
			originalContent: `{"dependencies": {"express": "4.18.0"}, "peerDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: "",
			expectError:     true,
		},
		{
			name:            "skip peerDependencies section - package in both dependencies and peerDependencies",
			originalContent: `{"dependencies": {"minimist": "1.2.5"}, "peerDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"minimist": "1.2.6"}, "peerDependencies": {"minimist": "1.2.5"}}`,
			expectError:     false,
		},
		{
			name:            "update in multiple allowed sections",
			originalContent: `{"dependencies": {"minimist": "1.2.5"}, "devDependencies": {"minimist": "1.2.5"}}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: `{"dependencies": {"minimist": "1.2.6"}, "devDependencies": {"minimist": "1.2.6"}}`,
			expectError:     false,
		},
		{
			name:            "package name with dot",
			originalContent: `{"dependencies": {"vue.config": "1.0.0"}}`,
			packageName:     "vue.config",
			newVersion:      "2.0.0",
			expectedContent: `{"dependencies": {"vue.config": "2.0.0"}}`,
			expectError:     false,
		},
		{
			name:            "no dependency sections",
			originalContent: `{"name": "test", "version": "1.0.0"}`,
			packageName:     "minimist",
			newVersion:      "1.2.6",
			expectedContent: "",
			expectError:     true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := npm.GetFixedDescriptor([]byte(tc.originalContent), tc.packageName, tc.newVersion, "package.json")

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedContent, string(result))
			}
		})
	}
}

func TestEscapeJsonPathKey(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple package name",
			input:    "lodash",
			expected: "lodash",
		},
		{
			name:     "scoped package",
			input:    "@types/node",
			expected: "@types/node",
		},
		{
			name:     "package with dot",
			input:    "vue.config",
			expected: "vue\\.config",
		},
		{
			name:     "package with multiple dots",
			input:    "some.package.name",
			expected: "some\\.package\\.name",
		},
		{
			name:     "package with asterisk",
			input:    "package*name",
			expected: "package\\*name",
		},
		{
			name:     "package with question mark",
			input:    "package?name",
			expected: "package\\?name",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := EscapeJsonPathKey(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestBuildIsolatedEnv(t *testing.T) {
	testcases := []struct {
		name         string
		predefineEnv bool
	}{
		{
			name:         "sets required env vars",
			predefineEnv: false,
		},
		{
			name:         "overrides conflicting user env vars",
			predefineEnv: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.predefineEnv {
				originalCI := os.Getenv(CiEnv)
				defer func() {
					assert.NoError(t, os.Setenv(CiEnv, originalCI))
				}()
				assert.NoError(t, os.Setenv(CiEnv, "false"))
			}

			npm := &NpmPackageUpdater{}
			env := npm.BuildEnvWithOverrides(NpmInstallEnvVars)

			envMap := make(map[string]string)
			envCount := make(map[string]int)
			for _, e := range env {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) == 2 {
					envMap[parts[0]] = parts[1]
					envCount[parts[0]]++
				}
			}

			assert.Equal(t, "true", envMap[ConfigIgnoreScriptsEnv])
			assert.Equal(t, "false", envMap[ConfigAuditEnv])
			assert.Equal(t, "false", envMap[ConfigFundEnv])
			assert.Equal(t, "error", envMap[ConfigLevelEnv])
			assert.Equal(t, "true", envMap[CiEnv])

			if tc.predefineEnv {
				assert.Equal(t, 1, envCount[CiEnv], "CI should appear exactly once")
			}
		})
	}
}
