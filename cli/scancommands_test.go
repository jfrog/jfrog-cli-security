package cli

import (
	"errors"
	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	coretests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clienttestutils "github.com/jfrog/jfrog-client-go/utils/tests"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

var TestDataDir = filepath.Join("..", "tests", "testdata")

func TestShouldRunCurationAfterFailure(t *testing.T) {
	tests := []struct {
		name                  string
		cmdName               string
		envSkipCuration       string
		envOutputDirPath      string
		originError           error
		isForbiddenOutput     bool
		isEntitledForCuration bool
		expectedRunCuration   bool
		expectedError         error
	}{
		{
			name:                "Unsupported command",
			cmdName:             "unsupported",
			envOutputDirPath:    "path",
			expectedRunCuration: false,
		},
		{
			name:                "Skip curation after failure",
			cmdName:             "install",
			envSkipCuration:     "true",
			envOutputDirPath:    "path",
			expectedRunCuration: false,
		},
		{
			name:                "Output directory path not set",
			cmdName:             "install",
			envOutputDirPath:    "",
			expectedRunCuration: false,
		},
		{
			name:                "Forbidden error",
			cmdName:             "install",
			originError:         &utils.ForbiddenError{},
			envOutputDirPath:    "path",
			expectedRunCuration: false,
		},
		{
			name:                "Forbidden error in message",
			cmdName:             "install",
			originError:         errors.New("403 Forbidden"),
			envOutputDirPath:    "path",
			expectedRunCuration: false,
		},
		{
			name:                  "Not entitled for curation",
			cmdName:               "install",
			originError:           &utils.ForbiddenError{},
			envOutputDirPath:      "path",
			isEntitledForCuration: false,
			expectedRunCuration:   false,
		},
		{
			name:                  "Successful curation audit",
			cmdName:               "install",
			originError:           &utils.ForbiddenError{},
			envOutputDirPath:      "path",
			isEntitledForCuration: true,
			expectedRunCuration:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			if tt.envSkipCuration != "" {
				callBack := clienttestutils.SetEnvWithCallbackAndAssert(t, SkipCurationAfterFailureEnv, tt.envSkipCuration)
				defer callBack()
			}
			if tt.envOutputDirPath != "" {
				callBack2 := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.SummaryOutputDirPathEnv, tt.envOutputDirPath)
				defer callBack2()
			}

			pathToProjectDir := filepath.Join(TestDataDir, "projects", "package-managers", "npm", "npm-project")

			rootDir, err := os.Getwd()
			assert.NoError(t, err)
			tempHomeDir := path.Join(rootDir, path.Join(pathToProjectDir, ".jfrog"))
			callback := clienttestutils.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempHomeDir)
			defer callback()

			serverMock, c, _ := coretests.CreateRtRestsMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.String(), "system/version") {
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte(`{"xray_version":"3.99.0"}`))
					assert.NoError(t, err)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"feature_id":"curation","entitled":` + strconv.FormatBool(tt.isEntitledForCuration) + `}`))
				assert.NoError(t, err)
			})
			defer serverMock.Close()

			configFilePath := createCliConfig(t, c.ArtifactoryUrl, pathToProjectDir)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(configFilePath))
			}()

			callbackPreTest := clienttestutils.ChangeDirWithCallback(t, rootDir, pathToProjectDir)
			defer callbackPreTest()

			_, err, runCuration := ShouldRunCurationAfterFailure(&components.Context{}, techutils.Npm, tt.cmdName, tt.originError)

			// Verify the expected behavior
			assert.Equal(t, tt.expectedRunCuration, runCuration)
			assert.Equal(t, tt.expectedError, err)

		})
	}
}

func createCliConfig(t *testing.T, url string, configPath string) string {
	server := &config.ServerDetails{
		User:           "admin",
		Password:       "password",
		Url:            url,
		ArtifactoryUrl: url,
		XrayUrl:        url,
	}
	configCmd := commonCommands.NewConfigCommand(commonCommands.AddOrEdit, "test").
		SetDetails(server).SetUseBasicAuthOnly(true).SetInteractive(false)
	assert.NoError(t, configCmd.Run())
	return filepath.Join(configPath, "jfrog-cli.conf.v"+strconv.Itoa(coreutils.GetCliConfigVersion()))
}
