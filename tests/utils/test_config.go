package utils

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	configTests "github.com/jfrog/jfrog-cli-security/tests"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/repository"
	artifactoryUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	commonTests "github.com/jfrog/jfrog-cli-core/v2/common/tests"
	"github.com/jfrog/jfrog-cli-core/v2/plugins"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	rtutils "github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/http/httpclient"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
)

func CreateJfrogHomeConfig(t *testing.T, encryptPassword bool) {
	wd, err := os.Getwd()
	assert.NoError(t, err, "Failed to get current dir")
	clientTests.SetEnvAndAssert(t, coreutils.HomeDir, filepath.Join(wd, configTests.Out, "jfroghome"))

	// Delete the default server if exist
	config, err := commonCommands.GetConfig("default", false)
	if err == nil && config.ServerId != "" {
		err = commonCommands.NewConfigCommand(commonCommands.Delete, "default").Run()
		assert.NoError(t, err)
	}
	*configTests.JfrogUrl = clientUtils.AddTrailingSlashIfNeeded(*configTests.JfrogUrl)
	err = commonCommands.NewConfigCommand(commonCommands.AddOrEdit, "default").SetDetails(configTests.XrDetails).SetInteractive(false).SetEncPassword(encryptPassword).Run()
	assert.NoError(t, err)
}

func InitTestCliDetails(testApplication components.App) {
	configTests.TestApplication = &testApplication
	if configTests.PlatformCli == nil {
		configTests.PlatformCli = GetTestCli(testApplication, false)
	}
}

func GetTestCli(testApplication components.App, xrayUrlOnly bool) (testCli *coreTests.JfrogCli) {
	creds := authenticateXray(xrayUrlOnly)
	return coreTests.NewJfrogCli(func() error { return plugins.RunCliWithPlugin(testApplication)() }, "", creds)
}

func authenticateXray(xrayUrlOnly bool) string {
	*configTests.JfrogUrl = clientUtils.AddTrailingSlashIfNeeded(*configTests.JfrogUrl)
	cred := fmt.Sprintf("--url=%s", *configTests.JfrogUrl)
	if xrayUrlOnly {
		cred = fmt.Sprintf("--xray-url=%s", configTests.XrDetails.XrayUrl)
		configTests.XrDetails = &config.ServerDetails{XrayUrl: *configTests.JfrogUrl + configTests.XrayEndpoint}
	} else {
		configTests.XrDetails = &config.ServerDetails{Url: *configTests.JfrogUrl, ArtifactoryUrl: *configTests.JfrogUrl + configTests.ArtifactoryEndpoint, XrayUrl: *configTests.JfrogUrl + configTests.XrayEndpoint}
	}
	if *configTests.JfrogAccessToken != "" {
		configTests.XrDetails.AccessToken = *configTests.JfrogAccessToken
		cred += fmt.Sprintf(" --access-token=%s", configTests.XrDetails.AccessToken)
	} else {
		configTests.XrDetails.User = *configTests.JfrogUser
		configTests.XrDetails.Password = *configTests.JfrogPassword
		cred += fmt.Sprintf(" --user=%s --password=%s", configTests.XrDetails.User, configTests.XrDetails.Password)
	}

	var err error
	if configTests.XrAuth, err = configTests.XrDetails.CreateXrayAuthConfig(); err != nil {
		coreutils.ExitOnErr(errors.New("Failed while attempting to authenticate with Xray: " + err.Error()))
	}
	configTests.XrDetails.XrayUrl = configTests.XrAuth.GetUrl()
	return cred
}

func AuthenticateXsc() string {
	*configTests.JfrogUrl = clientUtils.AddTrailingSlashIfNeeded(*configTests.JfrogUrl)
	configTests.XscDetails = &config.ServerDetails{Url: *configTests.JfrogUrl, ArtifactoryUrl: *configTests.JfrogUrl + configTests.ArtifactoryEndpoint, XrayUrl: *configTests.JfrogUrl + configTests.XrayEndpoint, XscUrl: *configTests.JfrogUrl + configTests.XscEndpoint}
	cred := fmt.Sprintf("--url=%s", configTests.XscDetails.XrayUrl)
	if *configTests.JfrogAccessToken != "" {

		configTests.XscDetails.AccessToken = *configTests.JfrogAccessToken
		cred += fmt.Sprintf(" --access-token=%s", configTests.XscDetails.AccessToken)
	} else {
		configTests.XscDetails.User = *configTests.JfrogUser
		configTests.XscDetails.Password = *configTests.JfrogPassword
		cred += fmt.Sprintf(" --user=%s --password=%s", configTests.XscDetails.User, configTests.XscDetails.Password)
	}

	var err error
	if configTests.XscAuth, err = configTests.XscDetails.CreateXscAuthConfig(); err != nil {
		coreutils.ExitOnErr(errors.New("Failed while attempting to authenticate with Xsc: " + err.Error()))
	}
	configTests.XscDetails.XscUrl = configTests.XscAuth.GetUrl()
	return cred
}

func AuthenticateArtifactory() string {
	*configTests.JfrogUrl = clientUtils.AddTrailingSlashIfNeeded(*configTests.JfrogUrl)
	configTests.RtDetails = &config.ServerDetails{Url: *configTests.JfrogUrl, ArtifactoryUrl: *configTests.JfrogUrl + configTests.ArtifactoryEndpoint, SshKeyPath: *configTests.JfrogSshKeyPath, SshPassphrase: *configTests.JfrogSshPassphrase}

	if !fileutils.IsSshUrl(configTests.RtDetails.ArtifactoryUrl) {
		if *configTests.JfrogAccessToken != "" {
			configTests.RtDetails.AccessToken = *configTests.JfrogAccessToken
		} else {
			configTests.RtDetails.User = *configTests.JfrogUser
			configTests.RtDetails.Password = *configTests.JfrogPassword
		}
	}
	cred := getArtifactoryTestCredentials()
	var err error
	if configTests.RtAuth, err = configTests.RtDetails.CreateArtAuthConfig(); err != nil {
		coreutils.ExitOnErr(errors.New("Failed while attempting to authenticate with Artifactory: " + err.Error()))
	}
	configTests.RtDetails.ArtifactoryUrl = configTests.RtAuth.GetUrl()
	configTests.RtDetails.SshUrl = configTests.RtAuth.GetSshUrl()
	configTests.RtDetails.AccessUrl = clientUtils.AddTrailingSlashIfNeeded(*configTests.JfrogUrl) + configTests.AccessEndpoint
	configTests.RtHttpDetails = configTests.RtAuth.CreateHttpClientDetails()
	return cred
}

func getArtifactoryTestCredentials() string {
	creds := "--url=" + configTests.RtDetails.ArtifactoryUrl

	if fileutils.IsSshUrl(configTests.RtDetails.ArtifactoryUrl) {
		return creds + getSshCredentials()
	}
	if *configTests.JfrogAccessToken != "" {
		return creds + " --access-token=" + *configTests.JfrogAccessToken
	}
	return creds + " --user=" + *configTests.JfrogUser + " --password=" + *configTests.JfrogPassword
}

func getSshCredentials() string {
	cred := ""
	if *configTests.JfrogSshKeyPath != "" {
		cred += " --ssh-key-path=" + *configTests.JfrogSshKeyPath
	}
	if *configTests.JfrogSshPassphrase != "" {
		cred += " --ssh-passphrase=" + *configTests.JfrogSshPassphrase
	}
	return cred
}

func GetAllRepositoriesNames() []string {
	var baseRepoNames []string
	for repoName := range configTests.GetNonVirtualRepositories() {
		baseRepoNames = append(baseRepoNames, *repoName)
	}
	for repoName := range configTests.GetVirtualRepositories() {
		baseRepoNames = append(baseRepoNames, *repoName)
	}
	return baseRepoNames
}

func CreateRequiredRepositories() {
	// Clean up old repositories
	coreTests.CleanUpOldItems(GetAllRepositoriesNames(), getAllRepos, ExecDeleteRepo)
	// Create repositories unique names
	configTests.AddTimestampToGlobalVars()
	// Create repositories
	configTests.CreatedNonVirtualRepositories = configTests.GetNonVirtualRepositories()
	CreateRepos(configTests.CreatedNonVirtualRepositories)
	configTests.CreatedVirtualRepositories = configTests.GetVirtualRepositories()
	CreateRepos(configTests.CreatedVirtualRepositories)
}

func getAllRepos() (repositoryKeys []string, err error) {
	servicesManager, err := artifactoryUtils.CreateServiceManager(configTests.RtDetails, -1, 0, false)
	if err != nil {
		return nil, err
	}
	repos, err := servicesManager.GetAllRepositories()
	if err != nil {
		return nil, err
	}
	for _, repo := range *repos {
		repositoryKeys = append(repositoryKeys, repo.Key)
	}
	return
}

func ExecDeleteRepo(repoName string) {
	err := commonCommands.Exec(repository.NewRepoDeleteCommand().SetRepoPattern(repoName).SetServerDetails(configTests.RtDetails).SetQuiet(true))
	if err != nil {
		log.Error("Couldn't delete repository", repoName, ":", err.Error())
	}
}

func execCreateRepoRest(repoConfig, repoName string) {
	output, err := os.ReadFile(repoConfig)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	rtutils.AddHeader("Content-Type", "application/json", &configTests.RtHttpDetails.Headers)
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	resp, body, err := client.SendPut(configTests.RtDetails.ArtifactoryUrl+"api/repositories/"+repoName, output, configTests.RtHttpDetails, "")
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK, http.StatusCreated); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	log.Info("Repository", repoName, "created.")
}

func isRepoExist(repoName string) bool {
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	resp, _, _, err := client.SendGet(configTests.RtDetails.ArtifactoryUrl+configTests.RepoDetailsEndpoint+repoName, true, configTests.RtHttpDetails, "")
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusBadRequest {
		return true
	}
	return false
}

func DeleteRepos(repos map[*string]string) {
	for repoName := range repos {
		if isRepoExist(*repoName) {
			ExecDeleteRepo(*repoName)
		}
	}
}

func CreateRepos(repos map[*string]string) {
	for repoName, configFile := range repos {
		if !isRepoExist(*repoName) {
			repoConfig := GetTestResourcesPath() + "artifactory-repo-configs/" + configFile
			repoConfig, err := commonTests.ReplaceTemplateVariables(repoConfig, "", configTests.GetSubstitutionMap())
			if err != nil {
				log.Error(err)
				os.Exit(1)
			}
			execCreateRepoRest(repoConfig, *repoName)
		}
	}
}
