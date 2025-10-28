package integration

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/cli"
	configTests "github.com/jfrog/jfrog-cli-security/tests"
	testUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"

	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/repository"
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

func getSkipTestMsg(testName, testFlag string) string {
	return fmt.Sprintf("Skipping %s tests. To run them, add the '%s=true' option or don't supply any options.", testName, testFlag)
}

func InitUnitTest(t *testing.T) {
	if !*configTests.TestUnit {
		t.Skip(getSkipTestMsg("Unit", "--test.unit"))
	}
}

func InitArtifactoryTest(t *testing.T) {
	if !*configTests.TestArtifactory {
		t.Skip(getSkipTestMsg("Artifactory integration", "--test.artifactory"))
	}
}

func InitXrayTest(t *testing.T, minVersion string) {
	if !*configTests.TestXray {
		t.Skip(getSkipTestMsg("Xray commands", "--test.xray"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func GetTestServerDetails() *config.ServerDetails {
	return configTests.RtDetails
}

func InitXscTest(t *testing.T, validations ...func()) (string, string, func()) {
	if !*configTests.TestXsc {
		t.Skip(getSkipTestMsg("XSC integration", "--test.xsc"))
	}
	xrayVersion, xscVersion, err := getXrayAndXscTestVersions(t)
	if err != nil {
		t.Skip("Skipping XSC integration tests. XSC is not enabled at the given server.")
	}
	for _, validation := range validations {
		validation()
	}
	cleanUp := PrepareXscForTest(t)
	return xrayVersion, xscVersion, cleanUp
}

func PrepareXscForTest(t *testing.T) func() {
	// Make sure the request will work with xsc and not xray
	assert.NoError(t, os.Setenv(coreutils.ReportUsage, "true"))
	return func() {
		assert.NoError(t, os.Setenv(coreutils.ReportUsage, "false"))
	}
}

func getXrayAndXscTestVersions(t *testing.T) (string, string, error) {
	xrayVersion, err := testUtils.GetTestsXrayVersion()
	assert.NoError(t, err)
	xscService, err := xsc.CreateXscServiceBackwardCompatible(xrayVersion.GetVersion(), configTests.XscDetails)
	assert.NoError(t, err)
	xscVersion, err := xscService.GetVersion()
	return xrayVersion.GetVersion(), xscVersion, err
}

func InitAuditGeneralTests(t *testing.T, minVersion string) {
	if !*configTests.TestAuditGeneral {
		t.Skip(getSkipTestMsg("Audit command general integration", "--test.audit"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditNewScaTests(t *testing.T, minVersion string) {
	if !*configTests.TestAuditNewSca {
		t.Skip(getSkipTestMsg("Audit command new SCA integration", "--test.audit.NewSca"))
	}
	testUtils.SkipTestIfDurationNotPassed(t, "22-10-2025", 14, "Catalog API not available yet in test platform.")
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditJasTest(t *testing.T, minVersion string) {
	if !*configTests.TestAuditJas {
		t.Skip(getSkipTestMsg("Audit command JFrog Artifactory Security integration", "--test.audit.Jas"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditJavaScriptTest(t *testing.T, minVersion string) {
	if !*configTests.TestAuditJavaScript {
		t.Skip(getSkipTestMsg("Audit command JavaScript technologies (Npm, Pnpm, Yarn) integration", "--test.audit.JavaScript"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditJavaTest(t *testing.T, minVersion string) {
	if !*configTests.TestAuditJava {
		t.Skip(getSkipTestMsg("Audit command Java technologies (Maven, Gradle) integration", "--test.audit.Java"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditCTest(t *testing.T, minVersion string) {
	if !*configTests.TestAuditCTypes {
		t.Skip(getSkipTestMsg("Audit command C/C++/C# technologies (Nuget/DotNet, Conan) integration", "--test.audit.C"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditGoTest(t *testing.T, minVersion string) {
	if !*configTests.TestAuditGo {
		t.Skip(getSkipTestMsg("Audit command Go technologies (GoLang) integration", "--test.audit.Go"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditCocoapodsTest(t *testing.T, minVersion string) {
	if !*configTests.TestAuditCocoapods {
		t.Skip(getSkipTestMsg("Audit command Cocoapods technologies integration", "--test.audit.Cocoapods"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditSwiftTest(t *testing.T, minVersion string) {
	if !*configTests.TestAuditSwift {
		t.Skip(getSkipTestMsg("Audit command Swift technologies integration", "--test.audit.Swift"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitAuditPythonTest(t *testing.T, minVersion string) {
	if !*configTests.TestAuditPython {
		t.Skip(getSkipTestMsg("Audit command Python technologies (Pip, PipEnv, Poetry) integration", "--test.audit.Python"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitScanTest(t *testing.T, minVersion string) {
	if !*configTests.TestScan {
		t.Skip(getSkipTestMsg("Other scan commands integration", "--test.scan"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitNativeDockerTest(t *testing.T) (mockCli *coreTests.JfrogCli, cleanUp func()) {
	if !*configTests.TestDockerScan {
		t.Skip(getSkipTestMsg("Docker scan command integration (Ubuntu)", "--test.dockerScan"))
	}
	return InitTestWithMockCommandOrParams(t, false, cli.DockerScanMockCommand)
}

func InitCurationTest(t *testing.T) {
	if !*configTests.TestCuration {
		t.Skip(getSkipTestMsg("Curation command integration", "--test.curation"))
	}
}

func InitEnrichTest(t *testing.T, minVersion string) {
	if !*configTests.TestEnrich {
		t.Skip(getSkipTestMsg("Enrich command integration", "--test.enrich"))
	}
	testUtils.GetAndValidateXrayVersion(t, minVersion)
}

func InitGitTest(t *testing.T, minXrayVersion string) (string, string, func()) {
	if !*configTests.TestGit {
		t.Skip(getSkipTestMsg("Git commands integration", "--test.git"))
	}
	xrayVersion, xscVersion, err := getXrayAndXscTestVersions(t)
	assert.NoError(t, err)
	if minXrayVersion != "" {
		testUtils.ValidateXrayVersion(t, xrayVersion, minXrayVersion)
	}
	// Make sure the request will work with xsc and not xray
	assert.NoError(t, os.Setenv(coreutils.ReportUsage, "true"))
	return xrayVersion, xscVersion, func() {
		assert.NoError(t, os.Setenv(coreutils.ReportUsage, "false"))
	}
}

func CreateJfrogHomeConfig(t *testing.T, home string, details *config.ServerDetails, encryptPassword bool) (cleanUp func()) {
	if home == "" {
		wd, err := os.Getwd()
		assert.NoError(t, err, "Failed to get current dir")
		home = wd
	}
	clientTests.SetEnvAndAssert(t, coreutils.HomeDir, filepath.Join(home, configTests.Out, "jfroghome"))
	assert.NoError(t, OverrideDefaultConfig(details, encryptPassword))
	cleanUp = func() {
		assert.NoError(t, os.Unsetenv(coreutils.HomeDir), "Failed to unset env: "+coreutils.HomeDir)
	}
	return
}

func OverrideDefaultConfig(details *config.ServerDetails, encryptPassword bool) error {
	// Delete the default server if exist
	config, err := commonCommands.GetConfig("default", false)
	if err == nil && config.ServerId != "" {
		err = commonCommands.NewConfigCommand(commonCommands.Delete, "default").Run()
		if err != nil {
			return fmt.Errorf("failed to delete existing 'default' config: %w", err)
		}
	}
	*configTests.JfrogUrl = clientUtils.AddTrailingSlashIfNeeded(*configTests.JfrogUrl)
	return commonCommands.NewConfigCommand(commonCommands.AddOrEdit, "default").SetDetails(details).SetInteractive(false).SetEncPassword(encryptPassword).Run()
}

func InitTestCliDetails(testApplication components.App) {
	configTests.TestApplication = &testApplication
	if configTests.PlatformCli == nil {
		configTests.PlatformCli = GetXrayTestCli(testApplication, false)
	}
}

func GetXrayTestCli(testApplication components.App, xrayUrlOnly bool) (testCli *coreTests.JfrogCli) {
	creds := authenticateXray(xrayUrlOnly)
	return coreTests.NewJfrogCli(func() error { return plugins.RunCliWithPlugin(testApplication)() }, "", creds)
}

func GetArtifactoryCli(testApplication components.App) (testCli *coreTests.JfrogCli) {
	creds := AuthenticateArtifactory()
	return coreTests.NewJfrogCli(func() error { return plugins.RunCliWithPlugin(testApplication)() }, "", creds)
}

func authenticateXray(xrayUrlOnly bool) string {
	*configTests.JfrogUrl = clientUtils.AddTrailingSlashIfNeeded(*configTests.JfrogUrl)
	var cred string
	if xrayUrlOnly {
		configTests.XrDetails = &config.ServerDetails{XrayUrl: *configTests.JfrogUrl + configTests.XrayEndpoint}
		cred = fmt.Sprintf("--xray-url=%s", configTests.XrDetails.XrayUrl)
	} else {
		configTests.XrDetails = &config.ServerDetails{Url: *configTests.JfrogUrl, ArtifactoryUrl: *configTests.JfrogUrl + configTests.ArtifactoryEndpoint, XrayUrl: *configTests.JfrogUrl + configTests.XrayEndpoint}
		cred = fmt.Sprintf("--url=%s", configTests.XrDetails.XrayUrl)
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

func IsRepoExist(repoName string) (bool, error) {
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		return false, err
	}
	resp, _, _, err := client.SendGet(configTests.RtDetails.ArtifactoryUrl+configTests.RepoDetailsEndpoint+repoName, true, configTests.RtHttpDetails, "")
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusBadRequest {
		return true, nil
	}
	return false, nil
}

func isRepoExistExitOnError(repoName string) bool {
	exist, err := IsRepoExist(repoName)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return exist
}

func DeleteRepos(repos map[*string]string) {
	for repoName := range repos {
		if isRepoExistExitOnError(*repoName) {
			ExecDeleteRepo(*repoName)
		}
	}
}

func CreateRepos(repos map[*string]string) {
	for repoName, configFile := range repos {
		if !isRepoExistExitOnError(*repoName) {
			repoConfig := configTests.GetTestResourcesPath() + "/artifactory-repo-configs/" + configFile
			repoConfig, err := commonTests.ReplaceTemplateVariables(repoConfig, "", configTests.GetSubstitutionMap())
			if err != nil {
				log.Error(err)
				os.Exit(1)
			}
			execCreateRepoRest(repoConfig, *repoName)
		}
	}
}

func InitTestWithMockCommandOrParams(t *testing.T, xrayUrlCli bool, mockCommands ...func() components.Command) (mockCli *coreTests.JfrogCli, cleanUp func()) {
	cleanUp = UseTestHomeWithDefaultXrayConfig(t)
	// Create server config to use with the command.
	CreateJfrogHomeConfig(t, "", configTests.XrDetails, true)
	// Create mock cli with the mock commands.
	commands := []components.Command{}
	for _, mockCommand := range mockCommands {
		commands = append(commands, mockCommand())
	}
	mockCli = GetXrayTestCli(components.CreateEmbeddedApp("security", commands), xrayUrlCli)
	return
}

func UseTestHomeWithDefaultXrayConfig(t *testing.T) func() {
	clientTests.SetEnvAndAssert(t, coreutils.HomeDir, configTests.TestJfrogHomeResourcesPath)
	return func() {
		assert.NoError(t, os.Unsetenv(coreutils.HomeDir))
	}
}

func InitTestHomeResources() (cleanUp func()) {
	tempDirPath, err := fileutils.CreateTempDir()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	log.Info("Using JFrog Home resources path:", tempDirPath)
	// Can be referenced by the tests to get the JFrog Home that defines 'default' config
	configTests.TestJfrogHomeResourcesPath = tempDirPath
	// Set the JFrog Home environment variable to the temp dir and prepare the JFrog Home.
	if err = os.Setenv(coreutils.HomeDir, configTests.TestJfrogHomeResourcesPath); err != nil {
		log.Error(fmt.Sprintf("Couldn't set env: %s. Error: %s", coreutils.HomeDir, err.Error()))
		os.Exit(1)
	}
	// Create a default Xray server config to use with the commands. (most commands require Xray server config)
	if err = OverrideDefaultConfig(configTests.XrDetails, true); err != nil {
		log.Error(fmt.Sprintf("Failed to create default Xray server config: %s", err.Error()))
		os.Exit(1)
	}
	// Prepare resources for commands in JFrog Home.
	// If TestJfrogHomeResourcesPath is used, it will have all the resources needed for the tests. and nothing will be downloaded.
	if err = PrepareJfrogHomeResources(configTests.XrDetails); err != nil {
		log.Error(fmt.Sprintf("Failed to prepare JFrog Home resources: %s", err.Error()))
		os.Exit(1)
	}
	// Unset the JFROG_HOME environment variable to avoid affecting other tests.
	if err = os.Unsetenv(coreutils.HomeDir); err != nil {
		log.Error(fmt.Sprintf("Couldn't unset env: %s. Error: %s", coreutils.HomeDir, err.Error()))
		os.Exit(1)
	}
	return func() {
		if err := fileutils.RemoveTempDir(tempDirPath); err != nil {
			log.Error(err)
		}
	}
}

func PrepareJfrogHomeResources(details *config.ServerDetails) (err error) {
	// Prepare the Analyzer Manager resource.
	if err = testUtils.PrepareAnalyzerManagerResource(); err != nil {
		return fmt.Errorf("failed to prepare analyzer manager resource: %w", err)
	}
	// Prepare the Xray Indexer resource.
	if err = testUtils.PrepareIndexerResource(details); err != nil {
		return fmt.Errorf("failed to prepare Xray Indexer resource: %w", err)
	}
	return
}

func CleanFileSystem() {
	removeDirs(configTests.Out, configTests.Temp)
}

func removeDirs(dirs ...string) {
	for _, dir := range dirs {
		isExist, err := fileutils.IsDirExists(dir, false)
		if err != nil {
			log.Error(err)
		}
		if isExist {
			err = fileutils.RemoveTempDir(dir)
			if err != nil {
				log.Error(errors.New("Cannot remove path: " + dir + " due to: " + err.Error()))
			}
		}
	}
}
