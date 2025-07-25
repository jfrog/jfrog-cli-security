package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-core/v2/utils/dependencies"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/stretchr/testify/assert"

	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/jfrog-cli-security/cli"
	"github.com/jfrog/jfrog-cli-security/jas"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	securityIntegrationTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/artifactory"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"

	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/generic"
	commonCommands "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
)

// We perform validation on dependency resolution from an Artifactory server during the construction of the dependency tree during 'audit' flow.
// This process involves resolving all dependencies required by the project.
func TestDependencyResolutionFromArtifactory(t *testing.T) {
	securityIntegrationTestUtils.InitArtifactoryTest(t)
	testCases := []struct {
		testProjectPath []string
		resolveRepoName string
		cacheRepoName   string
		projectType     project.ProjectType
	}{
		{
			testProjectPath: []string{"npm", "npm-no-lock"},
			resolveRepoName: securityTests.NpmRemoteRepo,
			cacheRepoName:   securityTests.NpmRemoteRepo,
			projectType:     project.Npm,
		},
		{
			testProjectPath: []string{"dotnet", "dotnet-single"},
			resolveRepoName: securityTests.NugetRemoteRepo,
			cacheRepoName:   securityTests.NugetRemoteRepo,
			projectType:     project.Dotnet,
		},
		{
			testProjectPath: []string{"yarn", "yarn-v2"},
			resolveRepoName: securityTests.YarnRemoteRepo,
			cacheRepoName:   securityTests.YarnRemoteRepo,
			projectType:     project.Yarn,
		},
		{
			testProjectPath: []string{"gradle", "gradleproject"},
			resolveRepoName: securityTests.GradleRemoteRepo,
			cacheRepoName:   securityTests.GradleRemoteRepo,
			projectType:     project.Gradle,
		},
		{
			testProjectPath: []string{"maven", "mavenproject"},
			resolveRepoName: securityTests.MvnRemoteRepo,
			cacheRepoName:   securityTests.MvnRemoteRepo,
			projectType:     project.Maven,
		},
		{
			testProjectPath: []string{"maven", "maven-snapshot"},
			resolveRepoName: securityTests.MvnVirtualRepo,
			cacheRepoName:   securityTests.MvnRemoteRepo,
			projectType:     project.Maven,
		},
		{
			testProjectPath: []string{"go", "simple-project"},
			resolveRepoName: securityTests.GoVirtualRepo,
			cacheRepoName:   securityTests.GoRemoteRepo,
			projectType:     project.Go,
		},
		{
			testProjectPath: []string{"python", "pipenv", "pipenv", "pipenvproject"},
			resolveRepoName: securityTests.PypiRemoteRepo,
			cacheRepoName:   securityTests.PypiRemoteRepo,
			projectType:     project.Pipenv,
		},
		{
			testProjectPath: []string{"python", "pip", "pip", "setuppyproject"},
			resolveRepoName: securityTests.PypiRemoteRepo,
			cacheRepoName:   securityTests.PypiRemoteRepo,
			projectType:     project.Pip,
		},
		{
			testProjectPath: []string{"python", "poetry", "poetry"},
			resolveRepoName: securityTests.PypiRemoteRepo,
			cacheRepoName:   securityTests.PypiRemoteRepo,
			projectType:     project.Poetry,
		},
	}
	securityIntegrationTestUtils.CreateJfrogHomeConfig(t, "", true)
	defer securityTestUtils.CleanTestsHomeEnv()

	for _, testCase := range testCases {
		t.Run(testCase.projectType.String(), func(t *testing.T) {
			testSingleTechDependencyResolution(t, testCase.testProjectPath, testCase.resolveRepoName, testCase.cacheRepoName, testCase.projectType)
		})
	}
}

func testSingleTechDependencyResolution(t *testing.T, testProjectPartialPath []string, resolveRepoName string, cacheRepoName string, projectType project.ProjectType) {
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	testProjectPath := filepath.Join(append([]string{filepath.FromSlash(securityTests.GetTestResourcesPath()), "projects", "package-managers"}, testProjectPartialPath...)...)
	assert.NoError(t, biutils.CopyDir(testProjectPath, tempDirPath, true, nil))
	rootDir, err := os.Getwd()
	assert.NoError(t, err)
	assert.NoError(t, os.Chdir(tempDirPath))
	defer func() {
		assert.NoError(t, os.Chdir(rootDir))
	}()

	server := &config.ServerDetails{
		Url:            *securityTests.JfrogUrl,
		ArtifactoryUrl: *securityTests.JfrogUrl + securityTests.ArtifactoryEndpoint,
		XrayUrl:        *securityTests.JfrogUrl + securityTests.XrayEndpoint,
		AccessToken:    *securityTests.JfrogAccessToken,
		ServerId:       securityTests.ServerId,
	}
	configCmd := commonCommands.NewConfigCommand(commonCommands.AddOrEdit, securityTests.ServerId).SetDetails(server).SetUseBasicAuthOnly(true).SetInteractive(false)
	assert.NoError(t, configCmd.Run())
	// Create build config
	assert.NoError(t, commonCommands.CreateBuildConfigWithOptions(false, projectType,
		commonCommands.WithResolverServerId(server.ServerId),
		commonCommands.WithResolverRepo(resolveRepoName),
	))

	artifactoryPathToSearch := cacheRepoName + "-cache/*"
	// To ensure a clean state between test cases, we need to verify that the cache remains clear for remote directories shared across multiple test cases.
	deleteCmd := generic.NewDeleteCommand()
	deleteCmd.SetServerDetails(server).SetRetries(3).SetSpec(spec.NewBuilder().Pattern(artifactoryPathToSearch).Recursive(true).BuildSpec())
	assert.NoError(t, deleteCmd.Run())

	callbackFunc := clearOrRedirectLocalCacheIfNeeded(t, projectType)
	if callbackFunc != nil {
		defer func() {
			callbackFunc()
		}()
	}

	// Executing the 'audit' command on an uninstalled project, we anticipate the resolution of dependencies from the configured Artifactory server and repository.
	assert.NoError(t, securityTests.PlatformCli.WithoutCredentials().Exec("audit"))

	// Following resolution from Artifactory, we anticipate the repository's cache to contain data.
	output := coreTests.RunCmdWithOutput(t, func() error {
		searchCmd := generic.NewSearchCommand()
		searchCmd.SetServerDetails(server).SetRetries(3).SetSpec(spec.NewBuilder().Pattern(artifactoryPathToSearch).Recursive(true).BuildSpec())
		err := searchCmd.Run()
		if err != nil {
			return err
		}
		// After the resolution from Artifactory, we verify whether the repository's cache is filled with artifacts.
		result := searchCmd.Result()
		require.NotNil(t, result)
		reader := result.Reader()
		require.NotNil(t, reader)
		defer func() {
			err = errors.Join(err, reader.Close())
		}()
		readerLen, e := reader.Length()
		if err = errors.Join(err, e); err != nil {
			return err
		}
		assert.NotEqual(t, 0, readerLen)
		return err
	})
	assert.NotEqual(t, "[]\n", output)
}

// To guarantee that dependencies are resolved from Artifactory, certain package managers may need their local cache to be cleared.
func clearOrRedirectLocalCacheIfNeeded(t *testing.T, projectType project.ProjectType) (callbackFunc func()) {
	switch projectType {
	case project.Dotnet:
		_, err := exec.Command("dotnet", "nuget", "locals", "all", "--clear").CombinedOutput()
		assert.NoError(t, err)
	case project.Maven:
		mavenCacheTempPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
		envVarCallbackFunc := clientTests.SetEnvWithCallbackAndAssert(t, securityTests.JvmLaunchEnvVar, securityTests.MavenCacheRedirectionVal+mavenCacheTempPath)
		callbackFunc = func() {
			envVarCallbackFunc()
			createTempDirCallback()
		}
	case project.Go:
		goTempCachePath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
		envVarCallbackFunc := clientTests.SetEnvWithCallbackAndAssert(t, securityTests.GoCacheEnvVar, goTempCachePath)

		callbackFunc = func() {
			envVarCallbackFunc()
			// To remove the temporary cache in Go and all its contents, appropriate deletion permissions are required.
			assert.NoError(t, coreutils.SetPermissionsRecursively(goTempCachePath, 0755))
			createTempDirCallback()
		}
	case project.Pip:
		pipTempCachePath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
		envVarCallbackFunc := clientTests.SetEnvWithCallbackAndAssert(t, securityTests.PipCacheEnvVar, pipTempCachePath)
		callbackFunc = func() {
			envVarCallbackFunc()
			createTempDirCallback()
		}
	}
	return
}

func TestDownloadAnalyzerManagerIfNeeded(t *testing.T) {
	securityIntegrationTestUtils.InitArtifactoryTest(t)
	// Configure a new JFrog CLI home dir.
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	setEnvCallBack := clientTests.SetEnvWithCallbackAndAssert(t, coreutils.HomeDir, tempDirPath)
	defer setEnvCallBack()

	// Download
	err := jas.DownloadAnalyzerManagerIfNeeded(0)
	assert.NoError(t, err)

	// Validate Analyzer manager app & checksum.sh2 file exist
	path, err := jas.GetAnalyzerManagerDirAbsolutePath()
	assert.NoError(t, err)
	amPath := filepath.Join(path, jas.GetAnalyzerManagerExecutableName())
	exists, err := fileutils.IsFileExists(amPath, false)
	assert.NoError(t, err)
	assert.True(t, exists)
	checksumPath := filepath.Join(path, dependencies.ChecksumFileName)
	exists, err = fileutils.IsFileExists(checksumPath, false)
	assert.NoError(t, err)
	assert.True(t, exists)
	checksumFileStat, err := os.Stat(checksumPath)
	assert.NoError(t, err)
	assert.True(t, checksumFileStat.Size() > 0)

	// Validate no second download occurred
	firstFileStat, err := os.Stat(amPath)
	assert.NoError(t, err)
	err = jas.DownloadAnalyzerManagerIfNeeded(0)
	assert.NoError(t, err)
	secondFileStat, err := os.Stat(amPath)
	assert.NoError(t, err)
	assert.Equal(t, firstFileStat.ModTime(), secondFileStat.ModTime())
}

func TestUploadCdxCmdCommand(t *testing.T) {
	securityIntegrationTestUtils.InitArtifactoryTest(t)
	// Create a temporary cdx file with suffix .cdx.json to upload
	tempDirPath, createTempDirCallback := coreTests.CreateTempDirWithCallbackAndAssert(t)
	defer createTempDirCallback()
	securityIntegrationTestUtils.CreateJfrogHomeConfig(t, tempDirPath, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	cdxFileToUpload := getTestCdxFile(t, tempDirPath)
	// Configure the repository to upload the cdx file to
	var repoPath string
	for range 10 {
		repoPath = generateTestRepoName()
		// Check if the repository already exists, if it does, generate a new name
		exists, err := securityIntegrationTestUtils.IsRepoExist(repoPath)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to check if repository %s exists: %s", repoPath, err.Error()))
			continue
		}
		if !exists {
			// Found a unique not existing repository name
			break
		}
	}
	if repoPath == "" {
		t.Fatalf("Failed to generate a unique repository name after 10 attempts")
	}
	defer securityIntegrationTestUtils.ExecDeleteRepo(repoPath)
	// Run the upload command
	assert.NoError(t, integration.GetArtifactoryCli(cli.GetJfrogCliSecurityApp()).Exec("upload-cdx", "--rt-repo-path", repoPath, cdxFileToUpload))

	// Validate the file was uploaded successfully
	searchResults, err := artifactory.SearchArtifactsInRepo(securityTests.RtDetails, filepath.Base(cdxFileToUpload), repoPath)
	assert.NoError(t, err)
	assert.NotEmpty(t, searchResults, "Expected to find the uploaded CycloneDX file in the repository")
}

func generateTestRepoName() string {
	// Generate a unique repository name for the test
	return fmt.Sprintf("test-upload-cdx-%s", utils.GetCurrentTimeUnix())
}

func getTestCdxFile(t *testing.T, tempDir string) string {
	// Create the cyclonedx BOM
	bom := cyclonedx.NewBOM()
	fileComponent := cdxutils.CreateFileOrDirComponent(tempDir)
	bom.Metadata = &cyclonedx.Metadata{
		Component: &fileComponent,
	}
	bom.Components = &[]cyclonedx.Component{
		{
			BOMRef:     "npm:npm-app-root:1.0.0",
			Name:       "npm-app-root",
			Version:    "1.0.0",
			Type:       cyclonedx.ComponentTypeLibrary,
			PackageURL: "pkg:npm/npm-app-root@1.0.0",
		},
		{
			BOMRef:     "npm:npm-app-dep:1.0.0",
			Name:       "npm-app-dep",
			Version:    "1.0.0",
			Type:       cyclonedx.ComponentTypeLibrary,
			PackageURL: "pkg:npm/npm-app-dep@1.0.0",
		},
		{
			BOMRef:     "npm:npm-app-transitive-dep:1.0.0",
			Name:       "npm-app-transitive-dep",
			Version:    "1.0.0",
			Type:       cyclonedx.ComponentTypeLibrary,
			PackageURL: "pkg:npm/npm-app-transitive-dep@1.0.0",
		},
	}
	bom.Dependencies = &[]cyclonedx.Dependency{
		{
			Ref: "npm:npm-app-root:1.0.0",
			Dependencies: &[]string{
				"npm:npm-app-dep:1.0.0",
			},
		},
		{
			Ref: "npm:npm-app-dep:1.0.0",
			Dependencies: &[]string{
				"npm:npm-app-transitive-dep:1.0.0",
			},
		},
	}
	bom.Vulnerabilities = &[]cyclonedx.Vulnerability{
		{
			BOMRef:      "CVE-2021-1234",
			ID:          "CVE-2021-1234",
			Source:      &cyclonedx.Source{Name: "NVD"},
			Description: "Example Vulnerability",
			Affects: &[]cyclonedx.Affects{
				{
					Ref: "npm:npm-app-dep:1.0.0",
				},
			},
		},
	}
	// Create a CycloneDX file in the temporary directory
	cdxFilePath := filepath.Join(tempDir, fmt.Sprintf("upload-integration-test-%s.cdx.json", utils.GetCurrentTimeUnix()))
	file, err := os.Create(cdxFilePath)
	assert.NoError(t, err)
	defer file.Close()
	// Write the BOM to the file
	assert.NoError(t, cyclonedx.NewBOMEncoder(file, cyclonedx.BOMFileFormatJSON).SetPretty(true).Encode(bom))
	return cdxFilePath
}
