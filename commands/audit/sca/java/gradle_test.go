package java

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	testsutils "github.com/jfrog/jfrog-cli-core/v2/utils/config/tests"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/ioutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"

	"github.com/stretchr/testify/assert"
)

// #nosec G101 -- Dummy token for tests
// jfrog-ignore
const dummyToken = "eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJIcnU2VHctZk1yOTV3dy12TDNjV3ZBVjJ3Qm9FSHpHdGlwUEFwOE1JdDljIn0.eyJzdWIiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3XC91c2Vyc1wvYWRtaW4iLCJzY3AiOiJtZW1iZXItb2YtZ3JvdXBzOnJlYWRlcnMgYXBpOioiLCJhdWQiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3IiwiaXNzIjoiamZydEAwMWMzZ2ZmaGcyZTh3NjE0OWUzYTJxMHc5NyIsImV4cCI6MTU1NjAzNzc2NSwiaWF0IjoxNTU2MDM0MTY1LCJqdGkiOiI1M2FlMzgyMy05NGM3LTQ0OGItOGExOC1iZGVhNDBiZjFlMjAifQ.Bp3sdvppvRxysMlLgqT48nRIHXISj9sJUCXrm7pp8evJGZW1S9hFuK1olPmcSybk2HNzdzoMcwhUmdUzAssiQkQvqd_HanRcfFbrHeg5l1fUQ397ECES-r5xK18SYtG1VR7LNTVzhJqkmRd3jzqfmIK2hKWpEgPfm8DRz3j4GGtDRxhb3oaVsT2tSSi_VfT3Ry74tzmO0GcCvmBE2oh58kUZ4QfEsalgZ8IpYHTxovsgDx_M7ujOSZx_hzpz-iy268-OkrU22PQPCfBmlbEKeEUStUO9n0pj4l1ODL31AGARyJRy46w4yzhw7Fk5P336WmDMXYs5LAX2XxPFNLvNzA"

const expectedInitScriptWithRepos = `initscript {
	repositories { 
		mavenCentral()
	}
	dependencies {
		classpath files('%s')
	}
}

allprojects {
	repositories { 
		maven {
			url "https://myartifactory.com/artifactory/deps-repo"
			credentials {
				username = 'admin'
				password = '%s'
			}
		}
	}
	apply plugin: com.jfrog.GradleDepTree
}`

func TestGradleTreesWithoutConfig(t *testing.T) {
	// Create and change directory to test workspace
	tempDirPath, cleanUp := tests.CreateTestWorkspace(t, filepath.Join("..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "gradle", "gradle"))
	defer cleanUp()
	assert.NoError(t, os.Chmod(filepath.Join(tempDirPath, "gradlew"), 0700))

	// Run getModulesDependencyTrees
	modulesDependencyTrees, uniqueDeps, err := buildGradleDependencyTree(&DepTreeParams{})
	if assert.NoError(t, err) && assert.NotNil(t, modulesDependencyTrees) {
		assert.Len(t, uniqueDeps, 12)
		assert.Len(t, modulesDependencyTrees, 5)
		// Check module
		module := tests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.example.gradle:webservice:1.0")
		assert.Len(t, module.Nodes, 7)

		// Check direct dependency
		directDependency := tests.GetAndAssertNode(t, module.Nodes, "junit:junit:4.11")
		assert.Len(t, directDependency.Nodes, 1)

		// Check transitive dependency
		tests.GetAndAssertNode(t, directDependency.Nodes, "org.hamcrest:hamcrest-core:1.3")
	}
}

func TestGradleTreesWithConfig(t *testing.T) {
	// Create and change directory to test workspace
	tempDirPath, cleanUp := tests.CreateTestWorkspace(t, filepath.Join("..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "gradle", "gradle-example-config"))
	defer cleanUp()
	assert.NoError(t, os.Chmod(filepath.Join(tempDirPath, "gradlew"), 0700))

	// Run getModulesDependencyTrees
	modulesDependencyTrees, uniqueDeps, err := buildGradleDependencyTree(&DepTreeParams{UseWrapper: true})
	if assert.NoError(t, err) && assert.NotNil(t, modulesDependencyTrees) {
		assert.Len(t, modulesDependencyTrees, 5)
		assert.Len(t, uniqueDeps, 11)
		// Check module
		module := tests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test.gradle.publish:api:1.0-SNAPSHOT")
		assert.Len(t, module.Nodes, 4)

		// Check direct dependency
		directDependency := tests.GetAndAssertNode(t, module.Nodes, "commons-lang:commons-lang:2.4")
		assert.Len(t, directDependency.Nodes, 1)

		// Check transitive dependency
		tests.GetAndAssertNode(t, directDependency.Nodes, "commons-io:commons-io:1.2")
	}
}

func TestIsGradleWrapperExist(t *testing.T) {
	// Check Gradle wrapper doesn't exist
	isWrapperExist, err := isGradleWrapperExist()
	assert.False(t, isWrapperExist)
	assert.NoError(t, err)

	// Check Gradle wrapper exist
	_, cleanUp := tests.CreateTestWorkspace(t, filepath.Join("..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "gradle", "gradle"))
	defer cleanUp()
	isWrapperExist, err = isGradleWrapperExist()
	assert.NoError(t, err)
	assert.True(t, isWrapperExist)
}

func TestGetDepTreeArtifactoryRepository(t *testing.T) {
	tests := []struct {
		name        string
		remoteRepo  string
		server      *config.ServerDetails
		expectedUrl string
		expectedErr string
	}{
		{
			name:       "WithAccessToken",
			remoteRepo: "my-remote-repo",
			server: &config.ServerDetails{
				Url: "https://myartifactory.com",
				// jfrog-ignore
				AccessToken: dummyToken,
			},
			// jfrog-ignore
			expectedUrl: "\n\t\tmaven {\n\t\t\turl \"/my-remote-repo\"\n\t\t\tcredentials {\n\t\t\t\tusername = 'admin'\n\t\t\t\tpassword = 'eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJIcnU2VHctZk1yOTV3dy12TDNjV3ZBVjJ3Qm9FSHpHdGlwUEFwOE1JdDljIn0.eyJzdWIiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3XC91c2Vyc1wvYWRtaW4iLCJzY3AiOiJtZW1iZXItb2YtZ3JvdXBzOnJlYWRlcnMgYXBpOioiLCJhdWQiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3IiwiaXNzIjoiamZydEAwMWMzZ2ZmaGcyZTh3NjE0OWUzYTJxMHc5NyIsImV4cCI6MTU1NjAzNzc2NSwiaWF0IjoxNTU2MDM0MTY1LCJqdGkiOiI1M2FlMzgyMy05NGM3LTQ0OGItOGExOC1iZGVhNDBiZjFlMjAifQ.Bp3sdvppvRxysMlLgqT48nRIHXISj9sJUCXrm7pp8evJGZW1S9hFuK1olPmcSybk2HNzdzoMcwhUmdUzAssiQkQvqd_HanRcfFbrHeg5l1fUQ397ECES-r5xK18SYtG1VR7LNTVzhJqkmRd3jzqfmIK2hKWpEgPfm8DRz3j4GGtDRxhb3oaVsT2tSSi_VfT3Ry74tzmO0GcCvmBE2oh58kUZ4QfEsalgZ8IpYHTxovsgDx_M7ujOSZx_hzpz-iy268-OkrU22PQPCfBmlbEKeEUStUO9n0pj4l1ODL31AGARyJRy46w4yzhw7Fk5P336WmDMXYs5LAX2XxPFNLvNzA'\n\t\t\t}\n\t\t}",
			expectedErr: "",
		},
		{
			name:       "WithUsernameAndPassword",
			remoteRepo: "my-remote-repo",
			server: &config.ServerDetails{
				Url:      "https://myartifactory.com",
				User:     "my-username",
				Password: "my-password",
			},
			expectedUrl: "\n\t\tmaven {\n\t\t\turl \"/my-remote-repo\"\n\t\t\tcredentials {\n\t\t\t\tusername = 'my-username'\n\t\t\t\tpassword = 'my-password'\n\t\t\t}\n\t\t}",
			expectedErr: "",
		},
		{
			name:       "MissingCredentials",
			remoteRepo: "my-remote-repo",
			server: &config.ServerDetails{
				Url: "https://myartifactory.com",
			},
			expectedUrl: "",
			expectedErr: "either username/password or access token must be set for https://myartifactory.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			url, err := getDepTreeArtifactoryRepository(test.remoteRepo, test.server)
			if err != nil {
				assert.Equal(t, test.expectedErr, err.Error())
			} else {
				assert.Equal(t, test.expectedUrl, url)
			}
		})
	}
}

func TestCreateDepTreeScript(t *testing.T) {
	manager := &gradleDepTreeManager{DepTreeManager: DepTreeManager{}}
	tmpDir, err := manager.createDepTreeScriptAndGetDir()
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.Remove(filepath.Join(tmpDir, gradleDepTreeInitFile)))
	}()
	content, err := os.ReadFile(filepath.Join(tmpDir, gradleDepTreeInitFile))
	assert.NoError(t, err)
	gradleDepTreeJarPath := ioutils.DoubleWinPathSeparator(filepath.Join(tmpDir, gradleDepTreeJarFile))
	assert.Equal(t, fmt.Sprintf(gradleDepTreeInitScript, "", gradleDepTreeJarPath, ""), string(content))
}

func TestCreateDepTreeScriptWithRepositories(t *testing.T) {
	manager := &gradleDepTreeManager{DepTreeManager: DepTreeManager{}}
	manager.depsRepo = "deps-repo"
	manager.server = &config.ServerDetails{
		Url:            "https://myartifactory.com/",
		ArtifactoryUrl: "https://myartifactory.com/artifactory",
		// jfrog-ignore
		AccessToken: dummyToken,
	}
	tmpDir, err := manager.createDepTreeScriptAndGetDir()
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.Remove(filepath.Join(tmpDir, gradleDepTreeInitFile)))
	}()

	content, err := os.ReadFile(filepath.Join(tmpDir, gradleDepTreeInitFile))
	assert.NoError(t, err)
	gradleDepTreeJarPath := ioutils.DoubleWinPathSeparator(filepath.Join(tmpDir, gradleDepTreeJarFile))
	// jfrog-ignore
	assert.Equal(t, fmt.Sprintf(expectedInitScriptWithRepos, gradleDepTreeJarPath, dummyToken), string(content))
}

func TestConstructReleasesRemoteRepo(t *testing.T) {
	cleanUp := testsutils.CreateTempEnv(t, false)
	serverDetails := &config.ServerDetails{
		ServerId:       "test",
		ArtifactoryUrl: "https://domain.com/artifactory",
		User:           "user",
		Password:       "pass",
	}
	err := config.SaveServersConf([]*config.ServerDetails{serverDetails})
	assert.NoError(t, err)
	defer cleanUp()
	testCases := []struct {
		envVar       string
		expectedRepo string
		expectedErr  error
	}{
		{envVar: "", expectedRepo: "", expectedErr: nil},
		{envVar: "test/repo1", expectedRepo: "\n\t\tmaven {\n\t\t\turl \"https://domain.com/artifactory/repo1/artifactory/oss-release-local\"\n\t\t\tcredentials {\n\t\t\t\tusername = 'user'\n\t\t\t\tpassword = 'pass'\n\t\t\t}\n\t\t}", expectedErr: nil},
		{envVar: "notexist/repo1", expectedRepo: "", expectedErr: errors.New("Server ID 'notexist' does not exist.")},
	}

	for _, tc := range testCases {
		// Set the environment variable for this test case
		func() {
			assert.NoError(t, os.Setenv(coreutils.ReleasesRemoteEnv, tc.envVar))
			defer func() {
				// Reset the environment variable after each test case
				assert.NoError(t, os.Unsetenv(coreutils.ReleasesRemoteEnv))
			}()
			actualRepo, actualErr := constructReleasesRemoteRepo()
			assert.Equal(t, tc.expectedRepo, actualRepo)
			assert.Equal(t, tc.expectedErr, actualErr)
		}()
	}
}

func TestCreateDepTreeScriptWithRepositoriesForCli(t *testing.T) {
	manager := &gradleDepTreeManager{DepTreeManager: DepTreeManager{}, isCurationCmd: true}
	manager.depsRepo = "deps-repo"
	manager.server = &config.ServerDetails{
		Url:            "https://myartifactory.com/",
		ArtifactoryUrl: "https://myartifactory.com/artifactory",
		// jfrog-ignore
		AccessToken: dummyToken,
	}
	tmpDir, err := manager.createDepTreeScriptAndGetDir()
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.Remove(filepath.Join(tmpDir, gradleDepTreeInitFile)))
	}()

	content, err := os.ReadFile(filepath.Join(tmpDir, gradleDepTreeInitFile))
	assert.NoError(t, err)
	gradleDepTreeJarPath := ioutils.DoubleWinPathSeparator(filepath.Join(tmpDir, gradleDepTreeJarFile))
	// jfrog-ignore
	assert.Equal(t, fmt.Sprintf(expectedInitScriptWithRepos, gradleDepTreeJarPath, dummyToken), string(content))
}
func TestExecGradleDepTree_WithCurationCmd_ModifiesBuildGradle(t *testing.T) {

	tempDirPath, cleanUp := tests.CreateTestWorkspace(t, filepath.Join("..", "..", "..", "..", "tests", "testdata", "projects", "package-managers", "gradle", "gradle-example-config"))
	defer cleanUp()
	const buildGradleContent = `
// Apply the Java plugin to add support for Java
plugins {
    id 'java'
}

// Set the group and version of the project
group = 'com.example'
version = '1.0.0'

// Specify the repositories for dependencies
repositories {
    // Use Maven Central repository
    //mavenCentral()
    maven {
        allowInsecureProtocol = true
        url "http://localhost:8046/artifactory/gradle-remote/"
        credentials {
            username = 'admin'
            password = 'password'
        }
    }
}

// Declare the dependencies for the project
dependencies {
    // Use JUnit 4 for testing
    testImplementation 'junit:junit:4.13.2'

    // Example of including a library (e.g., Apache Commons Lang)
    implementation 'org.apache.commons:commons-lang3:3.12.0'
    implementation group: 'ch.qos.logback', name: 'logback-access', version: '1.4.13'
    implementation group: 'ch.qos.logback', name: 'logback-core', version: '1.5.4'
    implementation group: 'net.sourceforge.jexcelapi', name: 'jxl', version: '2.6.10'
    //implementation 'com.h2database:h2:1.4.200'
}

// Define a custom task (optional)
task hello {
    doLast {
        println 'Hello, Gradle!'
    }
}

// Specify the Java version compatibility
java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}
`
	path := filepath.Join(tempDirPath, "build.gradle")
	err := os.WriteFile(path, []byte(buildGradleContent), 0644)
	assert.NoError(t, err, "Failed to write build.gradle")
	assert.NoError(t, os.Chmod(filepath.Join(tempDirPath, "gradlew"), 0700))
	manager := &gradleDepTreeManager{DepTreeManager: DepTreeManager{}, isCurationCmd: true}
	manager.depsRepo = "deps-repo"
	manager.server = &config.ServerDetails{
		Url:            "https://myartifactory.com/",
		ArtifactoryUrl: "https://myartifactory.com/artifactory",
		AccessToken:    dummyToken,
	}
	if manager.isCurationCmd {
		manager.isCurationCmd = createTempBuildGradleFile()
	}
	// Path to the build.gradle file in the current directory
	buildGradlePath := filepath.Join(tempDirPath, "build.gradle")
	content, err := os.ReadFile(buildGradlePath)
	assert.NoError(t, err, "Failed to read the modified build.gradle file")
	// Verify the build.gradle content contains the updated curation audit URL
	assert.Contains(t, string(content), "/artifactory/api/curation/audit/", "build.gradle should contain the updated curation audit URL")
	if manager.isCurationCmd {
		err := renameTempToBuildGradle()
		assert.NoError(t, err, "Failed to rename temporary build.gradle")
	}
	content, err = os.ReadFile(buildGradlePath)
	assert.NoError(t, err, "Failed to read the modified build.gradle file")
	// Verify the build.gradle content no longer contains the original curation URL
	assert.NotContains(t, string(content), "/artifactory/api/curation/audit/", "build.gradle should not contain the updated curation audit URL")
	// Verify the temporary build.gradle.tmp file was cleaned up
	tempDirPath = filepath.Join(tempDirPath, "build.gradle.tmp")
	_, err = os.Stat(tempDirPath)
	assert.True(t, os.IsNotExist(err), "Expected build.gradle.tmp to be removed after execution")
}
