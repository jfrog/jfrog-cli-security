package java

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

const (
	//#nosec G101 - dummy token for testing
	settingsXmlWithUsernameAndPassword = `<?xml version="1.0" encoding="UTF-8"?>
<settings xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd"
          xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <servers>
        <server>
            <id>artifactory</id>
            <username>testUser</username>
            <password>testPass</password>
        </server>
    </servers>
    <mirrors>
        <mirror>
            <id>artifactory</id>
            <url>https://myartifactory.com/artifactory/testRepo</url>
            <mirrorOf>*</mirrorOf>
        </mirror>
    </mirrors>
    <profiles>
        <profile>
            <repositories>
                <repository>
                    <snapshots>
                        <enabled>true</enabled>
                    </snapshots>
                    <id>artifactory</id>
                    <name>mavenRepo</name>
                    <url>https://myartifactory.com/artifactory/testRepo</url>
                </repository>
            </repositories>
            <id>artifactory</id>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>artifactory</activeProfile>
    </activeProfiles>
</settings>`
	//#nosec G101 - dummy token for testing
	settingsXmlWithUsernameAndPasswordAndCurationDedicatedAPi = `<?xml version="1.0" encoding="UTF-8"?>
<settings xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd"
          xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <servers>
        <server>
            <id>artifactory</id>
            <username>testUser</username>
            <password>testPass</password>
        </server>
    </servers>
    <mirrors>
        <mirror>
            <id>artifactory</id>
            <url>https://myartifactory.com/artifactory/api/curation/audit/testRepo</url>
            <mirrorOf>*</mirrorOf>
        </mirror>
    </mirrors>
    <profiles>
        <profile>
            <repositories>
                <repository>
                    <snapshots>
                        <enabled>true</enabled>
                    </snapshots>
                    <id>artifactory</id>
                    <name>mavenRepo</name>
                    <url>https://myartifactory.com/artifactory/api/curation/audit/testRepo</url>
                </repository>
            </repositories>
            <id>artifactory</id>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>artifactory</activeProfile>
    </activeProfiles>
</settings>`
	//#nosec G101 - dummy token for testing
	settingsXmlWithUsernameAndToken = `<?xml version="1.0" encoding="UTF-8"?>
<settings xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd"
          xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <servers>
        <server>
            <id>artifactory</id>
            <username>testUser</username>
            <password>eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJIcnU2VHctZk1yOTV3dy12TDNjV3ZBVjJ3Qm9FSHpHdGlwUEFwOE1JdDljIn0.eyJzdWIiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3XC91c2Vyc1wvYWRtaW4iLCJzY3AiOiJtZW1iZXItb2YtZ3JvdXBzOnJlYWRlcnMgYXBpOioiLCJhdWQiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3IiwiaXNzIjoiamZydEAwMWMzZ2ZmaGcyZTh3NjE0OWUzYTJxMHc5NyIsImV4cCI6MTU1NjAzNzc2NSwiaWF0IjoxNTU2MDM0MTY1LCJqdGkiOiI1M2FlMzgyMy05NGM3LTQ0OGItOGExOC1iZGVhNDBiZjFlMjAifQ.Bp3sdvppvRxysMlLgqT48nRIHXISj9sJUCXrm7pp8evJGZW1S9hFuK1olPmcSybk2HNzdzoMcwhUmdUzAssiQkQvqd_HanRcfFbrHeg5l1fUQ397ECES-r5xK18SYtG1VR7LNTVzhJqkmRd3jzqfmIK2hKWpEgPfm8DRz3j4GGtDRxhb3oaVsT2tSSi_VfT3Ry74tzmO0GcCvmBE2oh58kUZ4QfEsalgZ8IpYHTxovsgDx_M7ujOSZx_hzpz-iy268-OkrU22PQPCfBmlbEKeEUStUO9n0pj4l1ODL31AGARyJRy46w4yzhw7Fk5P336WmDMXYs5LAX2XxPFNLvNzA</password>
        </server>
    </servers>
    <mirrors>
        <mirror>
            <id>artifactory</id>
            <url>https://myartifactory.com/artifactory/testRepo</url>
            <mirrorOf>*</mirrorOf>
        </mirror>
    </mirrors>
    <profiles>
        <profile>
            <repositories>
                <repository>
                    <snapshots>
                        <enabled>true</enabled>
                    </snapshots>
                    <id>artifactory</id>
                    <name>mavenRepo</name>
                    <url>https://myartifactory.com/artifactory/testRepo</url>
                </repository>
            </repositories>
            <id>artifactory</id>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>artifactory</activeProfile>
    </activeProfiles>
</settings>`
	//#nosec G101 - dummy token for testing
	settingsXmlWithAccessToken = `<?xml version="1.0" encoding="UTF-8"?>
<settings xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd"
          xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <servers>
        <server>
            <id>artifactory</id>
            <username>admin</username>
            <password>eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJIcnU2VHctZk1yOTV3dy12TDNjV3ZBVjJ3Qm9FSHpHdGlwUEFwOE1JdDljIn0.eyJzdWIiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3XC91c2Vyc1wvYWRtaW4iLCJzY3AiOiJtZW1iZXItb2YtZ3JvdXBzOnJlYWRlcnMgYXBpOioiLCJhdWQiOiJqZnJ0QDAxYzNnZmZoZzJlOHc2MTQ5ZTNhMnEwdzk3IiwiaXNzIjoiamZydEAwMWMzZ2ZmaGcyZTh3NjE0OWUzYTJxMHc5NyIsImV4cCI6MTU1NjAzNzc2NSwiaWF0IjoxNTU2MDM0MTY1LCJqdGkiOiI1M2FlMzgyMy05NGM3LTQ0OGItOGExOC1iZGVhNDBiZjFlMjAifQ.Bp3sdvppvRxysMlLgqT48nRIHXISj9sJUCXrm7pp8evJGZW1S9hFuK1olPmcSybk2HNzdzoMcwhUmdUzAssiQkQvqd_HanRcfFbrHeg5l1fUQ397ECES-r5xK18SYtG1VR7LNTVzhJqkmRd3jzqfmIK2hKWpEgPfm8DRz3j4GGtDRxhb3oaVsT2tSSi_VfT3Ry74tzmO0GcCvmBE2oh58kUZ4QfEsalgZ8IpYHTxovsgDx_M7ujOSZx_hzpz-iy268-OkrU22PQPCfBmlbEKeEUStUO9n0pj4l1ODL31AGARyJRy46w4yzhw7Fk5P336WmDMXYs5LAX2XxPFNLvNzA</password>
        </server>
    </servers>
    <mirrors>
        <mirror>
            <id>artifactory</id>
            <url>https://myartifactory.com/artifactory/testRepo</url>
            <mirrorOf>*</mirrorOf>
        </mirror>
    </mirrors>
    <profiles>
        <profile>
            <repositories>
                <repository>
                    <snapshots>
                        <enabled>true</enabled>
                    </snapshots>
                    <id>artifactory</id>
                    <name>mavenRepo</name>
                    <url>https://myartifactory.com/artifactory/testRepo</url>
                </repository>
            </repositories>
            <id>artifactory</id>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>artifactory</activeProfile>
    </activeProfiles>
</settings>`
)

func TestMavenTreesMultiModule(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "maven", "maven-example"))
	defer cleanUp()

	expectedUniqueDeps := []string{
		GavPackageTypeIdentifier + "javax.mail:mail:1.4",
		GavPackageTypeIdentifier + "org.testng:testng:5.9-jdk15",
		GavPackageTypeIdentifier + "javax.servlet:servlet-api:2.5",
		GavPackageTypeIdentifier + "org.jfrog.test:multi:3.7-SNAPSHOT",
		GavPackageTypeIdentifier + "org.jfrog.test:multi3:3.7-SNAPSHOT",
		GavPackageTypeIdentifier + "org.jfrog.test:multi2:3.7-SNAPSHOT",
		GavPackageTypeIdentifier + "junit:junit:3.8.1",
		GavPackageTypeIdentifier + "org.jfrog.test:multi1:3.7-SNAPSHOT",
		GavPackageTypeIdentifier + "commons-io:commons-io:1.4",
		GavPackageTypeIdentifier + "org.apache.commons:commons-email:1.1",
		GavPackageTypeIdentifier + "javax.activation:activation:1.1",
		GavPackageTypeIdentifier + "hsqldb:hsqldb:1.8.0.10",
	}
	// Run getModulesDependencyTrees
	modulesDependencyTrees, uniqueDeps, err := buildMavenDependencyTree(&DepTreeParams{})
	if assert.NoError(t, err) && assert.NotEmpty(t, modulesDependencyTrees) {
		assert.ElementsMatch(t, maps.Keys(uniqueDeps), expectedUniqueDeps, "First is actual, Second is Expected")
		// Check root module
		multi := coreTests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test:multi:3.7-SNAPSHOT")
		if assert.NotNil(t, multi) {
			assert.Len(t, multi.Nodes, 1)
			// Check multi1 with a transitive dependency
			multi1 := coreTests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test:multi1:3.7-SNAPSHOT")
			assert.Len(t, multi1.Nodes, 4)
			commonsEmail := coreTests.GetAndAssertNode(t, multi1.Nodes, "org.apache.commons:commons-email:1.1")
			assert.Len(t, commonsEmail.Nodes, 2)

			// Check multi2 and multi3
			multi2 := coreTests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test:multi2:3.7-SNAPSHOT")
			assert.Len(t, multi2.Nodes, 1)
			multi3 := coreTests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test:multi3:3.7-SNAPSHOT")
			assert.Len(t, multi3.Nodes, 4)
		}
	}
}

func TestMavenWrapperWithoutExecutePermission(t *testing.T) {
	// Simulate mvnw committed without the execute bit (e.g. 100644 in git).
	// The scan must still succeed because RunMvnCmd invokes it via 'sh' on non-Windows.
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "maven", "maven-example-with-wrapper"))
	defer cleanUp()
	assert.NoError(t, os.Chmod("mvnw", 0644))

	modulesDependencyTrees, _, err := buildMavenDependencyTree(&DepTreeParams{UseWrapper: true})
	assert.NoError(t, err)
	assert.NotNil(t, modulesDependencyTrees)
}

func TestMavenWrapperTrees(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "maven", "maven-example-with-wrapper"))
	err := os.Chmod("mvnw", 0700)
	defer cleanUp()
	assert.NoError(t, err)
	expectedUniqueDeps := []string{
		GavPackageTypeIdentifier + "org.jfrog.test:multi1:3.7-SNAPSHOT",
		GavPackageTypeIdentifier + "org.codehaus.plexus:plexus-utils:1.5.1",
		GavPackageTypeIdentifier + "org.springframework:spring-beans:2.5.6",
		GavPackageTypeIdentifier + "commons-logging:commons-logging:1.1.1",
		GavPackageTypeIdentifier + "org.jfrog.test:multi3:3.7-SNAPSHOT",
		GavPackageTypeIdentifier + "org.apache.commons:commons-email:1.1",
		GavPackageTypeIdentifier + "org.springframework:spring-aop:2.5.6",
		GavPackageTypeIdentifier + "org.springframework:spring-core:2.5.6",
		GavPackageTypeIdentifier + "org.jfrog.test:multi:3.7-SNAPSHOT",
		GavPackageTypeIdentifier + "org.jfrog.test:multi2:3.7-SNAPSHOT",
		GavPackageTypeIdentifier + "org.testng:testng:5.9-jdk15",
		GavPackageTypeIdentifier + "hsqldb:hsqldb:1.8.0.10",
		GavPackageTypeIdentifier + "junit:junit:3.8.1",
		GavPackageTypeIdentifier + "javax.activation:activation:1.1",
		GavPackageTypeIdentifier + "javax.mail:mail:1.4",
		GavPackageTypeIdentifier + "aopalliance:aopalliance:1.0",
		GavPackageTypeIdentifier + "commons-io:commons-io:1.4",
		GavPackageTypeIdentifier + "javax.servlet.jsp:jsp-api:2.1",
		GavPackageTypeIdentifier + "javax.servlet:servlet-api:2.5",
	}

	modulesDependencyTrees, uniqueDeps, err := buildMavenDependencyTree(&DepTreeParams{UseWrapper: true})
	if assert.NoError(t, err) && assert.NotEmpty(t, modulesDependencyTrees) {
		assert.ElementsMatch(t, maps.Keys(uniqueDeps), expectedUniqueDeps, "First is actual, Second is Expected")
		// Check root module
		multi := coreTests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test:multi:3.7-SNAPSHOT")
		if assert.NotNil(t, multi) {
			assert.Len(t, multi.Nodes, 1)
			// Check multi1 with a transitive dependency
			multi1 := coreTests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test:multi1:3.7-SNAPSHOT")
			assert.Len(t, multi1.Nodes, 7)
			commonsEmail := coreTests.GetAndAssertNode(t, multi1.Nodes, "org.apache.commons:commons-email:1.1")
			assert.Len(t, commonsEmail.Nodes, 2)
			// Check multi2 and multi3
			multi2 := coreTests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test:multi2:3.7-SNAPSHOT")
			assert.Len(t, multi2.Nodes, 1)
			multi3 := coreTests.GetAndAssertNode(t, modulesDependencyTrees, "org.jfrog.test:multi3:3.7-SNAPSHOT")
			assert.Len(t, multi3.Nodes, 4)
		}
	}
}

func TestMavenWrapperTreesTypes(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "maven", "maven-example-with-many-types"))
	defer cleanUp()
	tree, uniqueDeps, err := buildMavenDependencyTree(&DepTreeParams{})
	require.NoError(t, err)
	// dependency of pom type
	depWithPomType := uniqueDeps["gav://org.webjars:lodash:4.17.21"]
	assert.NotEmpty(t, depWithPomType)
	types := *depWithPomType.Types
	assert.Equal(t, types[0], "pom")
	existInTreePom := false
	for _, node := range tree[0].Nodes {
		if node.Id == "gav://org.webjars:lodash:4.17.21" {
			nodeTypes := *node.Types
			assert.Equal(t, nodeTypes[0], "pom")
			existInTreePom = true
		}
	}
	assert.True(t, existInTreePom)

	// dependency of jar type
	depWithJarType := uniqueDeps["gav://junit:junit:4.11"]
	assert.NotEmpty(t, depWithJarType)
	types = *depWithJarType.Types
	assert.Equal(t, types[0], "jar")
	existInTreeJar := false
	for _, node := range tree[0].Nodes {
		if node.Id == "gav://junit:junit:4.11" {
			nodeTypes := *node.Types
			assert.Equal(t, nodeTypes[0], "jar")
			existInTreeJar = true
		}
	}
	// dependency with classifier
	depWithJarClassifier1 := uniqueDeps["gav://commons-io:commons-io:1.2-flavor1"]
	assert.NotEmpty(t, depWithJarClassifier1)
	depWithJarClassifier2 := uniqueDeps["gav://commons-io:commons-io:1.2-flavor2"]
	assert.NotEmpty(t, depWithJarClassifier2)

	assert.True(t, existInTreeJar)
}

func TestDepTreeWithDedicatedCache(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "maven", "maven-example-with-wrapper"))
	err := os.Chmod("mvnw", 0700)
	defer cleanUp()
	assert.NoError(t, err)
	tempDir := t.TempDir()
	defer assert.NoError(t, utils.RemoveTempDir(tempDir))
	manager := NewMavenDepTreeManager(&DepTreeParams{UseWrapper: true, IsCurationCmd: true, CurationCacheFolder: tempDir}, Tree)
	_, err = manager.runTreeCmd(tempDir)
	require.NoError(t, err)
	// validate one of the jars exist in the dedicated cache for curation
	fileExist, err := utils.IsFileExists(filepath.Join(tempDir, "org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar"), false)
	require.NoError(t, err)
	assert.True(t, fileExist)
}

func TestGetMavenPluginInstallationArgs(t *testing.T) {
	expected := []string{
		"org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file",
		"-Dfile=testPlugin",
		"-B",
	}
	assert.Equal(t, expected, GetMavenPluginInstallationGoals("testPlugin"))
}

func TestCreateSettingsXmlWithConfiguredArtifactory(t *testing.T) {
	// Test case for successful creation of settings.xml.
	mdt := MavenDepTreeManager{
		DepTreeManager: DepTreeManager{
			server: &config.ServerDetails{
				ArtifactoryUrl: "https://myartifactory.com/artifactory",
				User:           "testUser",
				Password:       "testPass",
			},
			depsRepo: "testRepo",
		},
	}
	// Create a temporary directory for testing and settings.xml creation
	tempDir := t.TempDir()
	err := mdt.createSettingsXmlWithConfiguredArtifactory(tempDir)
	assert.NoError(t, err)

	// Verify settings.xml file creation with username and password
	settingsXmlPath := filepath.Join(tempDir, "settings.xml")
	actualContent, err := os.ReadFile(settingsXmlPath)
	actualContent = []byte(strings.ReplaceAll(string(actualContent), "\r\n", "\n"))
	assert.NoError(t, err)
	assert.Equal(t, settingsXmlWithUsernameAndPassword, string(actualContent))

	// check curation command write a dedicated api for curation.
	mdt.isCurationCmd = true
	err = mdt.createSettingsXmlWithConfiguredArtifactory(tempDir)
	require.NoError(t, err)
	actualContent, err = os.ReadFile(settingsXmlPath)
	actualContent = []byte(strings.ReplaceAll(string(actualContent), "\r\n", "\n"))
	assert.NoError(t, err)
	assert.Equal(t, settingsXmlWithUsernameAndPasswordAndCurationDedicatedAPi, string(actualContent))
	mdt.isCurationCmd = false

	mdt.server.Password = ""
	// jfrog-ignore
	mdt.server.AccessToken = dummyToken
	err = mdt.createSettingsXmlWithConfiguredArtifactory(tempDir)
	assert.NoError(t, err)

	// Verify settings.xml file creation with username and access token
	actualContent, err = os.ReadFile(settingsXmlPath)
	actualContent = []byte(strings.ReplaceAll(string(actualContent), "\r\n", "\n"))
	assert.NoError(t, err)
	assert.Equal(t, settingsXmlWithUsernameAndToken, string(actualContent))

	mdt.server.User = ""
	err = mdt.createSettingsXmlWithConfiguredArtifactory(tempDir)
	assert.NoError(t, err)

	// Verify settings.xml file creation with access token only
	actualContent, err = os.ReadFile(settingsXmlPath)
	actualContent = []byte(strings.ReplaceAll(string(actualContent), "\r\n", "\n"))
	assert.NoError(t, err)
	assert.Equal(t, settingsXmlWithAccessToken, string(actualContent))
}

func TestRunProjectsCmd(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "maven", "maven-example"))
	defer cleanUp()
	mvnDepTreeManager := NewMavenDepTreeManager(&DepTreeParams{}, Projects)
	output, clearMavenDepTreeRun, err := mvnDepTreeManager.RunMavenDepTree()
	assert.NoError(t, err)
	assert.NotNil(t, clearMavenDepTreeRun)

	pomPathOccurrences := strings.Count(output, "pomPath")
	assert.Equal(t, 4, pomPathOccurrences)
	assert.NoError(t, clearMavenDepTreeRun())
}

func TestRemoveMavenConfig(t *testing.T) {
	tmpDir := t.TempDir()
	currentDir, err := os.Getwd()
	assert.NoError(t, err)
	restoreDir := tests.ChangeDirWithCallback(t, currentDir, tmpDir)
	defer restoreDir()

	// No maven.config exists
	restoreFunc, err := removeMavenConfig()
	assert.Nil(t, restoreFunc)
	assert.Nil(t, err)

	// Create maven.config
	err = fileutils.CreateDirIfNotExist(".mvn")
	assert.NoError(t, err)
	file, err := os.Create(mavenConfigPath)
	assert.NoError(t, err)
	err = file.Close()
	assert.NoError(t, err)
	restoreFunc, err = removeMavenConfig()
	assert.NoError(t, err)
	assert.NoFileExists(t, mavenConfigPath)
	err = restoreFunc()
	assert.NoError(t, err)
	assert.FileExists(t, mavenConfigPath)
}

func TestNewMavenDepTreeManagerPreservesAllParams(t *testing.T) {
	t.Parallel()
	server := &config.ServerDetails{ArtifactoryUrl: "https://test.jfrog.io/artifactory"}
	params := &DepTreeParams{
		UseWrapper:              true,
		Server:                  server,
		DepsRepo:                "test-repo",
		IsMavenDepTreeInstalled: true,
		IsCurationCmd:           true,
		CurationCacheFolder:     "/tmp/cache",
		UseIncludedBuilds:       true,
		MvnIncludePluginDeps:    true,
	}

	manager := NewMavenDepTreeManager(params, Tree)

	assert.True(t, manager.useWrapper)
	assert.True(t, manager.useIncludedBuilds)
	assert.Equal(t, server, manager.server)
	assert.Equal(t, "test-repo", manager.depsRepo)

	assert.True(t, manager.isInstalled)
	assert.True(t, manager.isCurationCmd)
	assert.Equal(t, "/tmp/cache", manager.curationCacheFolder)
	assert.Equal(t, Tree, manager.cmdName)
	assert.True(t, manager.mvnIncludePluginDeps, "MvnIncludePluginDeps must be propagated from params into the manager")
}

// TestInjectPluginDeps locks in the dedup guard and the module-root fan-out
// of plugin-dep injection without spawning Maven.
func TestInjectPluginDeps(t *testing.T) {
	t.Parallel()
	jarType := func() *[]string { t := []string{"jar"}; return &t }
	strPtr := func(s string) *string { return &s }

	existing := &xray.DepTreeNode{Types: jarType()}

	cases := []struct {
		name                string
		uniqueDeps          map[string]*xray.DepTreeNode
		dependencyTree      []*xrayUtils.GraphNode
		pluginDeps          map[string]*xray.DepTreeNode
		wantUniqueDeps      []string
		wantRootChildren    map[string][]string
		wantExistingKept    bool
		wantChildClassifier map[string]string
	}{
		{
			name:           "empty plugin deps is a no-op",
			uniqueDeps:     map[string]*xray.DepTreeNode{"gav://g:a:1.0": {Types: jarType()}},
			dependencyTree: []*xrayUtils.GraphNode{{Id: "gav://org.example:m1:1.0"}},
			pluginDeps:     nil,
			wantUniqueDeps: []string{"gav://g:a:1.0"},
			wantRootChildren: map[string][]string{
				"gav://org.example:m1:1.0": nil,
			},
		},
		{
			name: "duplicate GAV is not re-added and existing entry is preserved",
			uniqueDeps: map[string]*xray.DepTreeNode{
				"gav://org.codehaus.plexus:plexus-utils:4.0.2": existing,
			},
			dependencyTree: []*xrayUtils.GraphNode{{Id: "gav://org.example:m1:1.0"}},
			pluginDeps: map[string]*xray.DepTreeNode{
				"org.codehaus.plexus:plexus-utils:4.0.2": {Types: jarType()},
			},
			wantUniqueDeps: []string{"gav://org.codehaus.plexus:plexus-utils:4.0.2"},
			wantRootChildren: map[string][]string{
				"gav://org.example:m1:1.0": nil,
			},
			wantExistingKept: true,
		},
		{
			name:       "new plugin dep is attached to every module root",
			uniqueDeps: map[string]*xray.DepTreeNode{},
			dependencyTree: []*xrayUtils.GraphNode{
				{Id: "gav://org.example:m1:1.0"},
				{Id: "gav://org.example:m2:1.0"},
			},
			pluginDeps: map[string]*xray.DepTreeNode{
				"commons-io:commons-io:2.11.0": {Types: jarType()},
			},
			wantUniqueDeps: []string{"gav://commons-io:commons-io:2.11.0"},
			wantRootChildren: map[string][]string{
				"gav://org.example:m1:1.0": {"gav://commons-io:commons-io:2.11.0"},
				"gav://org.example:m2:1.0": {"gav://commons-io:commons-io:2.11.0"},
			},
		},
		{
			name:       "classifier is propagated to the fanned-out module-root node",
			uniqueDeps: map[string]*xray.DepTreeNode{},
			dependencyTree: []*xrayUtils.GraphNode{
				{Id: "gav://org.example:m1:1.0"},
			},
			pluginDeps: map[string]*xray.DepTreeNode{
				"org.ow2.asm:asm:9.8": {Types: jarType(), Classifier: strPtr("tests")},
			},
			wantUniqueDeps: []string{"gav://org.ow2.asm:asm:9.8"},
			wantRootChildren: map[string][]string{
				"gav://org.example:m1:1.0": {"gav://org.ow2.asm:asm:9.8"},
			},
			wantChildClassifier: map[string]string{
				"gav://org.ow2.asm:asm:9.8": "tests",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			injectPluginDeps(tc.uniqueDeps, tc.dependencyTree, tc.pluginDeps)

			gotKeys := make([]string, 0, len(tc.uniqueDeps))
			for k := range tc.uniqueDeps {
				gotKeys = append(gotKeys, k)
			}
			assert.ElementsMatch(t, tc.wantUniqueDeps, gotKeys, "uniqueDeps key set")

			if tc.wantExistingKept {
				assert.Samef(t, existing, tc.uniqueDeps["gav://org.codehaus.plexus:plexus-utils:4.0.2"],
					"dedup guard must not overwrite the existing DepTreeNode")
			}

			for _, root := range tc.dependencyTree {
				var childIDs []string
				for _, child := range root.Nodes {
					childIDs = append(childIDs, child.Id)
					if want, ok := tc.wantChildClassifier[child.Id]; ok {
						if assert.NotNilf(t, child.Classifier, "classifier for %s on root %s", child.Id, root.Id) {
							assert.Equalf(t, want, *child.Classifier, "classifier for %s on root %s", child.Id, root.Id)
						}
					}
				}
				assert.ElementsMatch(t, tc.wantRootChildren[root.Id], childIDs,
					"children attached to module root %s", root.Id)
			}
		})
	}
}
