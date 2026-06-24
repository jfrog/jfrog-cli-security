package java

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

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
	args := GetMavenPluginInstallationGoals("testPlugin")
	assert.Equal(t, "org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file", args[0])
	assert.Equal(t, "-Dfile=testPlugin", args[1])
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

func TestParseMavenPluginDeps(t *testing.T) {
	t.Parallel()
	// Realistic "mvn dependency:resolve-plugins" output from Maven 3.9.x.
	mvnOutput := `
[INFO] Scanning for projects...
[INFO]
[INFO] --- dependency:3.7.0:resolve-plugins (default-cli) @ test-ignore-rules ---
[INFO]
[INFO] The following plugins have been resolved:
[INFO]    org.apache.maven.plugins:maven-clean-plugin:maven-plugin:3.2.0:runtime
[INFO]       org.apache.maven.plugins:maven-clean-plugin:jar:3.2.0
[INFO]       org.apache.maven.shared:maven-shared-utils:jar:3.3.4
[INFO]    org.apache.maven.plugins:maven-resources-plugin:maven-plugin:3.4.0:runtime
[INFO]       org.apache.maven.plugins:maven-resources-plugin:jar:3.4.0
[INFO]       org.codehaus.plexus:plexus-utils:jar:4.0.2
[INFO]       org.apache.commons:commons-lang3:jar:3.20.0
[INFO]       commons-io:commons-io:jar:2.16.1
[INFO]    org.apache.maven.plugins:maven-compiler-plugin:maven-plugin:3.15.0:runtime
[INFO]       org.apache.maven.plugins:maven-compiler-plugin:jar:3.15.0
[INFO]       org.ow2.asm:asm:jar:9.7
[INFO]    org.apache.maven.plugins:maven-site-plugin:maven-plugin:3.12.1:runtime
[INFO]       org.eclipse.sisu:org.eclipse.sisu.plexus:jar:0.3.5
[INFO]       org.sonatype.sisu:sisu-guice:jar:no_aop:3.2.3
[INFO]
[INFO] BUILD SUCCESS
`
	deps := parseMavenPluginDeps(mvnOutput, nil)

	expectedKeys := []string{
		"org.apache.maven.plugins:maven-clean-plugin:3.2.0",
		"org.apache.maven.shared:maven-shared-utils:3.3.4",
		"org.apache.maven.plugins:maven-resources-plugin:3.4.0",
		"org.codehaus.plexus:plexus-utils:4.0.2",
		"org.apache.commons:commons-lang3:3.20.0",
		"commons-io:commons-io:2.16.1",
		"org.apache.maven.plugins:maven-compiler-plugin:3.15.0",
		"org.ow2.asm:asm:9.7",
		"org.eclipse.sisu:org.eclipse.sisu.plexus:0.3.5",
		"org.sonatype.sisu:sisu-guice:3.2.3", // classifier "no_aop" — version must be 3.2.3
	}
	assert.Len(t, deps, len(expectedKeys))
	for _, key := range expectedKeys {
		assert.Contains(t, deps, key, "expected plugin dep %q to be parsed", key)
		if node, ok := deps[key]; ok {
			assert.NotNil(t, node.Types, "expected Types to be set for %q", key)
			assert.NotEmpty(t, *node.Types, "expected at least one type for %q", key)
		}
	}
	// plexus-utils must carry type "jar" so the curation HEAD check builds the correct URL
	plexusNode := deps["org.codehaus.plexus:plexus-utils:4.0.2"]
	if assert.NotNil(t, plexusNode) && assert.NotNil(t, plexusNode.Types) {
		assert.Contains(t, *plexusNode.Types, "jar")
	}
}

func TestParseMavenPluginDepsEmpty(t *testing.T) {
	t.Parallel()
	assert.Empty(t, parseMavenPluginDeps("", nil))
	assert.Empty(t, parseMavenPluginDeps("[INFO] BUILD SUCCESS\n[INFO] some random line", nil))
}

func TestParseMavenPluginDepsScopeSuffix(t *testing.T) {
	t.Parallel()
	// Verifies that a known Maven scope in the 5th colon-field is not mistaken for a version.
	// A line like "g:a:jar:1.0:compile" must produce key "g:a:1.0", not "g:a:compile".
	output := "[INFO]       commons-io:commons-io:jar:2.16.1:compile\n" +
		"[INFO]       org.sonatype.sisu:sisu-guice:jar:no_aop:3.2.3\n"
	deps := parseMavenPluginDeps(output, nil)
	assert.Contains(t, deps, "commons-io:commons-io:2.16.1", "scope suffix should not become the version")
	assert.NotContains(t, deps, "commons-io:commons-io:compile", "version must not be the scope")
	assert.Contains(t, deps, "org.sonatype.sisu:sisu-guice:3.2.3", "classifier path (no_aop) must still resolve correctly")
}

func TestParseMavenPluginDepsSkipsNonCoordinateLines(t *testing.T) {
	t.Parallel()
	output := `
[INFO] Building my-project 1.0-SNAPSHOT
[INFO] --- dependency:3.7.0:resolve-plugins @ my-project ---
[INFO]    org.apache.maven.plugins:maven-jar-plugin:maven-plugin:3.3.0:runtime
[INFO]       org.apache.maven.plugins:maven-jar-plugin:jar:3.3.0
[INFO]       org.apache.maven.shared:maven-shared-utils:jar:3.3.4
[WARNING] Some warning line
[ERROR] some error that should be skipped
`
	deps := parseMavenPluginDeps(output, nil)
	assert.Len(t, deps, 2)
	assert.Contains(t, deps, "org.apache.maven.plugins:maven-jar-plugin:3.3.0")
	assert.Contains(t, deps, "org.apache.maven.shared:maven-shared-utils:3.3.4")
}

func TestParseMavenPluginDepsFiltersByAllowList(t *testing.T) {
	t.Parallel()
	// Same realistic Maven 3.9 output as TestParseMavenPluginDeps; allow-list excludes
	// maven-site-plugin so its transitive deps (sisu.plexus, sisu-guice) must be dropped.
	mvnOutput := `
[INFO] --- dependency:3.7.0:resolve-plugins (default-cli) @ test-ignore-rules ---
[INFO]    org.apache.maven.plugins:maven-resources-plugin:maven-plugin:3.4.0:runtime
[INFO]       org.apache.maven.plugins:maven-resources-plugin:jar:3.4.0
[INFO]       org.codehaus.plexus:plexus-utils:jar:4.0.2
[INFO]    org.apache.maven.plugins:maven-site-plugin:maven-plugin:3.12.1:runtime
[INFO]       org.eclipse.sisu:org.eclipse.sisu.plexus:jar:0.3.5
[INFO]       org.sonatype.sisu:sisu-guice:jar:no_aop:3.2.3
[INFO]    org.apache.maven.plugins:maven-compiler-plugin:maven-plugin:3.15.0:runtime
[INFO]       org.ow2.asm:asm:jar:9.7
`
	allowed := map[string]struct{}{
		"org.apache.maven.plugins:maven-resources-plugin": {},
		"org.apache.maven.plugins:maven-compiler-plugin":  {},
	}
	deps := parseMavenPluginDeps(mvnOutput, allowed)

	assert.Contains(t, deps, "org.apache.maven.plugins:maven-resources-plugin:3.4.0")
	assert.Contains(t, deps, "org.codehaus.plexus:plexus-utils:4.0.2")
	assert.Contains(t, deps, "org.ow2.asm:asm:9.7")
	assert.NotContains(t, deps, "org.eclipse.sisu:org.eclipse.sisu.plexus:0.3.5", "site-plugin transitive dep must be filtered out")
	assert.NotContains(t, deps, "org.sonatype.sisu:sisu-guice:3.2.3", "site-plugin transitive dep must be filtered out")
}

func TestParseEffectivePomPluginCoordinates(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		xmlData  string
		wantNil  bool
		included []string
		excluded []string
	}{
		{
			name: "install-lifecycle plugins included, post-install plugins excluded",
			xmlData: `<?xml version="1.0"?>
<project>
  <build>
    <plugins>
      <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-resources-plugin</artifactId><version>3.4.0</version></plugin>
      <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId><version>3.15.0</version></plugin>
      <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-deploy-plugin</artifactId><version>3.1.4</version></plugin>
      <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-site-plugin</artifactId><version>3.12.1</version></plugin>
    </plugins>
  </build>
</project>`,
			included: []string{
				"org.apache.maven.plugins:maven-resources-plugin",
				"org.apache.maven.plugins:maven-compiler-plugin",
			},
			excluded: []string{
				"org.apache.maven.plugins:maven-deploy-plugin",
				"org.apache.maven.plugins:maven-site-plugin",
			},
		},
		{
			name: "user rebinds deploy-plugin to install-lifecycle phase — included",
			xmlData: `<?xml version="1.0"?>
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-deploy-plugin</artifactId>
        <version>3.1.4</version>
        <executions><execution><id>custom-pkg</id><phase>package</phase></execution></executions>
      </plugin>
    </plugins>
  </build>
</project>`,
			included: []string{"org.apache.maven.plugins:maven-deploy-plugin"},
		},
		{
			name: "user plugin with only post-install executions — excluded",
			xmlData: `<?xml version="1.0"?>
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>com.example</groupId>
        <artifactId>my-deploy-only-plugin</artifactId>
        <version>1.0</version>
        <executions><execution><id>only-on-deploy</id><phase>deploy</phase></execution></executions>
      </plugin>
    </plugins>
  </build>
</project>`,
			excluded: []string{"com.example:my-deploy-only-plugin"},
		},
		{
			// mvn install does not invoke the Clean lifecycle; a plugin bound only to it
			// must not contribute its transitive deps to the curation evaluation.
			name: "user plugin bound only to clean phase — excluded",
			xmlData: `<?xml version="1.0"?>
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>com.example</groupId>
        <artifactId>my-clean-only-plugin</artifactId>
        <version>1.0</version>
        <executions><execution><id>only-on-clean</id><phase>clean</phase></execution></executions>
      </plugin>
    </plugins>
  </build>
</project>`,
			excluded: []string{"com.example:my-clean-only-plugin"},
		},
		{
			name: "multi-module: plugins from every <project> accumulate",
			xmlData: `<?xml version="1.0"?>
<projects>
  <project><build><plugins>
    <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId></plugin>
  </plugins></build></project>
  <project><build><plugins>
    <plugin><groupId>com.example</groupId><artifactId>custom-plugin</artifactId></plugin>
  </plugins></build></project>
</projects>`,
			included: []string{
				"org.apache.maven.plugins:maven-compiler-plugin",
				"com.example:custom-plugin",
			},
		},
		{
			name:    "empty input returns nil (callers fall back to no-filter)",
			xmlData: "",
			wantNil: true,
		},
		{
			name:    "non-XML input returns nil",
			xmlData: "not xml at all",
			wantNil: true,
		},
		{
			// Real maven-help-plugin output declares xmlns="http://maven.apache.org/POM/4.0.0".
			// Without stripping xmlns, encoding/xml returns an empty allow-list and silently
			// disables the filter.
			name: "default Maven namespace is stripped before parsing",
			xmlData: `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>test-ignore-rules</artifactId>
  <version>1.0-SNAPSHOT</version>
  <build>
    <plugins>
      <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-resources-plugin</artifactId><version>3.4.0</version></plugin>
      <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-deploy-plugin</artifactId><version>3.1.4</version></plugin>
    </plugins>
  </build>
</project>`,
			included: []string{"org.apache.maven.plugins:maven-resources-plugin"},
			excluded: []string{"org.apache.maven.plugins:maven-deploy-plugin"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseEffectivePomPluginCoordinates(tc.xmlData)
			if tc.wantNil {
				assert.Nil(t, got)
				return
			}
			assert.NotNil(t, got, "non-empty XML must produce a non-nil allow-list")
			for _, k := range tc.included {
				assert.Contains(t, got, k)
			}
			for _, k := range tc.excluded {
				assert.NotContains(t, got, k)
			}
		})
	}
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

	existing := &xray.DepTreeNode{Types: jarType()}

	cases := []struct {
		name             string
		uniqueDeps       map[string]*xray.DepTreeNode
		dependencyTree   []*xrayUtils.GraphNode
		pluginDeps       map[string]*xray.DepTreeNode
		wantUniqueDeps   []string
		wantRootChildren map[string][]string
		wantExistingKept bool
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
				}
				assert.ElementsMatch(t, tc.wantRootChildren[root.Id], childIDs,
					"children attached to module root %s", root.Id)
			}
		})
	}
}

// TestTailStringValidUTF8 guards against splitting a multibyte rune mid-sequence.
// Without the rune-boundary nudge, byte slicing "xあy" with n=3 yields the
// continuation bytes "\x81\x82y" — invalid UTF-8.
func TestTailStringValidUTF8(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"shorter than n returns full string", "abc", 10, "abc"},
		{"pure ASCII tail", "abcdefghij", 4, "...ghij"},
		{"multibyte cut mid-rune produces valid UTF-8 (reviewer's repro)", "xあy", 3, "...y"},
		{"multibyte cut on rune boundary is preserved", "xあy", 4, "...あy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tailString(tc.in, tc.n)
			assert.Equal(t, tc.want, got)
			assert.True(t, utf8.ValidString(got), "result must be valid UTF-8, got %q", got)
		})
	}
}
