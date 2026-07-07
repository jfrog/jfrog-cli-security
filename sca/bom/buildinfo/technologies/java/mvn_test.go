package java

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
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
            <id>jfrog-curation-audit</id>
            <username>testUser</username>
            <password>testPass</password>
        </server>
    </servers>
    <mirrors>
        <mirror>
            <id>jfrog-curation-audit</id>
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
                    <id>jfrog-curation-audit</id>
                    <name>mavenRepo</name>
                    <url>https://myartifactory.com/artifactory/api/curation/audit/testRepo</url>
                </repository>
            </repositories>
            <id>jfrog-curation-audit</id>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>jfrog-curation-audit</activeProfile>
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
		// Point to a non-existent path so the test always exercises the template
		// code path regardless of whether ~/.m2/settings.xml exists on the CI machine.
		userSettingsXmlPath: filepath.Join(t.TempDir(), "no-settings.xml"),
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

// TestCreateSettingsXmlPreservesExistingProxy verifies that when the user already has a
// settings.xml (containing e.g. a <proxies> block), the curation-audit temp file is
// seeded from that file so the proxy configuration is preserved.
func TestCreateSettingsXmlPreservesExistingProxy(t *testing.T) {
	t.Parallel()
	//#nosec G101 - test credentials only
	userSettings := `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd">
    <proxies>
        <proxy>
            <id>corp-proxy</id>
            <active>true</active>
            <protocol>http</protocol>
            <host>10.56.80.80</host>
            <port>8080</port>
        </proxy>
    </proxies>
</settings>`

	userSettingsPath := filepath.Join(t.TempDir(), "settings.xml")
	require.NoError(t, os.WriteFile(userSettingsPath, []byte(userSettings), 0600))

	mdt := MavenDepTreeManager{
		DepTreeManager: DepTreeManager{
			server: &config.ServerDetails{
				ArtifactoryUrl: "https://myartifactory.com/artifactory",
				User:           "testUser",
				Password:       "testPass",
			},
			depsRepo: "testRepo",
		},
		isCurationCmd:       true,
		userSettingsXmlPath: userSettingsPath,
	}

	tempDir := t.TempDir()
	require.NoError(t, mdt.createSettingsXmlWithConfiguredArtifactory(tempDir))

	resultBytes, err := os.ReadFile(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)
	result := string(resultBytes)

	// Proxy must be preserved from the user's original settings.
	assert.Contains(t, result, "10.56.80.80", "proxy host must be preserved")
	assert.Contains(t, result, "corp-proxy", "proxy id must be preserved")

	// Curation entries must be injected.
	assert.Contains(t, result, "api/curation/audit/testRepo", "curation mirror URL must be present")
	assert.Contains(t, result, "<mirrorOf>*</mirrorOf>", "catch-all mirror must be present")
	assert.Contains(t, result, "testUser", "username must be present")
	assert.Contains(t, result, "testPass", "password must be present")
	assert.Contains(t, result, "<activeProfile>"+curationSettingsID+"</activeProfile>", "activeProfile must be present")

	// The user's original settings.xml must be untouched.
	originalContent, err := os.ReadFile(userSettingsPath)
	require.NoError(t, err)
	assert.Equal(t, userSettings, string(originalContent), "user's settings.xml must not be modified")
}

// TestCreateSettingsXmlIdempotent verifies that calling createSettingsXmlWithConfiguredArtifactory
// multiple times with the same user settings does not create duplicate entries in the temp file.
func TestCreateSettingsXmlIdempotent(t *testing.T) {
	t.Parallel()
	//#nosec G101 - test credentials only
	userSettings := `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd">
    <proxies>
        <proxy>
            <id>corp-proxy</id>
            <active>true</active>
            <protocol>http</protocol>
            <host>10.56.80.80</host>
            <port>8080</port>
        </proxy>
    </proxies>
</settings>`

	userSettingsPath := filepath.Join(t.TempDir(), "settings.xml")
	require.NoError(t, os.WriteFile(userSettingsPath, []byte(userSettings), 0600))

	mdt := MavenDepTreeManager{
		DepTreeManager: DepTreeManager{
			server: &config.ServerDetails{
				ArtifactoryUrl: "https://myartifactory.com/artifactory",
				User:           "testUser",
				Password:       "testPass",
			},
			depsRepo: "testRepo",
		},
		isCurationCmd:       true,
		userSettingsXmlPath: userSettingsPath,
	}

	tempDir := t.TempDir()
	// Run twice — each invocation reads the unchanged user settings and writes to tempDir.
	require.NoError(t, mdt.createSettingsXmlWithConfiguredArtifactory(tempDir))

	firstRun, err := os.ReadFile(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)

	require.NoError(t, mdt.createSettingsXmlWithConfiguredArtifactory(tempDir))

	secondRun, err := os.ReadFile(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)

	// Both runs must produce identical output — no duplicate entries.
	assert.Equal(t, string(firstRun), string(secondRun), "second run must produce identical output (no duplicates)")

	result := string(secondRun)
	// Structural uniqueness: exactly one <server>, one <mirror>, one top-level <profile>,
	// and one <activeProfile> entry with the curation ID.
	assert.Equal(t, 1, strings.Count(result, "<server>"), "expected exactly one <server> block")
	assert.Equal(t, 1, strings.Count(result, "<mirror>"), "expected exactly one <mirror> block")
	assert.Equal(t, 1, strings.Count(result, "<activeProfile>"+curationSettingsID+"</activeProfile>"),
		"expected exactly one curation <activeProfile>")
}

// TestCreateSettingsXmlCurationMirrorIsFirst verifies that when the user already has a
// catch-all <mirror> (mirrorOf=*), the curation mirror is inserted first so Maven's
// document-order selection routes through curation. It also covers the id-collision case:
// the pre-existing mirror uses id="artifactory", which must not be overwritten.
func TestCreateSettingsXmlCurationMirrorIsFirst(t *testing.T) {
	t.Parallel()
	userSettings := `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd">
    <mirrors>
        <mirror>
            <id>artifactory</id>
            <url>https://existing-internal.corp/artifactory/repo</url>
            <mirrorOf>*</mirrorOf>
        </mirror>
    </mirrors>
</settings>`

	userSettingsPath := filepath.Join(t.TempDir(), "settings.xml")
	require.NoError(t, os.WriteFile(userSettingsPath, []byte(userSettings), 0600))

	mdt := MavenDepTreeManager{
		DepTreeManager: DepTreeManager{
			server: &config.ServerDetails{
				ArtifactoryUrl: "https://myartifactory.com/artifactory",
				User:           "testUser",
				Password:       "testPass",
			},
			depsRepo: "testRepo",
		},
		isCurationCmd:       true,
		userSettingsXmlPath: userSettingsPath,
	}

	tempDir := t.TempDir()
	require.NoError(t, mdt.createSettingsXmlWithConfiguredArtifactory(tempDir))

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromFile(filepath.Join(tempDir, settingsXmlFile)))
	mirrorEls := doc.SelectElement("settings").SelectElement("mirrors").SelectElements("mirror")
	require.Len(t, mirrorEls, 2, "both the curation mirror and the user's mirror must be present")

	// The curation mirror must come first so Maven picks it for the '*' match.
	firstID := mirrorEls[0].SelectElement("id").Text()
	assert.Equal(t, curationSettingsID, firstID, "curation mirror must be the first <mirror>")
	assert.Contains(t, mirrorEls[0].SelectElement("url").Text(), "api/curation/audit/testRepo")

	// The user's pre-existing mirror (id=artifactory) must be preserved untouched.
	assert.Equal(t, "artifactory", mirrorEls[1].SelectElement("id").Text())
	assert.Equal(t, "https://existing-internal.corp/artifactory/repo", mirrorEls[1].SelectElement("url").Text())
}

// TestCreateSettingsXmlFromExistingIsPrivate verifies the generated temp settings.xml,
// which carries credentials, is written with restrictive 0600 permissions.
func TestCreateSettingsXmlFromExistingIsPrivate(t *testing.T) {
	t.Parallel()
	userSettings := `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd">
</settings>`

	userSettingsPath := filepath.Join(t.TempDir(), "settings.xml")
	require.NoError(t, os.WriteFile(userSettingsPath, []byte(userSettings), 0600))

	mdt := MavenDepTreeManager{
		DepTreeManager: DepTreeManager{
			server: &config.ServerDetails{
				ArtifactoryUrl: "https://myartifactory.com/artifactory",
				User:           "testUser",
				Password:       "testPass",
			},
			depsRepo: "testRepo",
		},
		isCurationCmd:       true,
		userSettingsXmlPath: userSettingsPath,
	}

	tempDir := t.TempDir()
	require.NoError(t, mdt.createSettingsXmlWithConfiguredArtifactory(tempDir))

	info, err := os.Stat(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)
	if !coreutils.IsWindows() {
		// Windows does not enforce Unix permission bits — skip the mode check there.
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "temp settings.xml must be private (0600)")
	}
}

// TestCreateSettingsXmlFallsBackWhenNoHome verifies that an unresolvable home directory
// falls back to the built-in template instead of failing the whole scan.
func TestCreateSettingsXmlFallsBackWhenNoHome(t *testing.T) {
	if coreutils.IsWindows() {
		t.Skip("os.UserHomeDir resolves home from different env vars on Windows")
	}
	// Empty HOME makes os.UserHomeDir return an error on unix-like systems.
	t.Setenv("HOME", "")

	mdt := MavenDepTreeManager{
		DepTreeManager: DepTreeManager{
			server: &config.ServerDetails{
				ArtifactoryUrl: "https://myartifactory.com/artifactory",
				User:           "testUser",
				Password:       "testPass",
			},
			depsRepo: "testRepo",
		},
		// isCurationCmd must be true so this test actually reaches the os.UserHomeDir()
		// lookup below; non-curation runs short-circuit to the template before that point.
		isCurationCmd: true,
		// userSettingsXmlPath left empty so the default (home-based) lookup runs and fails.
	}

	tempDir := t.TempDir()
	require.NoError(t, mdt.createSettingsXmlWithConfiguredArtifactory(tempDir))

	actualContent, err := os.ReadFile(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)
	actualContent = []byte(strings.ReplaceAll(string(actualContent), "\r\n", "\n"))
	// Template fallback for a curation run still uses the curation-specific id.
	assert.Equal(t, settingsXmlWithUsernameAndPasswordAndCurationDedicatedAPi, string(actualContent))
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

// TestCreateSettingsXmlMalformedFallsBackToTemplate verifies that a settings.xml that
// cannot be parsed (e.g. mid-write by an IDE or CI script) is treated as absent and the
// built-in template is used, rather than aborting the whole scan (Finding 5).
func TestCreateSettingsXmlMalformedFallsBackToTemplate(t *testing.T) {
	t.Parallel()
	malformed := `<?xml version="1.0"?><settings><UNCLOSED`
	userSettingsPath := filepath.Join(t.TempDir(), "settings.xml")
	require.NoError(t, os.WriteFile(userSettingsPath, []byte(malformed), 0600))

	mdt := MavenDepTreeManager{
		isCurationCmd:       true,
		userSettingsXmlPath: userSettingsPath,
		DepTreeManager: DepTreeManager{
			server:   &config.ServerDetails{ArtifactoryUrl: "https://example.jfrog.io/artifactory/", User: "u", Password: "p"},
			depsRepo: "testRepo",
		},
	}
	tempDir := t.TempDir()
	err := mdt.createSettingsXmlWithConfiguredArtifactory(tempDir)
	require.NoError(t, err, "malformed user settings.xml must not abort the scan")

	result, err := os.ReadFile(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)
	assert.Contains(t, string(result), "testRepo", "template output must contain the repo")
}

// TestCreateSettingsXmlNoRootFallsBackToTemplate verifies that a settings.xml missing the
// <settings> root element is treated as absent and falls back to the built-in template.
func TestCreateSettingsXmlNoRootFallsBackToTemplate(t *testing.T) {
	t.Parallel()
	noRoot := `<?xml version="1.0"?><notSettings><foo/></notSettings>`
	userSettingsPath := filepath.Join(t.TempDir(), "settings.xml")
	require.NoError(t, os.WriteFile(userSettingsPath, []byte(noRoot), 0600))

	mdt := MavenDepTreeManager{
		isCurationCmd:       true,
		userSettingsXmlPath: userSettingsPath,
		DepTreeManager: DepTreeManager{
			server:   &config.ServerDetails{ArtifactoryUrl: "https://example.jfrog.io/artifactory/", User: "u", Password: "p"},
			depsRepo: "testRepo",
		},
	}
	tempDir := t.TempDir()
	err := mdt.createSettingsXmlWithConfiguredArtifactory(tempDir)
	require.NoError(t, err, "settings.xml with no <settings> root must not abort the scan")

	result, err := os.ReadFile(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)
	assert.Contains(t, string(result), "testRepo")
}

// TestNonCurationSkipsUserSettingsXml verifies that a plain jf audit --deps-repo run
// uses the built-in template directly without consulting ~/.m2/settings.xml, so the
// jf audit code path is fully unaffected by the proxy-preservation feature (Finding 6).
func TestNonCurationSkipsUserSettingsXml(t *testing.T) {
	t.Parallel()
	// Point userSettingsXmlPath at a file with valid but distinct proxy config.
	// If the code incorrectly reads it, the proxy host would appear in the output.
	userSettings := `<?xml version="1.0"?><settings><proxies><proxy><id>should-not-appear</id><host>1.2.3.4</host></proxy></proxies></settings>`
	userSettingsPath := filepath.Join(t.TempDir(), "settings.xml")
	require.NoError(t, os.WriteFile(userSettingsPath, []byte(userSettings), 0600))

	mdt := MavenDepTreeManager{
		isCurationCmd:       false, // plain jf audit
		userSettingsXmlPath: userSettingsPath,
		DepTreeManager: DepTreeManager{
			server:   &config.ServerDetails{ArtifactoryUrl: "https://example.jfrog.io/artifactory/", User: "u", Password: "p"},
			depsRepo: "testRepo",
		},
	}
	tempDir := t.TempDir()
	require.NoError(t, mdt.createSettingsXmlWithConfiguredArtifactory(tempDir))

	result, err := os.ReadFile(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)
	assert.NotContains(t, string(result), "should-not-appear", "non-curation run must not seed from user settings.xml")
	assert.NotContains(t, string(result), "1.2.3.4", "non-curation run must not seed from user settings.xml")
}

// TestCreateSettingsXmlStatErrorFallsBackToTemplate verifies that a stat error on
// ~/.m2/settings.xml (e.g. EACCES on a volume owned by a different UID in containerised
// CI) falls back to the built-in template rather than aborting the scan.
func TestCreateSettingsXmlStatErrorFallsBackToTemplate(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("running as root — permission checks do not apply")
	}
	// Create a directory where settings.xml would live, then chmod it 000 so stat fails.
	unreadableDir := t.TempDir()
	userSettingsPath := filepath.Join(unreadableDir, "settings.xml")
	require.NoError(t, os.WriteFile(userSettingsPath, []byte(`<?xml version="1.0"?><settings></settings>`), 0600))
	require.NoError(t, os.Chmod(unreadableDir, 0000))
	defer func() { _ = os.Chmod(unreadableDir, 0700) }()

	mdt := MavenDepTreeManager{
		isCurationCmd:       true,
		userSettingsXmlPath: userSettingsPath,
		DepTreeManager: DepTreeManager{
			server:   &config.ServerDetails{ArtifactoryUrl: "https://example.jfrog.io/artifactory/", User: "u", Password: "p"},
			depsRepo: "testRepo",
		},
	}
	tempDir := t.TempDir()
	err := mdt.createSettingsXmlWithConfiguredArtifactory(tempDir)
	require.NoError(t, err, "stat error on settings.xml must not abort the scan")

	result, err := os.ReadFile(filepath.Join(tempDir, settingsXmlFile))
	require.NoError(t, err)
	assert.Contains(t, string(result), "testRepo")
}
