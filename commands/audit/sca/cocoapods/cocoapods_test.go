package cocoapods

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"

	"github.com/stretchr/testify/assert"
)

func TestBuildGoDependencyList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "cocoapods"))
	defer cleanUp()

	// Run getModulesDependencyTrees
	server := &config.ServerDetails{
		Url:            "https://api.cocoapods.here",
		ArtifactoryUrl: "https://api.cocoapods.here/artifactory",
		User:           "user",
		AccessToken:    "sdsdccs2232",
	}
	currentDir, err := coreutils.GetWorkingDirectory()
	packageName := filepath.Base(currentDir)
	packageInfo := fmt.Sprintf("%s:%s", packageName, VersionForMainModule)
	expectedUniqueDeps := []string{
		xrayutils.CocoapodsPackageTypeIdentifier + "AppAuth:1.7.5",
		xrayutils.CocoapodsPackageTypeIdentifier + "GoogleSignIn:6.2.4",
		xrayutils.CocoapodsPackageTypeIdentifier + "GTMAppAuth:1.3.1",
		xrayutils.CocoapodsPackageTypeIdentifier + "GTMSessionFetcher:2.3.0",
		xrayutils.CocoapodsPackageTypeIdentifier + packageInfo,
	}

	auditBasicParams := (&xrayutils.AuditBasicParams{}).SetServerDetails(server)
	rootNode, uniqueDeps, err := BuildDependencyTree(auditBasicParams)
	assert.NoError(t, err)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
	assert.NotEmpty(t, rootNode)

	assert.Equal(t, rootNode[0].Id, xrayutils.CocoapodsPackageTypeIdentifier+packageInfo)
	assert.Len(t, rootNode[0].Nodes, 4)

	child1 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "GTMSessionFetcher:2.3.0")
	assert.Len(t, child1.Nodes, 0)

	child2 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "GoogleSignIn:6.2.4")
	assert.Len(t, child2.Nodes, 2)
}

func TestGetTechDependencyLocation(t *testing.T) {
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "cocoapods"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	locations, err := GetTechDependencyLocation("AppAuth", "1.7.5", filepath.Join(currentDir, "Podfile.lock"))
	assert.NoError(t, err)
	fmt.Println(locations)
}
