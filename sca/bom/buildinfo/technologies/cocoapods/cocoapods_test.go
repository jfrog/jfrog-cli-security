package cocoapods

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/stretchr/testify/assert"
)

func TestBuildCocoapodsDependencyList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "cocoapods"))
	defer cleanUp()

	// Run getModulesDependencyTrees
	server := &config.ServerDetails{
		Url:            "https://api.cocoapods.here",
		ArtifactoryUrl: "https://api.cocoapods.here/artifactory",
		User:           "user",
		AccessToken:    "sdsdccs2232",
	}
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	packageName := filepath.Base(currentDir)
	packageInfo := fmt.Sprintf("%s:%s", packageName, VersionForMainModule)
	expectedUniqueDeps := []string{
		techutils.Cocoapods.GetPackageTypeId() + "AppAuth:1.7.5",
		techutils.Cocoapods.GetPackageTypeId() + "AppAuth/Core:1.7.5",
		techutils.Cocoapods.GetPackageTypeId() + "AppAuth/ExternalUserAgent:1.7.5",
		techutils.Cocoapods.GetPackageTypeId() + "GoogleSignIn:6.2.4",
		techutils.Cocoapods.GetPackageTypeId() + "GTMAppAuth:1.3.1",
		techutils.Cocoapods.GetPackageTypeId() + "GTMSessionFetcher/Core:2.3.0",
		techutils.Cocoapods.GetPackageTypeId() + "nanopb:0.3.0",
		techutils.Cocoapods.GetPackageTypeId() + packageInfo,
	}

	auditBasicParams := technologies.BuildInfoBomGeneratorParams{ServerDetails: server}
	rootNode, uniqueDeps, err := BuildDependencyTree(auditBasicParams)
	assert.NoError(t, err)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
	assert.NotEmpty(t, rootNode)

	assert.Equal(t, rootNode[0].Id, techutils.Cocoapods.GetPackageTypeId()+packageInfo)
	assert.Len(t, rootNode[0].Nodes, 2)

	child1 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "nanopb:0.3.0")
	assert.Len(t, child1.Nodes, 0)

	child2 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "GoogleSignIn:6.2.4")
	assert.Len(t, child2.Nodes, 3)
}

func TestGetTechDependencyLocation(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "cocoapods"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	locations, err := GetTechDependencyLocation("GoogleSignIn", "6.2.4", filepath.Join(currentDir, "Podfile"))
	assert.NoError(t, err)
	assert.Len(t, locations, 1)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.StartLine, 4)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.StartColumn, 4)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.EndLine, 5)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.EndColumn, 30)
	assert.Contains(t, *locations[0].PhysicalLocation.Region.Snippet.Text, "GoogleSignIn', '~> 6.2.4'")
}

func TestPodLineParse(t *testing.T) {
	var podPositions []*sarif.Location
	foundDependency, _, startLine, startCol := parsePodLine("pod 'GoogleSignIn', '~> 6.2.4'", "GoogleSignIn", "6.2.4", "test", 0, 0, 0, 0, []string{"pod 'GoogleSignIn', '~> 6.2.4'"}, false, &podPositions)
	assert.Equal(t, foundDependency, false)
	assert.Equal(t, startLine, 0)
	assert.Equal(t, startCol, 5)
}

func TestPodLineParseFoundOnlyDependencyName(t *testing.T) {
	var podPositions []*sarif.Location
	foundDependency, _, startLine, startCol := parsePodLine("pod 'GoogleSignIn', '~> 6.2.3'", "GoogleSignIn", "6.2.4", "test", 0, 0, 0, 0, []string{"pod 'GoogleSignIn', '~> 6.2.3'"}, false, &podPositions)
	assert.Equal(t, foundDependency, true)
	assert.Equal(t, startLine, 0)
	assert.Equal(t, startCol, 5)
}

func TestFixTechDependencySingleLocation(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "cocoapods"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = FixTechDependency("GoogleSignIn", "6.2.4", "6.2.5", filepath.Join(currentDir, "Podfile"))
	assert.NoError(t, err)
	file, err := os.ReadFile(filepath.Join(currentDir, "Podfile"))
	assert.NoError(t, err)
	assert.Contains(t, string(file), "pod 'GoogleSignIn', '~> 6.2.5'")
}

func TestFixTechDependencyMultipleLocations(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "cocoapods"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = FixTechDependency("AppAuth", "1.7.5", "1.7.6", filepath.Join(currentDir, "Podfile"))
	assert.NoError(t, err)
	file, err := os.ReadFile(filepath.Join(currentDir, "Podfile"))
	assert.NoError(t, err)
	numAppearances := strings.Count(string(file), "pod 'AppAuth', '~> 1.7.6'")
	assert.Equal(t, numAppearances, 2)
}

func TestFixTechDependencyNoLocations(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "cocoapods"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = FixTechDependency("GoogleSignIn", "1.8.2", "1.8.3", filepath.Join(currentDir, "Podfile"))
	assert.NoError(t, err)
	file, err := os.ReadFile(filepath.Join(currentDir, "Podfile"))
	assert.NoError(t, err)
	assert.Contains(t, string(file), "pod 'GoogleSignIn', '~> 6.2.4'")
}
