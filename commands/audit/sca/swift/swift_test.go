package swift

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"

	"github.com/stretchr/testify/assert"
)

func TestBuildSwiftDependencyList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "swift"))
	defer cleanUp()

	// Run getModulesDependencyTrees
	server := &config.ServerDetails{
		Url:            "https://api.swift.here",
		ArtifactoryUrl: "https://api.swift.here/artifactory",
		User:           "user",
		AccessToken:    "sdsdccs2232",
	}
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	packageName := filepath.Base(currentDir)
	packageInfo := fmt.Sprintf("%s:%s", packageName, VersionForMainModule)
	expectedUniqueDeps := []string{
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-algorithms:1.2.0",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-numerics:1.0.2",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-nio-http2:1.19.0",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-atomics:1.2.0",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-collections:1.1.4",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-system:1.4.0",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-nio:2.76.1",
		techutils.Swift.GetPackageTypeId() + packageInfo,
	}

	auditBasicParams := (&xrayutils.AuditBasicParams{}).SetServerDetails(server)
	rootNode, uniqueDeps, err := BuildDependencyTree(auditBasicParams)
	assert.NoError(t, err)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
	assert.NotEmpty(t, rootNode)

	assert.Equal(t, rootNode[0].Id, techutils.Swift.GetPackageTypeId()+packageInfo)
	assert.Len(t, rootNode[0].Nodes, 9)

	child1 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "github.com/apple/swift-algorithms:1.2.0")
	assert.Len(t, child1.Nodes, 1)

	child2 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "github.com/apple/swift-numerics:1.0.2")
	assert.Len(t, child2.Nodes, 0)
}

func TestGetTechDependencyLocation(t *testing.T) {
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "swift"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	locations, err := GetTechDependencyLocation("github.com/apple/swift-algorithms", "1.2.0", filepath.Join(currentDir, "Package.swift"))
	assert.NoError(t, err)
	assert.Len(t, locations, 1)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.StartLine, 10)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.StartColumn, 10)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.EndLine, 31)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.EndColumn, 80)
	assert.Contains(t, *locations[0].PhysicalLocation.Region.Snippet.Text, "github.com/apple/swift-algorithms\", from: \"1.2.0\"")
}

func TestPodLineParse(t *testing.T) {
	var swiftPositions []*sarif.Location
	foundDependency, _, startLine, startCol := parsePodLine(".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\")", "github.com/apple/swift-algorithms", "1.2.0", "test", 0, 0, 0, 0, []string{".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\")"}, false, &swiftPositions)
	assert.Equal(t, foundDependency, false)
	assert.Equal(t, startLine, 0)
	assert.Equal(t, startCol, 23)
}

func TestPodLineParseFoundOnlyDependencyName(t *testing.T) {
	var swiftPositions []*sarif.Location
	foundDependency, _, startLine, startCol := parsePodLine(".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\")", "github.com/apple/swift-algorithms", "6.2.4", "test", 0, 0, 0, 0, []string{".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\")"}, false, &swiftPositions)
	assert.Equal(t, foundDependency, true)
	assert.Equal(t, startLine, 0)
	assert.Equal(t, startCol, 23)
}

func TestFixTechDependencySingleLocation(t *testing.T) {
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "swift"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = FixTechDependency("github.com/apple/swift-nio-http2", "1.0.0", "1.0.1", filepath.Join(currentDir, "Package.swift"))
	assert.NoError(t, err)
	file, err := os.ReadFile(filepath.Join(currentDir, "Package.swift"))
	assert.NoError(t, err)
	assert.Contains(t, string(file), ".package(url: \"https://github.com/apple/swift-nio-http2\", \"1.0.1\"..<\"1.19.1\")")
}

func TestFixTechDependencyNoLocations(t *testing.T) {
	_, cleanUp := sca.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "swift"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	err = FixTechDependency("github.com/apple/swift-nio-http2", "1.8.2", "1.8.3", filepath.Join(currentDir, "Package.swift"))
	assert.NoError(t, err)
	file, err := os.ReadFile(filepath.Join(currentDir, "Package.swift"))
	assert.NoError(t, err)
	assert.Contains(t, string(file), ".package(url: \"https://github.com/apple/swift-nio-http2\", \"1.0.0\"..<\"1.19.1\")")
}
