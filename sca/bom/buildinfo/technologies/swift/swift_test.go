package swift

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"

	"github.com/stretchr/testify/assert"
)

func TestBuildSwiftDependencyList(t *testing.T) {
	// Create and change directory to test workspace
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "swift"))
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
	packageName, err := GetMainPackageName(currentDir)
	assert.NoError(t, err)
	packageInfo := fmt.Sprintf("%s:%s", packageName, VersionForMainModule)
	expectedUniqueDeps := []string{
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-algorithms:1.2.0",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-numerics:1.0.2",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-nio-http2:1.19.0",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-atomics:1.2.0",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-collections:1.1.4",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-system:1.4.0",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-http-types:1.0.2",
		techutils.Swift.GetPackageTypeId() + "github.com/apple/swift-nio:2.76.1",
		techutils.Swift.GetPackageTypeId() + packageInfo,
	}

	auditBasicParams := (&xrayutils.AuditBasicParams{}).SetServerDetails(server)
	rootNode, uniqueDeps, err := BuildDependencyTree(auditBasicParams)
	assert.NoError(t, err)
	assert.ElementsMatch(t, uniqueDeps, expectedUniqueDeps, "First is actual, Second is Expected")
	assert.NotEmpty(t, rootNode)

	assert.Equal(t, rootNode[0].Id, techutils.Swift.GetPackageTypeId()+packageInfo)
	assert.Len(t, rootNode[0].Nodes, 11)

	child1 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "github.com/apple/swift-algorithms:1.2.0")
	assert.Len(t, child1.Nodes, 1)

	child2 := tests.GetAndAssertNode(t, rootNode[0].Nodes, "github.com/apple/swift-numerics:1.0.2")
	assert.Len(t, child2.Nodes, 0)
}

func TestGetTechDependencyLocation(t *testing.T) {
	_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "swift"))
	defer cleanUp()
	currentDir, err := coreutils.GetWorkingDirectory()
	assert.NoError(t, err)
	locations, err := GetTechDependencyLocation("github.com/apple/swift-algorithms", "1.1.0", filepath.Join(currentDir, "Package.swift"))
	assert.NoError(t, err)
	assert.Len(t, locations, 1)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.StartLine, 10)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.StartColumn, 10)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.EndLine, 31)
	assert.Equal(t, *locations[0].PhysicalLocation.Region.EndColumn, 80)
	assert.Contains(t, *locations[0].PhysicalLocation.Region.Snippet.Text, "github.com/apple/swift-algorithms\", from: \"1.1.0\"")
}

func TestSwiftLineParse(t *testing.T) {
	var swiftPositions []*sarif.Location
	foundDependency, _, startLine, startCol := parseSwiftLine(".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\")", "github.com/apple/swift-algorithms", "1.2.0", "test", 0, 0, 0, 0, []string{".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\")"}, false, &swiftPositions)
	assert.Equal(t, foundDependency, false)
	assert.Equal(t, startLine, 0)
	assert.Equal(t, startCol, 23)
}

func TestSwiftLineParseFoundOnlyDependencyName(t *testing.T) {
	var swiftPositions []*sarif.Location
	foundDependency, _, startLine, startCol := parseSwiftLine(".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\")", "github.com/apple/swift-algorithms", "6.2.4", "test", 0, 0, 0, 0, []string{".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\")"}, false, &swiftPositions)
	assert.Equal(t, foundDependency, true)
	assert.Equal(t, startLine, 0)
	assert.Equal(t, startCol, 23)
}

func TestFixTechDependencySingleLocation_Range(t *testing.T) {
	testCases := []struct {
		testName          string
		dependencyName    string
		dependencyVersion string
		fixVersion        string
		stringToFind      string
	}{
		{testName: "TestSingleLocation_Range", dependencyName: "github.com/apple/swift-nio-http2", dependencyVersion: "1.8.2", fixVersion: "1.8.3", stringToFind: ".package(url: \"https://github.com/apple/swift-nio-http2\", \"1.8.3\"..<\"1.19.1\")"},
		{testName: "TestSingleLocation_From", dependencyName: "github.com/apple/swift-algorithms", dependencyVersion: "1.1.0", fixVersion: "1.2.0", stringToFind: ".package(url: \"https://github.com/apple/swift-algorithms\", from: \"1.2.0\""},
		{testName: "TestSingleLocation_Exact", dependencyName: "github.com/apple/swift-http-types", dependencyVersion: "1.0.2", fixVersion: "1.0.3", stringToFind: ".package(url: \"https://github.com/apple/swift-http-types\", exact: \"1.0.3\""},
		{testName: "TestNoLocations_FixOutOfRange", dependencyName: "github.com/apple/swift-nio-http2", dependencyVersion: "1.8.3", fixVersion: "1.19.2", stringToFind: ".package(url: \"https://github.com/apple/swift-nio-http2\", \"1.0.0\"..<\"1.19.1\")"},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			_, cleanUp := technologies.CreateTestWorkspace(t, filepath.Join("projects", "package-managers", "swift"))
			defer cleanUp()
			currentDir, err := coreutils.GetWorkingDirectory()
			assert.NoError(t, err)
			err = FixTechDependency(tc.dependencyName, tc.dependencyVersion, tc.fixVersion, filepath.Join(currentDir, "Package.swift"))
			assert.NoError(t, err)
			file, err := os.ReadFile(filepath.Join(currentDir, "Package.swift"))
			assert.NoError(t, err)
			assert.Contains(t, string(file), tc.stringToFind)
		})
	}

}
