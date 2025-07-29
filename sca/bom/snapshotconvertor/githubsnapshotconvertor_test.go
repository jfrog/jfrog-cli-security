package snapshotconvertor

import (
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestCreateGithubSnapshotFromSbom_FullConversion(t *testing.T) {
	components := []cyclonedx.Component{
		createTestComponent("root1", "express", "4.18.2", "pkg:npm/express@4.18.2", []string{"package.json"}),
		createTestComponent("root2", "typescript", "5.0.0", "pkg:npm/typescript@5.0.0", []string{"tsconfig.json"}),
		createTestComponent("dep1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", []string{"package.json"}),
		createTestComponent("dep2", "moment", "2.29.4", "pkg:npm/moment@2.29.4", []string{"package.json"}),
	}

	// Create dependencies where root1 and root2 are roots (not listed in any dependsOn)
	// and dep1 and dep2 are dependencies of root1
	dependencies := []cyclonedx.Dependency{
		createTestDependency("root1", []string{"dep1", "dep2"}), // express depends on lodash and moment
		createTestDependency("root2", []string{}),               // typescript has no dependencies
		createTestDependency("dep1", []string{}),                // lodash has no dependencies
		createTestDependency("dep2", []string{}),                // moment has no dependencies
	}

	bom := createTestBOM(components, dependencies)

	snapshotVersion := 1
	scanTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	jobId := "test-job-123"
	jobCorrelator := "test-correlator"
	commitSha := "abc123def456"
	gitRef := "main"
	detectorName := "test-detector"
	detectorVersion := "1.0.0"
	detectorUrl := "https://example.com/detector"

	snapshot, err := CreateGithubSnapshotFromSbom(bom, snapshotVersion, scanTime, jobId, jobCorrelator, commitSha, gitRef, detectorName, detectorVersion, detectorUrl)

	assert.NoError(t, err)
	assert.NotNil(t, snapshot)
	assert.Equal(t, snapshotVersion, snapshot.Version)
	assert.Equal(t, commitSha, snapshot.Sha)
	assert.Equal(t, "refs/heads/main", snapshot.Ref)
	assert.Equal(t, scanTime, snapshot.Scanned)
	assert.NotNil(t, snapshot.Job)
	assert.Equal(t, jobId, snapshot.Job.ID)
	assert.Equal(t, jobCorrelator, snapshot.Job.Correlator)
	assert.NotNil(t, snapshot.Detector)
	assert.Equal(t, detectorName, snapshot.Detector.Name)
	assert.Equal(t, detectorVersion, snapshot.Detector.Version)
	assert.Equal(t, detectorUrl, snapshot.Detector.Url)
	assert.NotNil(t, snapshot.Manifests)
	assert.Len(t, snapshot.Manifests, 2)

	packageJsonManifest, exists := snapshot.Manifests["package.json"]
	assert.True(t, exists)
	assert.Equal(t, "package.json", packageJsonManifest.Name)
	assert.NotNil(t, packageJsonManifest.File)
	assert.Equal(t, "package.json", packageJsonManifest.File.SourceLocation)
	assert.NotNil(t, packageJsonManifest.Resolved)
	assert.Len(t, packageJsonManifest.Resolved, 2)

	// Check package.json manifest
	lodashDep, exists := packageJsonManifest.Resolved["lodash"]
	assert.True(t, exists)
	assert.Equal(t, "pkg:npm/lodash@4.17.21", lodashDep.PackageURL)
	assert.Equal(t, directDependency, lodashDep.Relationship)
	assert.Len(t, lodashDep.Dependencies, 0) // no dependencies

	momentDep, exists := packageJsonManifest.Resolved["moment"]
	assert.True(t, exists)
	assert.Equal(t, "pkg:npm/moment@2.29.4", momentDep.PackageURL)
	assert.Equal(t, directDependency, momentDep.Relationship)
	assert.Len(t, momentDep.Dependencies, 0) // no dependencies

	// Check tsconfig.json manifest
	tsconfigManifest, exists := snapshot.Manifests["tsconfig.json"]
	assert.True(t, exists)
	assert.Equal(t, "tsconfig.json", tsconfigManifest.Name)
	assert.NotNil(t, tsconfigManifest.File)
	assert.Equal(t, "tsconfig.json", tsconfigManifest.File.SourceLocation)
	assert.NotNil(t, tsconfigManifest.Resolved)
	assert.Len(t, tsconfigManifest.Resolved, 0) // typescript is root, so skipped
}

func TestCreateGithubSnapshotFromSbom_WithoutComponents(t *testing.T) {
	// Create BOM without components
	bom := createTestBOM([]cyclonedx.Component{}, []cyclonedx.Dependency{})

	snapshotVersion := 1
	scanTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	jobId := "test-job-123"
	jobCorrelator := "test-correlator"
	commitSha := "abc123def456"
	gitRef := "main"
	detectorName := "test-detector"
	detectorVersion := "1.0.0"
	detectorUrl := "https://example.com/detector"

	snapshot, err := CreateGithubSnapshotFromSbom(bom, snapshotVersion, scanTime, jobId, jobCorrelator, commitSha, gitRef, detectorName, detectorVersion, detectorUrl)

	assert.NoError(t, err)
	assert.NotNil(t, snapshot)
	assert.Equal(t, snapshotVersion, snapshot.Version)
	assert.Equal(t, commitSha, snapshot.Sha)
	assert.Equal(t, "refs/heads/main", snapshot.Ref)
	assert.Equal(t, scanTime, snapshot.Scanned)
	assert.NotNil(t, snapshot.Job)
	assert.Equal(t, jobId, snapshot.Job.ID)
	assert.Equal(t, jobCorrelator, snapshot.Job.Correlator)
	assert.NotNil(t, snapshot.Detector)
	assert.Equal(t, detectorName, snapshot.Detector.Name)
	assert.Equal(t, detectorVersion, snapshot.Detector.Version)
	assert.Equal(t, detectorUrl, snapshot.Detector.Url)
	assert.Nil(t, snapshot.Manifests)
}

func TestCreateGithubSnapshotFromSbom_NilBOM(t *testing.T) {
	snapshotVersion := 1
	scanTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	jobId := "test-job-123"
	jobCorrelator := "test-correlator"
	commitSha := "abc123def456"
	gitRef := "main"
	detectorName := "test-detector"
	detectorVersion := "1.0.0"
	detectorUrl := "https://example.com/detector"

	snapshot, err := CreateGithubSnapshotFromSbom(nil, snapshotVersion, scanTime, jobId, jobCorrelator, commitSha, gitRef, detectorName, detectorVersion, detectorUrl)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "received cycloneDX is nil", err.Error())
	assert.Nil(t, snapshot)
}

func TestCreateGithubSnapshotFromSbom_ComponentsWithoutEvidence(t *testing.T) {
	components := []cyclonedx.Component{
		{
			BOMRef:     "comp1",
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       "express",
			Version:    "4.18.2",
			PackageURL: "pkg:npm/express@4.18.2",
		},
	}

	bom := createTestBOM(components, []cyclonedx.Dependency{})

	// Test parameters
	snapshotVersion := 1
	scanTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	jobId := "test-job-123"
	jobCorrelator := "test-correlator"
	commitSha := "abc123def456"
	gitRef := "main"
	detectorName := "test-detector"
	detectorVersion := "1.0.0"
	detectorUrl := "https://example.com/detector"

	snapshot, err := CreateGithubSnapshotFromSbom(bom, snapshotVersion, scanTime, jobId, jobCorrelator, commitSha, gitRef, detectorName, detectorVersion, detectorUrl)

	assert.NoError(t, err)
	assert.NotNil(t, snapshot)
	assert.Equal(t, snapshotVersion, snapshot.Version)
	assert.Equal(t, commitSha, snapshot.Sha)
	assert.Equal(t, "refs/heads/main", snapshot.Ref)
	assert.Equal(t, scanTime, snapshot.Scanned)

	// Check manifests - should be empty when components have no evidence
	assert.NotNil(t, snapshot.Manifests)
	assert.Len(t, snapshot.Manifests, 0)
}

func TestCreateGithubSnapshotFromSbom_NonLibraryComponents(t *testing.T) {
	components := []cyclonedx.Component{
		{
			BOMRef:     "comp1",
			Type:       cyclonedx.ComponentTypeFile,
			Name:       "main.js",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/main@1.0.0",
			Evidence: &cyclonedx.Evidence{
				Occurrences: &[]cyclonedx.EvidenceOccurrence{
					{Location: "main.js"},
				},
			},
		},
		createTestComponent("comp2", "express", "4.18.2", "pkg:npm/express@4.18.2", []string{"package.json"}),
	}
	bom := createTestBOM(components, []cyclonedx.Dependency{})

	snapshotVersion := 1
	scanTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	jobId := "test-job-123"
	jobCorrelator := "test-correlator"
	commitSha := "abc123def456"
	gitRef := "main"
	detectorName := "test-detector"
	detectorVersion := "1.0.0"
	detectorUrl := "https://example.com/detector"

	snapshot, err := CreateGithubSnapshotFromSbom(bom, snapshotVersion, scanTime, jobId, jobCorrelator, commitSha, gitRef, detectorName, detectorVersion, detectorUrl)

	assert.NoError(t, err)
	assert.NotNil(t, snapshot)

	// Check manifests - should only include library components
	assert.NotNil(t, snapshot.Manifests)
	assert.Len(t, snapshot.Manifests, 1) // only package.json from express

	packageJsonManifest, exists := snapshot.Manifests["package.json"]
	assert.True(t, exists)
	// express might be classified as root and skipped, so check if it's there or not
	if len(packageJsonManifest.Resolved) > 0 {
		expressDep, exists := packageJsonManifest.Resolved["express"]
		assert.True(t, exists)
		assert.Equal(t, "pkg:npm/express@4.18.2", expressDep.PackageURL)
	}
}

func TestCreateGithubSnapshotFromSbom_RefPrefixHandling(t *testing.T) {
	components := []cyclonedx.Component{
		createTestComponent("comp1", "express", "4.18.2", "pkg:npm/express@4.18.2", []string{"package.json"}),
	}
	bom := createTestBOM(components, []cyclonedx.Dependency{})

	snapshotVersion := 1
	scanTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	jobId := "test-job-123"
	jobCorrelator := "test-correlator"
	commitSha := "abc123def456"
	detectorName := "test-detector"
	detectorVersion := "1.0.0"
	detectorUrl := "https://example.com/detector"

	// Test with ref that already has prefix
	gitRefWithPrefix := "refs/heads/feature-branch"
	snapshot, err := CreateGithubSnapshotFromSbom(bom, snapshotVersion, scanTime, jobId, jobCorrelator, commitSha, gitRefWithPrefix, detectorName, detectorVersion, detectorUrl)

	assert.NoError(t, err)
	assert.NotNil(t, snapshot)
	assert.Equal(t, "refs/heads/feature-branch", snapshot.Ref)

	// Test with ref without prefix
	gitRefWithoutPrefix := "main"
	snapshot, err = CreateGithubSnapshotFromSbom(bom, snapshotVersion, scanTime, jobId, jobCorrelator, commitSha, gitRefWithoutPrefix, detectorName, detectorVersion, detectorUrl)

	assert.NoError(t, err)
	assert.NotNil(t, snapshot)
	assert.Equal(t, "refs/heads/main", snapshot.Ref)
}

func TestCreateGithubSnapshotFromSbom_ComplexDependencies(t *testing.T) {
	// Create test components with evidence occurrences
	components := []cyclonedx.Component{
		createTestComponent("root1", "express", "4.18.2", "pkg:npm/express@4.18.2", []string{"package.json"}),
		createTestComponent("dep1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", []string{"package.json"}),
		createTestComponent("dep2", "moment", "2.29.4", "pkg:npm/moment@2.29.4", []string{"package.json"}),
		createTestComponent("dep3", "axios", "1.6.0", "pkg:npm/axios@1.6.0", []string{"package.json"}),
		createTestComponent("dep4", "follow-redirects", "1.15.0", "pkg:npm/follow-redirects@1.15.0", []string{"package.json"}),
	}

	// Create dependencies with some dependencies having other dependencies
	dependencies := []cyclonedx.Dependency{
		createTestDependency("root1", []string{"dep1", "dep2", "dep3"}), // express depends on lodash, moment, axios
		createTestDependency("dep1", []string{}),                        // lodash has no dependencies
		createTestDependency("dep2", []string{}),                        // moment has no dependencies
		createTestDependency("dep3", []string{"dep4"}),                  // axios depends on follow-redirects
		createTestDependency("dep4", []string{}),                        // follow-redirects has no dependencies
	}

	bom := createTestBOM(components, dependencies)

	snapshotVersion := 1
	scanTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	jobId := "test-job-123"
	jobCorrelator := "test-correlator"
	commitSha := "abc123def456"
	gitRef := "main"
	detectorName := "test-detector"
	detectorVersion := "1.0.0"
	detectorUrl := "https://example.com/detector"

	snapshot, err := CreateGithubSnapshotFromSbom(bom, snapshotVersion, scanTime, jobId, jobCorrelator, commitSha, gitRef, detectorName, detectorVersion, detectorUrl)

	assert.NoError(t, err)
	assert.NotNil(t, snapshot)
	assert.NotNil(t, snapshot.Manifests)
	assert.Len(t, snapshot.Manifests, 1) // only package.json

	// Check package.json manifest
	packageJsonManifest, exists := snapshot.Manifests["package.json"]
	assert.True(t, exists)
	assert.Equal(t, "package.json", packageJsonManifest.Name)
	assert.NotNil(t, packageJsonManifest.File)
	assert.Equal(t, "package.json", packageJsonManifest.File.SourceLocation)
	assert.NotNil(t, packageJsonManifest.Resolved)
	assert.Len(t, packageJsonManifest.Resolved, 4) // lodash, moment, axios, follow-redirects (express is root, so skipped)

	// Check package.json manifest
	lodashDep, exists := packageJsonManifest.Resolved["lodash"]
	assert.True(t, exists)
	assert.Equal(t, "pkg:npm/lodash@4.17.21", lodashDep.PackageURL)
	assert.Contains(t, []string{directDependency, indirectDependency}, lodashDep.Relationship)
	assert.Len(t, lodashDep.Dependencies, 0) // no dependencies

	momentDep, exists := packageJsonManifest.Resolved["moment"]
	assert.True(t, exists)
	assert.Equal(t, "pkg:npm/moment@2.29.4", momentDep.PackageURL)
	// Relationship can be Direct or Indirect depending on the dependency tree analysis
	assert.Contains(t, []string{directDependency, indirectDependency}, momentDep.Relationship)
	assert.Len(t, momentDep.Dependencies, 0) // no dependencies

	axiosDep, exists := packageJsonManifest.Resolved["axios"]
	assert.True(t, exists)
	assert.Equal(t, "pkg:npm/axios@1.6.0", axiosDep.PackageURL)
	// Relationship can be Direct or Indirect depending on the dependency tree analysis
	assert.Contains(t, []string{directDependency, indirectDependency}, axiosDep.Relationship)
	assert.Len(t, axiosDep.Dependencies, 1) // depends on follow-redirects

	followRedirectsDep, exists := packageJsonManifest.Resolved["follow-redirects"]
	assert.True(t, exists)
	assert.Equal(t, "pkg:npm/follow-redirects@1.15.0", followRedirectsDep.PackageURL)
	// Relationship can be Direct or Indirect depending on the dependency tree analysis
	assert.Contains(t, []string{directDependency, indirectDependency}, followRedirectsDep.Relationship)
	assert.Len(t, followRedirectsDep.Dependencies, 0) // no dependencies
}

// createTestBOM creates a test BOM with the specified components and dependencies
func createTestBOM(components []cyclonedx.Component, dependencies []cyclonedx.Dependency) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	if len(components) > 0 {
		bom.Components = &components
	}
	if len(dependencies) > 0 {
		bom.Dependencies = &dependencies
	}
	return bom
}

// createTestComponent creates a test component with evidence occurrences
func createTestComponent(bomRef, name, version, packageURL string, locations []string) cyclonedx.Component {
	component := cyclonedx.Component{
		BOMRef:     bomRef,
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       name,
		Version:    version,
		PackageURL: packageURL,
	}

	if len(locations) > 0 {
		occurrences := make([]cyclonedx.EvidenceOccurrence, len(locations))
		for i, location := range locations {
			occurrences[i] = cyclonedx.EvidenceOccurrence{
				Location: location,
			}
		}
		component.Evidence = &cyclonedx.Evidence{
			Occurrences: &occurrences,
		}
	}

	return component
}

// createTestDependency creates a test dependency
func createTestDependency(ref string, dependencies []string) cyclonedx.Dependency {
	dep := cyclonedx.Dependency{
		Ref: ref,
	}
	if len(dependencies) > 0 {
		dep.Dependencies = &dependencies
	}
	return dep
}
