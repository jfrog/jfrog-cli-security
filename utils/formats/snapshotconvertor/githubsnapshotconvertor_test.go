package snapshotconvertor

import (
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/stretchr/testify/assert"
)

const (
	testSnapshotVersion = 1
	testJobId           = "test-job-123"
	testJobCorrelator   = "test-correlator"
	testCommitSha       = "abc123def456"
	testGitRef          = "refs/heads/main"
	testDetectorName    = "test-detector"
	testDetectorVersion = "1.0.0"
	testDetectorUrl     = "https://example.com/detector"
)

func TestCreateGithubSnapshotFromSbom(t *testing.T) {
	testCases := []struct {
		name              string
		components        []cyclonedx.Component
		dependencies      []cyclonedx.Dependency
		gitRef            string
		expectedManifests map[string]vcsclient.Manifest
		errorExpected     bool
		validateSnapshot  func(*testing.T, *vcsclient.SbomSnapshot)
	}{
		{
			name: "Full valid conversion with multiple components",
			components: []cyclonedx.Component{
				createTestComponent("root1", "express", "4.18.2", "pkg:npm/express@4.18.2", []string{"package.json"}),
				createTestComponent("root2", "typescript", "5.0.0", "pkg:npm/typescript@5.0.0", []string{"tsconfig.json"}),
				createTestComponent("dep1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", []string{"package.json"}),
				createTestComponent("dep2", "moment", "2.29.4", "pkg:npm/moment@2.29.4", []string{"package.json"}),
			},
			dependencies: []cyclonedx.Dependency{
				createTestDependency("root1", []string{"dep1", "dep2"}),
				createTestDependency("root2", []string{}),
				createTestDependency("dep1", []string{}),
				createTestDependency("dep2", []string{}),
			},
			gitRef: testGitRef,
			validateSnapshot: func(t *testing.T, snapshot *vcsclient.SbomSnapshot) {
				assert.NotNil(t, snapshot.Manifests)
				assert.Len(t, snapshot.Manifests, 2)

				packageJsonManifest, exists := snapshot.Manifests["package.json"]
				assert.True(t, exists)
				assert.Equal(t, "package.json", packageJsonManifest.Name)
				assert.NotNil(t, packageJsonManifest.File)
				assert.Equal(t, "package.json", packageJsonManifest.File.SourceLocation)
				assert.NotNil(t, packageJsonManifest.Resolved)
				assert.Len(t, packageJsonManifest.Resolved, 2)

				// Check package.json manifest dependencies
				lodashDep, exists := packageJsonManifest.Resolved["lodash"]
				assert.True(t, exists)
				assert.Equal(t, "pkg:npm/lodash@4.17.21", lodashDep.PackageURL)
				assert.Equal(t, directDependency, lodashDep.Relationship)
				assert.Len(t, lodashDep.Dependencies, 0)

				momentDep, exists := packageJsonManifest.Resolved["moment"]
				assert.True(t, exists)
				assert.Equal(t, "pkg:npm/moment@2.29.4", momentDep.PackageURL)
				assert.Equal(t, directDependency, momentDep.Relationship)
				assert.Len(t, momentDep.Dependencies, 0)

				// Check tsconfig.json manifest
				tsconfigManifest, exists := snapshot.Manifests["tsconfig.json"]
				assert.True(t, exists)
				assert.Equal(t, "tsconfig.json", tsconfigManifest.Name)
				assert.NotNil(t, tsconfigManifest.File)
				assert.Equal(t, "tsconfig.json", tsconfigManifest.File.SourceLocation)
				assert.NotNil(t, tsconfigManifest.Resolved)
				assert.Len(t, tsconfigManifest.Resolved, 0) // typescript is root, so skipped
			},
		},
		{
			name:         "BOM without components",
			components:   []cyclonedx.Component{},
			dependencies: []cyclonedx.Dependency{},
			gitRef:       testGitRef,
			validateSnapshot: func(t *testing.T, snapshot *vcsclient.SbomSnapshot) {
				assert.Nil(t, snapshot.Manifests)
			},
		},
		{
			name:          "Nil BOM",
			components:    nil,
			dependencies:  nil,
			gitRef:        testGitRef,
			errorExpected: true,
		},
		{
			name: "Components without evidence",
			components: []cyclonedx.Component{
				{
					BOMRef:     "comp1",
					Type:       cyclonedx.ComponentTypeLibrary,
					Name:       "express",
					Version:    "4.18.2",
					PackageURL: "pkg:npm/express@4.18.2",
				},
			},
			dependencies: []cyclonedx.Dependency{},
			gitRef:       testGitRef,
			validateSnapshot: func(t *testing.T, snapshot *vcsclient.SbomSnapshot) {
				// Check manifests - should be empty when components have no evidence
				assert.NotNil(t, snapshot.Manifests)
				assert.Len(t, snapshot.Manifests, 0)
			},
		},
		{
			name: "Non-library components",
			components: []cyclonedx.Component{
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
				createTestComponent("root1", "express", "4.18.2", "pkg:npm/express@4.18.2", []string{"package.json"}),
				createTestComponent("dep1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", []string{"package.json"}),
			},
			dependencies: []cyclonedx.Dependency{
				createTestDependency("root1", []string{"dep1"}), // express depends on lodash
				createTestDependency("dep1", []string{}),        // lodash has no dependencies
			},
			gitRef: testGitRef,
			validateSnapshot: func(t *testing.T, snapshot *vcsclient.SbomSnapshot) {
				// Check manifests - should only include library components
				assert.NotNil(t, snapshot.Manifests)
				assert.Len(t, snapshot.Manifests, 1)

				packageJsonManifest, exists := snapshot.Manifests["package.json"]
				assert.True(t, exists)
				assert.NotNil(t, packageJsonManifest.Resolved)

				// lodash should be included as it's a non-root library component
				_, exists = packageJsonManifest.Resolved["lodash"]
				assert.True(t, exists)

				// main.js (comp1) should not be included as it's a non-library component
				_, exists = packageJsonManifest.Resolved["main.js"]
				assert.False(t, exists, "main.js should not be included as it's a non-library component")
			},
		},
		{
			name: "Git ref without prefix",
			components: []cyclonedx.Component{
				createTestComponent("comp1", "express", "4.18.2", "pkg:npm/express@4.18.2", []string{"package.json"}),
			},
			dependencies: []cyclonedx.Dependency{},
			gitRef:       "main",
			validateSnapshot: func(t *testing.T, snapshot *vcsclient.SbomSnapshot) {
				assert.Equal(t, "refs/heads/main", snapshot.Ref)
			},
		},
		{
			name: "Complex dependencies with nested structure",
			components: []cyclonedx.Component{
				createTestComponent("root1", "express", "4.18.2", "pkg:npm/express@4.18.2", []string{"package.json"}),
				createTestComponent("dep1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", []string{"package.json"}),
				createTestComponent("dep2", "moment", "2.29.4", "pkg:npm/moment@2.29.4", []string{"package.json"}),
				createTestComponent("dep3", "axios", "1.6.0", "pkg:npm/axios@1.6.0", []string{"package.json"}),
				createTestComponent("dep4", "follow-redirects", "1.15.0", "pkg:npm/follow-redirects@1.15.0", []string{"package.json"}),
			},
			dependencies: []cyclonedx.Dependency{
				createTestDependency("root1", []string{"dep1", "dep2", "dep3"}), // express depends on lodash, moment, axios
				createTestDependency("dep1", []string{}),                        // lodash has no dependencies
				createTestDependency("dep2", []string{}),                        // moment has no dependencies
				createTestDependency("dep3", []string{"dep4"}),                  // axios depends on follow-redirects
				createTestDependency("dep4", []string{}),                        // follow-redirects has no dependencies
			},
			gitRef: testGitRef,
			validateSnapshot: func(t *testing.T, snapshot *vcsclient.SbomSnapshot) {
				assert.NotNil(t, snapshot.Manifests)
				assert.Len(t, snapshot.Manifests, 1) // only package.json

				// Check package.json manifest
				packageJsonManifest, exists := snapshot.Manifests["package.json"]
				assert.True(t, exists)
				assert.Equal(t, "package.json", packageJsonManifest.Name)
				assert.NotNil(t, packageJsonManifest.File)
				assert.Equal(t, "package.json", packageJsonManifest.File.SourceLocation)
				assert.NotNil(t, packageJsonManifest.Resolved)
				assert.Len(t, packageJsonManifest.Resolved, 4)

				lodashDep, exists := packageJsonManifest.Resolved["lodash"]
				assert.True(t, exists)
				assert.Equal(t, "pkg:npm/lodash@4.17.21", lodashDep.PackageURL)
				assert.Contains(t, []string{directDependency, indirectDependency}, lodashDep.Relationship)
				assert.Len(t, lodashDep.Dependencies, 0)

				momentDep, exists := packageJsonManifest.Resolved["moment"]
				assert.True(t, exists)
				assert.Equal(t, "pkg:npm/moment@2.29.4", momentDep.PackageURL)
				assert.Contains(t, []string{directDependency, indirectDependency}, momentDep.Relationship)
				assert.Len(t, momentDep.Dependencies, 0)

				axiosDep, exists := packageJsonManifest.Resolved["axios"]
				assert.True(t, exists)
				assert.Equal(t, "pkg:npm/axios@1.6.0", axiosDep.PackageURL)
				assert.Contains(t, []string{directDependency, indirectDependency}, axiosDep.Relationship)
				assert.Len(t, axiosDep.Dependencies, 1) // depends on follow-redirects

				followRedirectsDep, exists := packageJsonManifest.Resolved["follow-redirects"]
				assert.True(t, exists)
				assert.Equal(t, "pkg:npm/follow-redirects@1.15.0", followRedirectsDep.PackageURL)
				assert.Contains(t, []string{directDependency, indirectDependency}, followRedirectsDep.Relationship)
				assert.Len(t, followRedirectsDep.Dependencies, 0)
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			var bom *cyclonedx.BOM
			if test.components == nil {
				bom = nil
			} else {
				bom = createTestBOM(test.components, test.dependencies)
			}

			scanTime := time.Now()
			snapshot, err := CreateGithubSnapshotFromSbom(bom, testSnapshotVersion, scanTime, testJobId, testJobCorrelator, testCommitSha, test.gitRef, testDetectorName, testDetectorVersion, testDetectorUrl)

			if test.errorExpected {
				assert.Error(t, err)
				assert.Nil(t, snapshot)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, snapshot)

				assert.Equal(t, testSnapshotVersion, snapshot.Version)
				assert.Equal(t, testCommitSha, snapshot.Sha)
				assert.Equal(t, testGitRef, snapshot.Ref)
				assert.Equal(t, scanTime, snapshot.Scanned)
				assert.NotNil(t, snapshot.Job)
				assert.Equal(t, testJobId, snapshot.Job.ID)
				assert.Equal(t, testJobCorrelator, snapshot.Job.Correlator)
				assert.NotNil(t, snapshot.Detector)
				assert.Equal(t, testDetectorName, snapshot.Detector.Name)
				assert.Equal(t, testDetectorVersion, snapshot.Detector.Version)
				assert.Equal(t, testDetectorUrl, snapshot.Detector.Url)

				if test.validateSnapshot != nil {
					test.validateSnapshot(t, snapshot)
				}
			}
		})
	}
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
