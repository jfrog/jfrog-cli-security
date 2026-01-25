package results

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string {
	return &s
}

func TestFilterNewSarifFindings_LocationBased(t *testing.T) {
	testCases := []struct {
		name          string
		targetRuns    []*sarif.Run
		sourceRuns    []*sarif.Run
		expectedCount int
		expectedFiles []string
	}{
		{
			name:       "new issues in source - empty target",
			targetRuns: []*sarif.Run{{Results: []*sarif.Result{}}},
			sourceRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
								}},
							},
						},
					},
				},
			},
			expectedCount: 1,
			expectedFiles: []string{"file1.js"},
		},
		{
			name: "source has no new issues - same file exists in target",
			targetRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
								}},
							},
						},
					},
				},
			},
			sourceRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
								}},
							},
						},
					},
				},
			},
			expectedCount: 0,
			expectedFiles: []string{},
		},
		{
			name: "multiple issues - partial match",
			targetRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
								}},
							},
						},
					},
				},
			},
			sourceRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file2.js")},
								}},
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
								}},
							},
						},
					},
				},
			},
			expectedCount: 1,
			expectedFiles: []string{"file2.js"},
		},
		{
			name: "issue removed in source",
			targetRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
								}},
							},
						},
					},
				},
			},
			sourceRuns:    []*sarif.Run{{Results: []*sarif.Result{}}},
			expectedCount: 0,
			expectedFiles: []string{},
		},
		{
			name:          "empty source and target",
			targetRuns:    []*sarif.Run{{Results: []*sarif.Result{}}},
			sourceRuns:    []*sarif.Run{{Results: []*sarif.Result{}}},
			expectedCount: 0,
			expectedFiles: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build target keys from target runs
			targetKeys := make(map[string]bool)
			extractLocationsOnly(targetKeys, tc.targetRuns...)

			// Filter source runs
			filteredRuns := filterNewSarifFindings(tc.sourceRuns, targetKeys)

			// Count results
			resultCount := countSarifResults(filteredRuns)
			assert.Equal(t, tc.expectedCount, resultCount)

			// Verify expected files
			var foundFiles []string
			for _, run := range filteredRuns {
				for _, result := range run.Results {
					for _, loc := range result.Locations {
						if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil && loc.PhysicalLocation.ArtifactLocation.URI != nil {
							foundFiles = append(foundFiles, *loc.PhysicalLocation.ArtifactLocation.URI)
						}
					}
				}
			}
			assert.ElementsMatch(t, tc.expectedFiles, foundFiles)
		})
	}
}

func TestFilterNewSarifFindings_FingerprintBased(t *testing.T) {
	testCases := []struct {
		name          string
		targetRuns    []*sarif.Run
		sourceRuns    []*sarif.Run
		expectedCount int
	}{
		{
			name:       "new issue with fingerprint - empty target",
			targetRuns: []*sarif.Run{{Results: []*sarif.Result{{}}}},
			sourceRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Fingerprints: map[string]string{
								"precise_sink_and_sink_function": "fingerprint2",
							},
						},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "no new issues - same fingerprint exists",
			targetRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Fingerprints: map[string]string{
								"precise_sink_and_sink_function": "fingerprint1",
							},
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
								}},
							},
						},
					},
				},
			},
			sourceRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Fingerprints: map[string]string{
								"precise_sink_and_sink_function": "fingerprint1",
							},
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file2.js")},
								}},
							},
						},
					},
				},
			},
			expectedCount: 0,
		},
		{
			name: "issue removed - fingerprint based",
			targetRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Fingerprints: map[string]string{
								"precise_sink_and_sink_function": "fingerprint2",
							},
						},
					},
				},
			},
			sourceRuns:    []*sarif.Run{{Results: []*sarif.Result{}}},
			expectedCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build target keys from target runs using fingerprints
			targetKeys := make(map[string]bool)
			extractFingerprints(targetKeys, tc.targetRuns...)

			// Filter source runs
			filteredRuns := filterNewSarifFindings(tc.sourceRuns, targetKeys)

			// Count results
			resultCount := countSarifResults(filteredRuns)
			assert.Equal(t, tc.expectedCount, resultCount)
		})
	}
}

func TestFilterNewSarifFindings_WithSnippets(t *testing.T) {
	testCases := []struct {
		name          string
		targetRuns    []*sarif.Run
		sourceRuns    []*sarif.Run
		expectedCount int
	}{
		{
			name: "same file different snippet - should be new",
			targetRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
									Region: &sarif.Region{
										Snippet: &sarif.ArtifactContent{Text: strPtr("password = 'secret1'")},
									},
								}},
							},
						},
					},
				},
			},
			sourceRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
									Region: &sarif.Region{
										Snippet: &sarif.ArtifactContent{Text: strPtr("password = 'secret2'")},
									},
								}},
							},
						},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "same file same snippet - should be filtered",
			targetRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
									Region: &sarif.Region{
										Snippet: &sarif.ArtifactContent{Text: strPtr("password = 'secret1'")},
									},
								}},
							},
						},
					},
				},
			},
			sourceRuns: []*sarif.Run{
				{
					Results: []*sarif.Result{
						{
							Locations: []*sarif.Location{
								{PhysicalLocation: &sarif.PhysicalLocation{
									ArtifactLocation: &sarif.ArtifactLocation{URI: strPtr("file1.js")},
									Region: &sarif.Region{
										Snippet: &sarif.ArtifactContent{Text: strPtr("password = 'secret1'")},
									},
								}},
							},
						},
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetKeys := make(map[string]bool)
			extractLocationsOnly(targetKeys, tc.targetRuns...)

			filteredRuns := filterNewSarifFindings(tc.sourceRuns, targetKeys)
			resultCount := countSarifResults(filteredRuns)
			assert.Equal(t, tc.expectedCount, resultCount)
		})
	}
}

// Note: Tests for extractRelativePath, getLocationSnippetText, getLocationFileName, and
// getInvocationWorkingDirectory have been removed as these now use sarifutils functions.

func TestGetSastFingerprint(t *testing.T) {
	testCases := []struct {
		name     string
		result   *sarif.Result
		expected string
	}{
		{
			name: "has fingerprint",
			result: &sarif.Result{
				Fingerprints: map[string]string{
					"precise_sink_and_sink_function": "test-fingerprint-123",
				},
			},
			expected: "test-fingerprint-123",
		},
		{
			name: "no fingerprint key",
			result: &sarif.Result{
				Fingerprints: map[string]string{
					"other_key": "some-value",
				},
			},
			expected: "",
		},
		{
			name:     "nil fingerprints",
			result:   &sarif.Result{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := sarifutils.GetSastDiffFingerprint(tc.result)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCountSarifResults(t *testing.T) {
	testCases := []struct {
		name     string
		runs     []*sarif.Run
		expected int
	}{
		{
			name:     "nil runs",
			runs:     nil,
			expected: 0,
		},
		{
			name:     "empty runs",
			runs:     []*sarif.Run{},
			expected: 0,
		},
		{
			name: "single run with results",
			runs: []*sarif.Run{
				{Results: []*sarif.Result{{}, {}, {}}},
			},
			expected: 3,
		},
		{
			name: "multiple runs",
			runs: []*sarif.Run{
				{Results: []*sarif.Result{{}, {}}},
				{Results: []*sarif.Result{{}}},
			},
			expected: 3,
		},
		{
			name: "run with nil",
			runs: []*sarif.Run{
				nil,
				{Results: []*sarif.Result{{}}},
			},
			expected: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := countSarifResults(tc.runs)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Integration test using real SARIF files from analyzer-manager.
// Note: The test files have different working directories (temp folders),
// so without normalizing paths the diff will show 1 "new" finding.
// This test verifies the SARIF parsing and filtering logic works correctly.
func TestFilterNewSarifFindings_RealSecretsData(t *testing.T) {
	testDataDir := filepath.Join("..", "..", "tests", "testdata", "other", "diff-scan")

	targetSarifBytes, err := os.ReadFile(filepath.Join(testDataDir, "target.sarif"))
	require.NoError(t, err, "Failed to read target.sarif")

	sourceSarifBytes, err := os.ReadFile(filepath.Join(testDataDir, "results.sarif"))
	require.NoError(t, err, "Failed to read results.sarif (source)")

	targetReport, err := sarif.FromBytes(targetSarifBytes)
	require.NoError(t, err, "Failed to parse target SARIF")

	sourceReport, err := sarif.FromBytes(sourceSarifBytes)
	require.NoError(t, err, "Failed to parse source SARIF")

	require.NotEmpty(t, targetReport.Runs, "Target should have runs")
	require.NotEmpty(t, sourceReport.Runs, "Source should have runs")

	// Verify both files contain the same secret content (snippet)
	targetSnippet := sarifutils.GetLocationSnippetText(targetReport.Runs[0].Results[0].Locations[0])
	sourceSnippet := sarifutils.GetLocationSnippetText(sourceReport.Runs[0].Results[0].Locations[0])
	assert.Equal(t, targetSnippet, sourceSnippet, "Both files should have the same secret snippet")
	assert.Equal(t, "password: jnvkjcxnjvxnvk22222", targetSnippet)

	// Build target keys using filename+snippet (this matches same secrets even with different paths)
	targetKeys := make(map[string]bool)
	for _, run := range targetReport.Runs {
		for _, result := range run.Results {
			for _, location := range result.Locations {
				// Use just filename (last path component) + snippet for matching
				fileName := sarifutils.GetLocationFileName(location)
				if fileName != "" {
					fileName = filepath.Base(fileName)
				}
				key := fileName + sarifutils.GetLocationSnippetText(location)
				targetKeys[key] = true
			}
		}
	}

	// Filter source using same key generation
	var filteredResults []*sarif.Result
	for _, run := range sourceReport.Runs {
		for _, result := range run.Results {
			var filteredLocations []*sarif.Location
			for _, location := range result.Locations {
				fileName := sarifutils.GetLocationFileName(location)
				if fileName != "" {
					fileName = filepath.Base(fileName)
				}
				key := fileName + sarifutils.GetLocationSnippetText(location)
				if !targetKeys[key] {
					filteredLocations = append(filteredLocations, location)
				}
			}
			if len(filteredLocations) > 0 {
				newResult := *result
				newResult.Locations = filteredLocations
				filteredResults = append(filteredResults, &newResult)
			}
		}
	}

	// Same file (TOKENS) with same snippet should result in 0 new findings
	assert.Equal(t, 0, len(filteredResults), "Same secrets should be filtered out")
}
