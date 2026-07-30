package buildinfo

import (
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/results"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeResults(t *testing.T) {
	nodeA := &xrayUtils.GraphNode{Id: "npm://a:1"}
	nodeB := &xrayUtils.GraphNode{Id: "gav://b:2"}
	nodeC := &xrayUtils.GraphNode{Id: "pypi://c:3"}
	fullTreeA := &xrayUtils.GraphNode{Id: "root-a"}
	fullTreeB := &xrayUtils.GraphNode{Id: "root-b"}

	testCases := []struct {
		name       string
		existing   *DependencyTreeResult
		additional *DependencyTreeResult
		assertFn   func(t *testing.T, got, existing *DependencyTreeResult)
	}{
		{
			name: "nil additional returns existing unchanged",
			existing: &DependencyTreeResult{
				FlatTree:     &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeA}},
				DownloadUrls: map[string]string{"pkg:a": "https://a"},
			},
			additional: nil,
			assertFn: func(t *testing.T, got, existing *DependencyTreeResult) {
				assert.Same(t, existing, got)
				assert.Len(t, got.FlatTree.Nodes, 1)
				assert.Equal(t, "https://a", got.DownloadUrls["pkg:a"])
			},
		},
		{
			name:       "nil existing returns additional",
			existing:   nil,
			additional: &DependencyTreeResult{FlatTree: &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeB}}},
			assertFn: func(t *testing.T, got, _ *DependencyTreeResult) {
				require.NotNil(t, got)
				assert.Len(t, got.FlatTree.Nodes, 1)
				assert.Equal(t, "gav://b:2", got.FlatTree.Nodes[0].Id)
			},
		},
		{
			name: "merges flat tree nodes without duplicates",
			existing: &DependencyTreeResult{
				FlatTree:     &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeA, nodeB}},
				DownloadUrls: map[string]string{},
			},
			additional: &DependencyTreeResult{
				FlatTree: &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeB, nodeC}},
			},
			assertFn: func(t *testing.T, got, _ *DependencyTreeResult) {
				require.NotNil(t, got.FlatTree)
				assert.ElementsMatch(t, []*xrayUtils.GraphNode{nodeA, nodeB, nodeC}, got.FlatTree.Nodes)
			},
		},
		{
			name: "merging same nodes again does not duplicate",
			existing: &DependencyTreeResult{
				FlatTree:     &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeA, nodeB}},
				DownloadUrls: map[string]string{},
			},
			additional: &DependencyTreeResult{
				FlatTree: &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeA}},
			},
			assertFn: func(t *testing.T, got, _ *DependencyTreeResult) {
				assert.Len(t, got.FlatTree.Nodes, 2)
			},
		},
		{
			name: "merges download URLs without overwriting existing keys",
			existing: &DependencyTreeResult{
				FlatTree:     &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeA}},
				DownloadUrls: map[string]string{"pkg:a": "https://existing"},
			},
			additional: &DependencyTreeResult{
				FlatTree:     &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeC}},
				DownloadUrls: map[string]string{"pkg:a": "https://new", "pkg:c": "https://c"},
			},
			assertFn: func(t *testing.T, got, _ *DependencyTreeResult) {
				assert.Equal(t, "https://existing", got.DownloadUrls["pkg:a"])
				assert.Equal(t, "https://c", got.DownloadUrls["pkg:c"])
			},
		},
		{
			name: "appends full dependency trees",
			existing: &DependencyTreeResult{
				FlatTree:     &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeA}},
				FullDepTrees: []*xrayUtils.GraphNode{fullTreeA},
				DownloadUrls: map[string]string{},
			},
			additional: &DependencyTreeResult{
				FlatTree:     &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{nodeB}},
				FullDepTrees: []*xrayUtils.GraphNode{fullTreeB},
			},
			assertFn: func(t *testing.T, got, _ *DependencyTreeResult) {
				assert.Equal(t, []*xrayUtils.GraphNode{fullTreeA, fullTreeB}, got.FullDepTrees)
			},
		},
		{
			name: "clears flat tree when no nodes remain",
			existing: &DependencyTreeResult{
				FlatTree:     &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{}},
				DownloadUrls: map[string]string{},
			},
			additional: &DependencyTreeResult{
				FlatTree: &xrayUtils.GraphNode{Nodes: []*xrayUtils.GraphNode{}},
			},
			assertFn: func(t *testing.T, got, _ *DependencyTreeResult) {
				assert.Nil(t, got.FlatTree)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var existing, additional *DependencyTreeResult
			if tc.existing != nil {
				existing = copyDependencyTreeResult(tc.existing)
			}
			if tc.additional != nil {
				additional = copyDependencyTreeResult(tc.additional)
			}
			got := mergeResults(existing, additional)
			tc.assertFn(t, got, existing)
		})
	}
}

func copyDependencyTreeResult(src *DependencyTreeResult) *DependencyTreeResult {
	if src == nil {
		return nil
	}
	dst := &DependencyTreeResult{
		FullDepTrees: append([]*xrayUtils.GraphNode(nil), src.FullDepTrees...),
		DownloadUrls: make(map[string]string, len(src.DownloadUrls)),
	}
	for k, v := range src.DownloadUrls {
		dst.DownloadUrls[k] = v
	}
	if src.FlatTree != nil {
		nodes := make([]*xrayUtils.GraphNode, len(src.FlatTree.Nodes))
		copy(nodes, src.FlatTree.Nodes)
		dst.FlatTree = &xrayUtils.GraphNode{Nodes: nodes}
	}
	return dst
}

func TestGetDiffDependencyTree(t *testing.T) {
	targetResults := &results.TargetResults{
		ScanTarget: results.ScanTarget{Target: "targetPath"},
		ScaResults: &results.ScaScanResults{
			Sbom: &cyclonedx.BOM{
				Components: &[]cyclonedx.Component{
					{
						BOMRef:     "pypi:pip@20.3.4",
						PackageURL: "pkg:pypi/pip@20.3.4",
						Name:       "pip",
						Version:    "20.3.4",
						Type:       "library",
					},
					{
						BOMRef:     "pypi:pyyaml@5.2",
						PackageURL: "pkg:pypi/pyyaml@5.2",
						Name:       "pyyaml",
						Version:    "5.2",
						Type:       "library",
					},
					{
						BOMRef:     "pypi:werkzeug@1.0.1",
						PackageURL: "pkg:pypi/werkzeug@1.0.1",
						Name:       "werkzeug",
						Version:    "1.0.1",
						Type:       "library",
					},
				},
			},
		},
	}

	testCases := []struct {
		name                 string
		resultsToCompare     *results.TargetResults
		expectedDependencies []*xrayUtils.GraphNode
		expectedErr          error
	}{
		{
			name:        "No results to compare",
			expectedErr: fmt.Errorf("failed to get diff dependency tree: no results to compare"),
		},
		{
			name:             "same results",
			resultsToCompare: targetResults,
		},
		{
			name: "different results",
			resultsToCompare: &results.TargetResults{
				ScanTarget: results.ScanTarget{Target: "targetPath"},
				ScaResults: &results.ScaScanResults{
					Sbom: &cyclonedx.BOM{
						Components: &[]cyclonedx.Component{
							{
								BOMRef:     "pypi:werkzeug@1.0.2",
								PackageURL: "pkg:pypi/werkzeug@1.0.2",
								Name:       "werkzeug",
								Version:    "1.0.2",
								Type:       "library",
							},
							{
								BOMRef:     "pypi:pyyaml@5.2",
								PackageURL: "pkg:pypi/pyyaml@5.2",
								Name:       "pyyaml",
								Version:    "5.2",
								Type:       "library",
							},
							{
								BOMRef:     "pypi:wasabi@1.1.3",
								PackageURL: "pkg:pypi/wasabi@1.1.3",
								Name:       "wasabi",
								Version:    "1.1.3",
								Type:       "library",
							},
						},
					},
				},
			},
			expectedDependencies: []*xrayUtils.GraphNode{
				{Id: "pypi://pip:20.3.4"},
				{Id: "pypi://werkzeug:1.0.1"},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := GetDiffDependencyTree(targetResults, testCase.resultsToCompare)

			if testCase.resultsToCompare == nil {
				assert.Equal(t, testCase.expectedErr, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.FlatTree)
			assert.ElementsMatch(t, testCase.expectedDependencies, result.FlatTree.Nodes)
		})
	}
}
