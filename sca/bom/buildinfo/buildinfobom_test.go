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
