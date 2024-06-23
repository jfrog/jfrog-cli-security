package results

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
)

// import (
// 	"testing"

// 	"github.com/jfrog/jfrog-cli-security/formats"
// 	"github.com/jfrog/jfrog-client-go/xray/services"
// 	"github.com/owenrumney/go-sarif/v2/sarif"
// 	"github.com/stretchr/testify/assert"
// )

// func TestGetScaScanResultByTarget(t *testing.T) {
// 	scanResults := NewScaScanResults()
// 	target1 := &ScaScanResult{Target: "target1"}
// 	target2 := &ScaScanResult{Target: "target2"}
// 	testCases := []struct {
// 		name     string
// 		results  ScanCommandResults
// 		target   string
// 		expected *ScaScanResult
// 	}{
// 		{
// 			name: "Sca scan result by target",
// 			results: ScanCommandResults{
// 				ScaResults: []ScaScanResult{
// 					*target1,
// 					*target2,
// 				},
// 			},
// 			target:   "target1",
// 			expected: target1,
// 		},
// 		{
// 			name: "Sca scan result by target not found",
// 			results: ScanCommandResults{
// 				ScaResults: []ScaScanResult{
// 					*target1,
// 					*target2,
// 				},
// 			},
// 			target:   "target3",
// 			expected: nil,
// 		},
// 	}
// 	for _, testCase := range testCases {
// 		t.Run(testCase.name, func(t *testing.T) {
// 			result := testCase.results.getScaScanResultByTarget(testCase.target)
// 			assert.Equal(t, testCase.expected, result)
// 		})
// 	}
// }

func TestGetTechnologies(t *testing.T) {
	testCases := []struct {
		name     string
		results  *ScanCommandResults
		expected []techutils.Technology
	}{
		{
			name:     "No technologies",
			results:  &ScanCommandResults{},
			expected: []techutils.Technology{},
		},
		{
			name: "Multiple technologies, one scan result",
			results: &ScanCommandResults{Scans: []*ScanResults{
				{Target: "target1", ScaResults: []ScaScanResults{
					{Technology: techutils.Maven},
					{Technology: techutils.Maven},
				}},
			}},
			expected: []techutils.Technology{techutils.Maven},
		},
		{
			name: "Multiple technologies, multiple scan results",
			results: &ScanCommandResults{Scans: []*ScanResults{
				{Target: "target1", ScaResults: []ScaScanResults{
					{Technology: techutils.Maven},
					{Technology: techutils.Npm},
				}},
				{Target: "target2", ScaResults: []ScaScanResults{
					{Technology: techutils.Pip},
					{Technology: techutils.Npm},
				}},
			}},
			expected: []techutils.Technology{techutils.Maven, techutils.Npm, techutils.Pip},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.results.GetTechnologies()
			assert.Equal(t, testCase.expected, result)
		})
	}
}
