package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetScaScanResultByTarget(t *testing.T) {
	target1 := &ScaScanResult{Target: "target1"}
	target2 := &ScaScanResult{Target: "target2"}
	testCases := []struct {
		name     string
		results  Results
		target   string
		expected *ScaScanResult
	}{
		{
			name: "Sca scan result by target",
			results: Results{
				ScaResults: []*ScaScanResult{
					target1,
					target2,
				},
			},
			target:   "target1",
			expected: target1,
		},
		{
			name: "Sca scan result by target not found",
			results: Results{
				ScaResults: []*ScaScanResult{
					target1,
					target2,
				},
			},
			target:   "target3",
			expected: nil,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.results.getScaScanResultByTarget(testCase.target)
			assert.Equal(t, testCase.expected, result)
		})
	}
}
