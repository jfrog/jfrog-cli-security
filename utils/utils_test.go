package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUniqueUnion(t *testing.T) {
	testCases := []struct {
		targetFixVersions []string
		sourceFixVersions []string
		expectedResult    []string
	}{
		{
			targetFixVersions: []string{"1.0", "1.1"},
			sourceFixVersions: []string{"2.0", "2.1"},
			expectedResult:    []string{"1.0", "1.1", "2.0", "2.1"},
		},
		{
			targetFixVersions: []string{"1.0", "1.1"},
			sourceFixVersions: []string{"1.1", "2.0"},
			expectedResult:    []string{"1.0", "1.1", "2.0"},
		},
		{
			targetFixVersions: []string{},
			sourceFixVersions: []string{"1.0", "1.1"},
			expectedResult:    []string{"1.0", "1.1"},
		},
		{
			targetFixVersions: []string{"1.0", "1.1"},
			sourceFixVersions: []string{},
			expectedResult:    []string{"1.0", "1.1"},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("target:%v, source:%v", tc.targetFixVersions, tc.sourceFixVersions), func(t *testing.T) {
			result := UniqueUnion(tc.targetFixVersions, tc.sourceFixVersions...)
			assert.ElementsMatch(t, tc.expectedResult, result)
		})
	}
}
