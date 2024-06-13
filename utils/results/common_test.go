package results

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestGetDirectComponents(t *testing.T) {
	tests := []struct {
		impactPaths             [][]services.ImpactPathNode
		expectedComponentRows   []formats.ComponentRow
		expectedConvImpactPaths [][]formats.ComponentRow
	}{
		{[][]services.ImpactPathNode{{services.ImpactPathNode{ComponentId: "gav://jfrog:pack:1.2.3"}}}, []formats.ComponentRow{{Name: "jfrog:pack", Version: "1.2.3"}}, [][]formats.ComponentRow{{{Name: "jfrog:pack", Version: "1.2.3"}}}},
		{[][]services.ImpactPathNode{{services.ImpactPathNode{ComponentId: "gav://jfrog:pack1:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack2:1.2.3"}}}, []formats.ComponentRow{{Name: "jfrog:pack2", Version: "1.2.3"}}, [][]formats.ComponentRow{{{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack2", Version: "1.2.3"}}}},
		{[][]services.ImpactPathNode{{services.ImpactPathNode{ComponentId: "gav://jfrog:pack1:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack21:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack3:1.2.3"}}, {services.ImpactPathNode{ComponentId: "gav://jfrog:pack1:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack22:1.2.3"}, services.ImpactPathNode{ComponentId: "gav://jfrog:pack3:1.2.3"}}}, []formats.ComponentRow{{Name: "jfrog:pack21", Version: "1.2.3"}, {Name: "jfrog:pack22", Version: "1.2.3"}}, [][]formats.ComponentRow{{{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack21", Version: "1.2.3"}, {Name: "jfrog:pack3", Version: "1.2.3"}}, {{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack22", Version: "1.2.3"}, {Name: "jfrog:pack3", Version: "1.2.3"}}}},
	}

	for _, test := range tests {
		actualComponentRows, actualConvImpactPaths := getDirectComponentsAndImpactPaths(test.impactPaths)
		assert.ElementsMatch(t, test.expectedComponentRows, actualComponentRows)
		assert.ElementsMatch(t, test.expectedConvImpactPaths, actualConvImpactPaths)
	}
}

func TestGetFinalApplicabilityStatus(t *testing.T) {
	testCases := []struct {
		name           string
		input          []jasutils.ApplicabilityStatus
		expectedOutput jasutils.ApplicabilityStatus
	}{
		{
			name:           "applicable wins all statuses",
			input:          []jasutils.ApplicabilityStatus{jasutils.ApplicabilityUndetermined, jasutils.Applicable, jasutils.NotCovered, jasutils.NotApplicable},
			expectedOutput: jasutils.Applicable,
		},
		{
			name:           "undetermined wins not covered",
			input:          []jasutils.ApplicabilityStatus{jasutils.NotCovered, jasutils.ApplicabilityUndetermined, jasutils.NotCovered, jasutils.NotApplicable},
			expectedOutput: jasutils.ApplicabilityUndetermined,
		},
		{
			name:           "not covered wins not applicable",
			input:          []jasutils.ApplicabilityStatus{jasutils.NotApplicable, jasutils.NotCovered, jasutils.NotApplicable},
			expectedOutput: jasutils.NotCovered,
		},
		{
			name:           "all statuses are not applicable",
			input:          []jasutils.ApplicabilityStatus{jasutils.NotApplicable, jasutils.NotApplicable, jasutils.NotApplicable},
			expectedOutput: jasutils.NotApplicable,
		},
		{
			name:           "no statuses",
			input:          []jasutils.ApplicabilityStatus{},
			expectedOutput: jasutils.NotScanned,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedOutput, getFinalApplicabilityStatus(tc.input))
		})
	}
}
