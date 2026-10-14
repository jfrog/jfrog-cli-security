package audit

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/stretchr/testify/assert"
)

// This test verifies we always include vulnerabilities in the GraphScan params even if not requested by user,
// in order to support full JAS scans coverage
func TestCreateXrayGraphScanParams_AlwaysIncludesVulnerabilities(t *testing.T) {
	tests := []struct {
		name                   string
		watches                []string
		includeVulnerabilities bool
	}{
		{name: "no violation context, vulnerabilities requested for display", includeVulnerabilities: true},
		{name: "watch set, vulnerabilities not requested for display", watches: []string{"watch-with-no-cve-rule"}, includeVulnerabilities: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := NewAuditParams().SetResultsContext(results.ResultContext{
				Watches:                tt.watches,
				IncludeVulnerabilities: tt.includeVulnerabilities,
			})
			graphParams := params.createXrayGraphScanParams()
			assert.True(t, graphParams.IncludeVulnerabilities, "scan-graph request must always fetch vulnerabilities so JAS scanners (e.g. Contextual Analysis) get a complete CVE set, regardless of watches")
			assert.Equal(t, tt.watches, graphParams.Watches)
		})
	}
}
