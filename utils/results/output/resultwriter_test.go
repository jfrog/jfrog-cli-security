package output

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

func TestStripUnrequestedVulnerabilities(t *testing.T) {
	scaResults := []services.ScanResponse{
		{
			Vulnerabilities: []services.Vulnerability{{Cves: []services.Cve{{Id: "CVE-2021-1111"}}}},
			Violations:      []services.Violation{{Cves: []services.Cve{{Id: "CVE-2021-2222"}}}},
		},
	}

	tests := []struct {
		name                    string
		includeVulnerabilities  bool
		expectedVulnerabilities []services.Vulnerability
	}{
		{name: "vulnerabilities not requested - stripped", includeVulnerabilities: false, expectedVulnerabilities: nil},
		{name: "vulnerabilities requested - unchanged", includeVulnerabilities: true, expectedVulnerabilities: scaResults[0].Vulnerabilities},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdResults := results.NewCommandResults(utils.SourceCode).SetResultsContext(results.ResultContext{IncludeVulnerabilities: tt.includeVulnerabilities})
			rw := NewResultsWriter(cmdResults)
			filtered := rw.stripUnrequestedVulnerabilities(scaResults)
			assert.Equal(t, tt.expectedVulnerabilities, filtered[0].Vulnerabilities)
			assert.Equal(t, scaResults[0].Violations, filtered[0].Violations)
			assert.NotEmpty(t, scaResults[0].Vulnerabilities)
		})
	}
}
