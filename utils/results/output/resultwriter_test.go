package output

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestPrintJsonVulnerabilities(t *testing.T) {
	scaResponse := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{{Cves: []services.Cve{{Id: "CVE-2021-1111"}}}},
		Violations:      []services.Violation{{Cves: []services.Cve{{Id: "CVE-2021-2222"}}}},
	}

	tests := []struct {
		name                   string
		scaResponses           []services.ScanResponse
		includeVulnerabilities bool
		expectedOutput         string
		expectVulnerabilities  bool
	}{
		{name: "vulnerabilities not requested - stripped from output", scaResponses: []services.ScanResponse{scaResponse}},
		{name: "vulnerabilities requested - kept in output", scaResponses: []services.ScanResponse{scaResponse}, includeVulnerabilities: true, expectVulnerabilities: true},
		{name: "no sca results - output unchanged", expectedOutput: "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdResults := results.NewCommandResults(utils.SourceCode).SetResultsContext(results.ResultContext{IncludeVulnerabilities: tt.includeVulnerabilities})
			if len(tt.scaResponses) > 0 {
				cmdResults.NewScanResults(results.ScanTarget{}).ScaScanResults(0, tt.scaResponses...)
			}
			outputDir := t.TempDir()
			assert.NoError(t, NewResultsWriter(cmdResults).SetOutputDir(outputDir).printJson())

			files, err := filepath.Glob(filepath.Join(outputDir, "*.json"))
			assert.NoError(t, err)
			assert.Len(t, files, 1)
			content, err := os.ReadFile(files[0])
			assert.NoError(t, err)
			if tt.expectedOutput != "" {
				assert.Equal(t, tt.expectedOutput, string(content))
				return
			}
			var printed []services.ScanResponse
			assert.NoError(t, json.Unmarshal(content, &printed))
			assert.Len(t, printed, 1)
			assert.Equal(t, scaResponse.Violations, printed[0].Violations)
			if tt.expectVulnerabilities {
				assert.Equal(t, scaResponse.Vulnerabilities, printed[0].Vulnerabilities)
			} else {
				assert.Empty(t, printed[0].Vulnerabilities)
			}
		})
	}
}
