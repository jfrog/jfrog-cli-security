package enrich

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVulnerabilityId(t *testing.T) {
	testCases := []struct {
		name     string
		vuln     services.Vulnerability
		expected string
	}{
		{
			name: "prefers first CVE when present",
			vuln: services.Vulnerability{
				IssueId: "XRAY-1",
				Cves:    []services.Cve{{Id: "CVE-2020-1"}, {Id: "CVE-2020-2"}},
			},
			expected: "CVE-2020-1",
		},
		{
			name: "falls back to IssueId when Cves empty",
			vuln: services.Vulnerability{
				IssueId: "XRAY-87173",
				Cves:    nil,
			},
			expected: "XRAY-87173",
		},
		{
			name: "falls back to IssueId when first CVE id empty",
			vuln: services.Vulnerability{
				IssueId: "XRAY-2",
				Cves:    []services.Cve{{Id: ""}},
			},
			expected: "XRAY-2",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, vulnerabilityId(tc.vuln))
		})
	}
}

const componentRef = "pkg:maven/xerces/xercesImpl@2.11.0"

// resultsWithNonCveVuln builds a scan result carrying a single vulnerability that has no CVE,
// only an Xray issue id - the shape that used to crash AppendVulnsToJson/AppendVulnsToXML.
func resultsWithNonCveVuln(inputFile string) *results.SecurityCommandResults {
	cmdResults := results.NewCommandResults(utils.SBOM)
	cmdResults.NewScanResults(results.ScanTarget{Target: inputFile}).ScaScanResults(0, services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{{
			IssueId:    "XRAY-87173",
			Components: map[string]services.Component{componentRef: {}},
		}},
	})
	return cmdResults
}

func captureOutput(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	origLogger := log.Logger
	log.SetLogger(log.NewLogger(log.INFO, &buf))
	t.Cleanup(func() { log.SetLogger(origLogger) })
	return &buf
}

func TestAppendVulnsToJsonNonCveVuln(t *testing.T) {
	inputFile := filepath.Join(t.TempDir(), "sbom.json")
	require.NoError(t, os.WriteFile(inputFile, []byte(`{"bomFormat":"CycloneDX"}`), 0644))

	buf := captureOutput(t)
	require.NoError(t, AppendVulnsToJson(resultsWithNonCveVuln(inputFile)))

	output := buf.String()
	assert.Contains(t, output, "XRAY-87173")
	assert.Contains(t, output, componentRef)
}

func TestAppendVulnsToXMLNonCveVuln(t *testing.T) {
	inputFile := filepath.Join(t.TempDir(), "sbom.xml")
	require.NoError(t, os.WriteFile(inputFile, []byte(`<?xml version="1.0" encoding="UTF-8"?><bom></bom>`), 0644))

	buf := captureOutput(t)
	require.NoError(t, AppendVulnsToXML(resultsWithNonCveVuln(inputFile)))

	output := buf.String()
	assert.Contains(t, output, "XRAY-87173")
	assert.Contains(t, output, componentRef)
}
