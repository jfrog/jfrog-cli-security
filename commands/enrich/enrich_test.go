package enrich

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
	coreformat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeCmdResultsWithVulns(vulns []services.Vulnerability) *results.SecurityCommandResults {
	cmdResults := results.NewCommandResults(utils.SBOM)
	target := cmdResults.NewScanResults(results.ScanTarget{Target: "test.json", Name: "test.json"})
	target.ScaScanResults(0, services.ScanResponse{Vulnerabilities: vulns})
	return cmdResults
}

func makeCmdResultsForFile(targetPath string, vulns []services.Vulnerability) *results.SecurityCommandResults {
	cmdResults := results.NewCommandResults(utils.SBOM)
	target := cmdResults.NewScanResults(results.ScanTarget{Target: targetPath, Name: filepath.Base(targetPath)})
	target.ScaScanResults(0, services.ScanResponse{Vulnerabilities: vulns})
	return cmdResults
}

func createTempXMLFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "test*.xml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestPrintVulnerabilitiesTable_WithFindings(t *testing.T) {
	cmdResults := makeCmdResultsWithVulns([]services.Vulnerability{
		{
			Cves:       []services.Cve{{Id: "CVE-2021-1234"}},
			Components: map[string]services.Component{"pkg:npm/lodash@4.17.11": {}},
		},
		{
			Cves:       []services.Cve{{Id: "CVE-2020-9999"}},
			Components: map[string]services.Component{"pkg:npm/minimist@1.2.5": {}},
		},
	})

	cmd := &EnrichCommand{outputFormat: coreformat.Table}
	var buf bytes.Buffer
	err := cmd.printVulnerabilitiesTable(cmdResults, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "COMPONENT")
	assert.Contains(t, out, "CVE-ID")
	assert.Contains(t, out, "pkg:npm/lodash@4.17.11")
	assert.Contains(t, out, "CVE-2021-1234")
	assert.Contains(t, out, "pkg:npm/minimist@1.2.5")
	assert.Contains(t, out, "CVE-2020-9999")
}

func TestPrintVulnerabilitiesTable_Empty(t *testing.T) {
	cmdResults := makeCmdResultsWithVulns(nil)

	cmd := &EnrichCommand{outputFormat: coreformat.Table}
	var buf bytes.Buffer
	err := cmd.printVulnerabilitiesTable(cmdResults, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "COMPONENT")
	assert.Contains(t, out, "CVE-ID")
	// no data rows
	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1)
}

func TestPrintVulnerabilitiesTable_NoCves(t *testing.T) {
	cmdResults := makeCmdResultsWithVulns([]services.Vulnerability{
		{
			Cves:       nil,
			Components: map[string]services.Component{"pkg:go/golang.org/x/net@v0.0.0-20210226": {}},
		},
	})

	cmd := &EnrichCommand{outputFormat: coreformat.Table}
	var buf bytes.Buffer
	err := cmd.printVulnerabilitiesTable(cmdResults, &buf)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "pkg:go/golang.org/x/net@v0.0.0-20210226")
	// CVE-ID column is blank but row is present
	assert.True(t, strings.Count(out, "\n") >= 2)
}

const minimalXML = `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
    <components>
        <component bom-ref="pkg:npm/lodash@4.17.11" type="library">
            <name>lodash</name>
            <version>4.17.11</version>
        </component>
        <component bom-ref="pkg:npm/minimist@1.2.5" type="library">
            <name>minimist</name>
            <version>1.2.5</version>
        </component>
    </components>
</bom>`

func testVulns() []services.Vulnerability {
	return []services.Vulnerability{
		{
			Cves:       []services.Cve{{Id: "CVE-2021-1234"}},
			Components: map[string]services.Component{"pkg:npm/lodash@4.17.11": {}},
		},
	}
}

func TestXmlElementToOrderedJson(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(`<root attr="val">
		<single>text</single>
		<repeated>a</repeated>
		<repeated>b</repeated>
		<nested><child>val</child></nested>
	</root>`)
	require.NoError(t, err)

	result := xmlElementToOrderedJson(doc.Root())

	require.Len(t, result, 3)

	assert.Equal(t, "single", result[0].Key)
	assert.Equal(t, "text", result[0].Value)

	assert.Equal(t, "repeated", result[1].Key)
	arr, ok := result[1].Value.([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"a", "b"}, arr)

	assert.Equal(t, "nested", result[2].Key)
}

func TestAppendVulnsFromXMLToJson(t *testing.T) {
	xmlFile := createTempXMLFile(t, minimalXML)

	tests := []struct {
		name       string
		cmdResults *results.SecurityCommandResults
		wantErr    string
	}{
		{
			name:       "success",
			cmdResults: makeCmdResultsForFile(xmlFile, testVulns()),
		},
		{
			name: "empty xray results",
			cmdResults: func() *results.SecurityCommandResults {
				r := results.NewCommandResults(utils.SBOM)
				r.NewScanResults(results.ScanTarget{Target: xmlFile, Name: "test.xml"})
				return r
			}(),
			wantErr: "xray scan results are empty",
		},
		{
			name: "invalid file",
			cmdResults: func() *results.SecurityCommandResults {
				r := results.NewCommandResults(utils.SBOM)
				r.NewScanResults(results.ScanTarget{Target: "/nonexistent/file.xml", Name: "file.xml"})
				return r
			}(),
			wantErr: "error reading XML file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AppendVulnsFromXMLToJson(tt.cmdResults)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
