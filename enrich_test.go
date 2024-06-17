package main

import (
	"encoding/json"
	"encoding/xml"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

type Vulnerability struct {
	BomRef string `json:"bom_ref"`
	Id     string `json:"id"`
}

type EnrichJson struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Bom struct {
	Vulnerabilities struct {
		Vulnerability []struct {
			BomRef string `xml:"bom-ref,attr"`
			ID     string `xml:"id"`
		} `xml:"vulnerability"`
	} `xml:"vulnerabilities"`
}

func UnmarshalJson(t *testing.T, output string) EnrichJson {
	var jsonMap EnrichJson
	err := json.Unmarshal([]byte(output), &jsonMap)
	assert.NoError(t, err)
	return jsonMap
}

func UnmarshalXML(t *testing.T, output string) Bom {
	var xmlMap Bom
	err := xml.Unmarshal([]byte(output), &xmlMap)
	assert.NoError(t, err)
	return xmlMap
}

func TestXrayEnrichSbomJson_Success(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, "")
	// Configure a new server named "default".
	securityTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	// Check curl command with the default configured server.
	jsonPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "other", "enrich", "enrich.json")
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "sbom", "enrich", jsonPath)
	enrichedSbom := UnmarshalJson(t, output)
	assert.Greater(t, len(enrichedSbom.Vulnerabilities), 0)
	for _, vuln := range enrichedSbom.Vulnerabilities {
		assert.NotEqual(t, vuln.BomRef, nil)
		assert.NotEqual(t, vuln.Id, nil)
	}
}

func TestXrayEnrichSbomXML_Success(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, "")
	// Configure a new server named "default".
	securityTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	// Check curl command with the default configured server.
	jsonPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "other", "enrich", "enrich.xml")
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "sbom", "enrich", jsonPath)
	enrichedSbom := UnmarshalXML(t, output)
	assert.Greater(t, len(enrichedSbom.Vulnerabilities.Vulnerability), 0)
	for _, vuln := range enrichedSbom.Vulnerabilities.Vulnerability {
		assert.NotEqual(t, vuln.BomRef, nil)
		assert.NotEqual(t, vuln.ID, nil)
	}
}
