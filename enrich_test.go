package main

import (
	"encoding/json"
	"fmt"
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

func UnmarshalJson(t *testing.T, output string) EnrichJson {
	var jsonMap EnrichJson
	err := json.Unmarshal([]byte(output), &jsonMap)
	assert.NoError(t, err)
	return jsonMap
}

func TestXrayEnrichSbom(t *testing.T) {
	securityTestUtils.InitSecurityTest(t, "")
	// Configure a new server named "default".
	securityTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	// Check curl command with the default configured server.
	jsonPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "other", "enrich", "*")
	output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "sbom", "enrich", jsonPath)
	enrichedSbom := UnmarshalJson(t, output)
	assert.Equal(t, len(enrichedSbom.Vulnerabilities), 12)
	for _, vuln := range enrichedSbom.Vulnerabilities {
		assert.NotEqual(t, vuln.BomRef, nil)
		assert.NotEqual(t, vuln.Id, nil)
	}
	fmt.Println(enrichedSbom)
}
