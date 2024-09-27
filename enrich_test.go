package main

import (
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/commands/enrich/enrichgraph"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	securityIntegrationTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils/integration"
	"github.com/stretchr/testify/assert"
)

func TestXrayEnrichSbomOutput(t *testing.T) {
	integration.InitEnrichTest(t, enrichgraph.EnrichMinimumVersionXray)
	securityIntegrationTestUtils.CreateJfrogHomeConfig(t, true)
	defer securityTestUtils.CleanTestsHomeEnv()
	testCases := []struct {
		name      string
		inputPath string
		isXml     bool
	}{
		{
			name:      "Json format",
			inputPath: "enrich.json",
		},
		{
			name:      "Xml format",
			inputPath: "enrich.xml",
			isXml:     true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputPath := filepath.Join(filepath.FromSlash(securityTests.GetTestResourcesPath()), "other", "enrich", tc.inputPath)
			output := securityTests.PlatformCli.RunCliCmdWithOutput(t, "sbom-enrich", inputPath)
			if tc.isXml {
				enrichedSbom := securityTestUtils.UnmarshalXML(t, output)
				assert.Greater(t, len(enrichedSbom.Vulnerabilities.Vulnerability), 0)
				testVulnerabilities(t, []struct {
					BomRef string
					Id     string
				}(enrichedSbom.Vulnerabilities.Vulnerability))

			} else {
				enrichedSbom := securityTestUtils.UnmarshalJson(t, output)
				assert.Greater(t, len(enrichedSbom.Vulnerability), 0)
				testVulnerabilities(t, []struct {
					BomRef string
					Id     string
				}(enrichedSbom.Vulnerability))

			}

		})
	}
}

func testVulnerabilities(t *testing.T, vulnerabilities []struct {
	BomRef string
	Id     string
}) {
	for _, vulnerability := range vulnerabilities {
		assert.NotEqual(t, vulnerability.BomRef, nil)
		assert.NotEqual(t, vulnerability.Id, nil)
	}
}
