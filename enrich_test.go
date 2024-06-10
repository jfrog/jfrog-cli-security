package main

import (
	"github.com/jfrog/jfrog-cli-security/enrichgraph"
	securityTests "github.com/jfrog/jfrog-cli-security/tests"
	securityTestUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"path/filepath"
	"testing"
)

func testXrayEnrichSbom(t *testing.T) string {
	securityTestUtils.InitSecurityTest(t, enrichgraph.EnrichMinimumVersionXray)
	binariesPath := filepath.Join(filepath.FromSlash(securityTestUtils.GetTestResourcesPath()), "other", "enrich", "*")
	return securityTests.PlatformCli.RunCliCmdWithOutput(t, "sbom enrich", binariesPath)
}

func TestXrayeEnrichSbom(t *testing.T) {
	output := testXrayEnrichSbom(t)
	securityTestUtils.VerifyJsonScanResults(t, output, 0, 1, 1)
}
