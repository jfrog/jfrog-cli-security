package cyclonedxparser

import (
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

func TestParseCVEs_DoesNotMutateEnrichedSbomAffects(t *testing.T) {
	libRef := "pkg:maven/com.example/lib@1.0"
	enriched := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{{
			BOMRef: libRef, Type: cyclonedx.ComponentTypeLibrary, Name: "lib", Version: "1.0",
		}},
		Vulnerabilities: &[]cyclonedx.Vulnerability{{
			BOMRef: "CVE-2024-29371", ID: "CVE-2024-29371",
			Affects: &[]cyclonedx.Affects{{Ref: libRef}},
		}},
	}
	beforeLen := len(*(*enriched.Vulnerabilities)[0].Affects)
	beforeRefs := []string{(*(*enriched.Vulnerabilities)[0].Affects)[0].Ref}

	cdc := NewCmdResultsCycloneDxConverter(false)
	require.NoError(t, cdc.Reset(results.ResultsMetaData{Entitlements: results.Entitlements{Jas: true}}, results.ResultsStatus{}, false))
	require.NoError(t, cdc.ParseNewTargetResults(results.ScanTarget{Target: "/tmp/project"}))
	applicRun := sarifutils.CreateRunWithDummyResults(
		sarifutils.CreateResultWithLocations(
			"applic_CVE-2024-29371", "applic_CVE-2024-29371", "note",
			sarifutils.CreateLocation("src/Evidence.java", 1, 0, 2, 0, "snippet"),
		),
	)
	require.NoError(t, cdc.ParseCVEs(enriched, []*sarif.Run{applicRun}))

	after := (*enriched.Vulnerabilities)[0].Affects
	assert.Equal(t, beforeLen, len(*after), "enriched SBOM affects length must not change")
	for i, ref := range beforeRefs {
		assert.Equal(t, ref, (*after)[i].Ref)
	}
	exportVuln := cdxutils.SearchVulnerabilityByRef(&cdc.bom.BOM, "CVE-2024-29371")
	require.NotNil(t, exportVuln)
	assert.True(t, hasFileAffectOrCaProperty(*exportVuln))
}

func hasFileAffectOrCaProperty(v cyclonedx.Vulnerability) bool {
	if v.Affects != nil {
		for _, affect := range *v.Affects {
			if strings.HasPrefix(affect.Ref, "file:") {
				return true
			}
		}
	}
	if v.Properties != nil {
		for _, prop := range *v.Properties {
			if strings.HasPrefix(prop.Name, "jfrog:contextual-analysis:") {
				return true
			}
		}
	}
	return false
}
