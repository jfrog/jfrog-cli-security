package enforcer

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

func TestConvertToCveViolations_withoutImpactedComponent(t *testing.T) {
	cveId := "CVE-2024-no-component"
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{},
		Vulnerabilities: &[]cyclonedx.Vulnerability{{
			ID:     cveId,
			BOMRef: "vuln-ref-no-affects",
		}},
	}
	cmdResults := results.NewCommandResults(utils.SourceCode)
	target := cmdResults.NewScanResults(results.ScanTarget{Target: "target"})
	target.SetSbom(bom)

	xrayViolation := services.XrayViolation{
		Id:                   "violation-1",
		Type:                 xrayUtils.SecurityViolation,
		Severity:             "High",
		Cves:                 []services.CveDetails{{Id: cveId}},
		InfectedComponentIds: []string{},
	}

	got := convertToCveViolations(cmdResults, xrayViolation)
	require.Len(t, got, 1)
	assert.Nil(t, got[0].ImpactedComponent)
	assert.Equal(t, cveId, got[0].CveVulnerability.ID)
}

func TestConvertToCveViolations_skippedWhenBomHasAffectsButNoComponentId(t *testing.T) {
	cveId := "CVE-2024-mismatch"
	componentRef := "pkg:golang/example@1.0.0"
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{{
			BOMRef:     componentRef,
			PackageURL: componentRef,
			Type:       cyclonedx.ComponentTypeLibrary,
		}},
		Vulnerabilities: &[]cyclonedx.Vulnerability{{
			ID:     cveId,
			BOMRef: "vuln-with-affects",
			Affects: &[]cyclonedx.Affects{{
				Ref: componentRef,
			}},
		}},
	}
	cmdResults := results.NewCommandResults(utils.SourceCode)
	target := cmdResults.NewScanResults(results.ScanTarget{Target: "target"})
	target.SetSbom(bom)

	xrayViolation := services.XrayViolation{
		Id:                   "violation-2",
		Type:                 xrayUtils.SecurityViolation,
		Severity:             "High",
		Cves:                 []services.CveDetails{{Id: cveId}},
		InfectedComponentIds: []string{},
	}

	got := convertToCveViolations(cmdResults, xrayViolation)
	assert.Empty(t, got, "BOM vulnerability has Affects but Xray sent no component ids — createCveViolation returns nil")
}

func TestConvertToLicenseViolations_withoutImpactedComponent(t *testing.T) {
	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.NewScanResults(results.ScanTarget{Target: "target"}).SetSbom(&cyclonedx.BOM{
		Components:      &[]cyclonedx.Component{},
		Vulnerabilities: &[]cyclonedx.Vulnerability{},
	})

	xrayViolation := services.XrayViolation{
		Id:                   "license-vio-1",
		Type:                 xrayUtils.LicenseViolation,
		Severity:             "Medium",
		IssueId:              "GPL-3.0",
		Description:          "GPL license issue",
		InfectedComponentIds: []string{},
	}

	got := convertToLicenseViolations(cmdResults, xrayViolation)
	require.Len(t, got, 1)
	assert.Nil(t, got[0].ImpactedComponent)
	assert.Equal(t, "GPL-3.0", got[0].LicenseKey)
}
