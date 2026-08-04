package enforcer

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	testGoComponentRef = "pkg:golang/github.com/gophish/gophish@v0.1.2"
	testGoXrayId       = "go://github.com/gophish/gophish:v0.1.2"
)

func testGoBomComponent() cyclonedx.Component {
	return cyclonedx.Component{
		BOMRef:     testGoComponentRef,
		PackageURL: testGoComponentRef,
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       "github.com/gophish/gophish",
		Version:    "v0.1.2",
	}
}

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

func TestResolveInfectedComponents_resolvesValidId(t *testing.T) {
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{testGoBomComponent()}}
	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.NewScanResults(results.ScanTarget{Target: "target"}).SetSbom(bom)

	violation := services.XrayViolation{
		Id:                   "vio-1",
		InfectedComponentIds: []string{testGoXrayId},
	}

	resolved, unresolved := resolveInfectedComponents(cmdResults, violation)
	require.Len(t, resolved, 1)
	assert.Equal(t, 0, unresolved)
	require.NotNil(t, resolved[0].impacted)
	assert.Equal(t, testGoComponentRef, resolved[0].impacted.BOMRef)
}

func TestResolveInfectedComponents_countsUnresolvedIds(t *testing.T) {
	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.NewScanResults(results.ScanTarget{Target: "target"}).SetSbom(&cyclonedx.BOM{
		Components: &[]cyclonedx.Component{},
	})

	violation := services.XrayViolation{
		Id:                   "vio-2",
		InfectedComponentIds: []string{"missing:1.0.0", "also-missing:2.0.0"},
	}

	resolved, unresolved := resolveInfectedComponents(cmdResults, violation)
	assert.Empty(t, resolved)
	assert.Equal(t, 2, unresolved)
}

func TestConvertToScaViolation_usesPreResolvedWithoutSecondLookup(t *testing.T) {
	component := testGoBomComponent()
	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.NewScanResults(results.ScanTarget{Target: "target"}).SetSbom(&cyclonedx.BOM{
		Components: &[]cyclonedx.Component{},
	})

	pre := &bomResolvedComponent{xrayId: testGoXrayId, impacted: &component}
	violation := services.XrayViolation{Id: "vio-pre", Type: xrayUtils.SecurityViolation, Severity: "High"}

	impacted, sca := convertToScaViolation(cmdResults, pre.xrayId, violation, pre)
	require.NotNil(t, impacted)
	assert.Equal(t, testGoComponentRef, impacted.BOMRef)
	assert.Equal(t, testGoComponentRef, sca.ImpactedComponent.PackageURL)
}

func TestConvertToCveViolations_multipleCvesOneComponent(t *testing.T) {
	cveA, cveB := "CVE-2024-A", "CVE-2024-B"
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{testGoBomComponent()},
		Vulnerabilities: &[]cyclonedx.Vulnerability{
			{ID: cveA, BOMRef: "v-a", Affects: &[]cyclonedx.Affects{{Ref: testGoComponentRef}}},
			{ID: cveB, BOMRef: "v-b", Affects: &[]cyclonedx.Affects{{Ref: testGoComponentRef}}},
		},
	}
	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.NewScanResults(results.ScanTarget{Target: "target"}).SetSbom(bom)

	got := convertToCveViolations(cmdResults, services.XrayViolation{
		Id:                   "multi-cve",
		Type:                 xrayUtils.SecurityViolation,
		Severity:             "High",
		Cves:                 []services.CveDetails{{Id: cveA}, {Id: cveB}},
		InfectedComponentIds: []string{testGoXrayId},
	})
	require.Len(t, got, 2)
	for _, v := range got {
		require.NotNil(t, v.ImpactedComponent)
		assert.Equal(t, testGoComponentRef, v.ImpactedComponent.BOMRef)
	}
}

func TestConvertToLicenseViolations_withResolvedComponent(t *testing.T) {
	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.NewScanResults(results.ScanTarget{Target: "target"}).SetSbom(&cyclonedx.BOM{
		Components: &[]cyclonedx.Component{testGoBomComponent()},
	})

	got := convertToLicenseViolations(cmdResults, services.XrayViolation{
		Id:                   "lic-1",
		Type:                 xrayUtils.LicenseViolation,
		Severity:             "Medium",
		IssueId:              "MIT",
		Description:          "license",
		InfectedComponentIds: []string{testGoXrayId},
	})
	require.Len(t, got, 1)
	require.NotNil(t, got[0].ImpactedComponent)
	assert.Equal(t, testGoComponentRef, got[0].ImpactedComponent.BOMRef)
}

func TestIsMatchingExposureScannerId(t *testing.T) {
	rule := sarifutils.CreateDummyRuleWithProperties("secret-rule", sarif.Properties{
		sarifutils.JasScannerIdSarifPropertyKey: "REQ.SECRET.KEYS",
	})
	assert.True(t, isMatchingExposureScannerId("EXP-REQ.SECRET.KEYS", rule))
	assert.True(t, isMatchingExposureScannerId("EXP-REQ.SECRET.KEYS-unique123", rule))
	assert.False(t, isMatchingExposureScannerId("EXP-OTHER-unique123", rule))
	assert.False(t, isMatchingExposureScannerId("EXP-REQ.SECRET.KEYS", sarifutils.CreateDummyRuleWithProperties("no-scanner", sarif.Properties{})))
}

func TestConvertToViolations_exposureTypesFromLocalVulns(t *testing.T) {
	cmdResults := results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true)
	target := cmdResults.NewScanResults(results.ScanTarget{Target: "target"})

	secretsRule := sarifutils.CreateDummyRuleWithProperties("secret-rule", sarif.Properties{
		sarifutils.JasScannerIdSarifPropertyKey: "REQ.SECRET.KEYS",
	})
	servicesRule := sarifutils.CreateDummyRuleWithProperties("services-rule", sarif.Properties{
		sarifutils.JasScannerIdSarifPropertyKey: "GITHUB-ACTIONS-permissions-write-all",
	})
	iacRule := sarifutils.CreateDummyRuleWithProperties("iac-rule", sarif.Properties{
		sarifutils.JasScannerIdSarifPropertyKey: "aws_s3_bucket_public",
	})

	target.AddJasScanResults(jasutils.Secrets, []*sarif.Run{{
		Tool:        &sarif.Tool{Driver: sarifutils.CreateDummyDriver("secrets", secretsRule)},
		Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("/repo"))},
		Results: []*sarif.Result{
			sarifutils.CreateResultWithOneLocation("secrets.txt", 10, 1, 10, 5, "token", "secret-rule", "error"),
		},
	}}, nil, 0)
	target.AddJasScanResults(jasutils.Services, []*sarif.Run{{
		Tool:        &sarif.Tool{Driver: sarifutils.CreateDummyDriver("services", servicesRule)},
		Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("/repo"))},
		Results: []*sarif.Result{
			sarifutils.CreateResultWithOneLocation(".github/workflows/ci.yml", 4, 1, 4, 5, "write-all", "services-rule", "error"),
		},
	}}, nil, 0)
	target.AddJasScanResults(jasutils.IaC, []*sarif.Run{{
		Tool:        &sarif.Tool{Driver: sarifutils.CreateDummyDriver("iac", iacRule)},
		Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation("/repo"))},
		Results: []*sarif.Result{
			sarifutils.CreateResultWithOneLocation("infra/s3.tf", 7, 1, 7, 5, "public", "iac-rule", "error"),
		},
	}}, nil, 0)

	got, err := convertToViolations(cmdResults, []services.XrayViolation{
		{
			Id:                "sec-vio",
			Severity:          "High",
			InfectedFilePaths: []string{"secrets.txt"},
			LineNumber:        10,
			ExposureDetails:   &services.ExposureDetails{BaseJasDetails: services.BaseJasDetails{Id: "EXP-REQ.SECRET.KEYS-abc"}},
		},
		{
			Id:                "svc-vio",
			Severity:          "High",
			InfectedFilePaths: []string{".github/workflows/ci.yml"},
			LineNumber:        4,
			ExposureDetails:   &services.ExposureDetails{BaseJasDetails: services.BaseJasDetails{Id: "EXP-GITHUB-ACTIONS-permissions-write-all-def"}},
		},
		{
			Id:                "iac-vio",
			Severity:          "Medium",
			InfectedFilePaths: []string{"infra/s3.tf"},
			LineNumber:        7,
			ExposureDetails:   &services.ExposureDetails{BaseJasDetails: services.BaseJasDetails{Id: "EXP-aws_s3_bucket_public-ghi"}},
		},
		{
			Id:                "unmatched-vio",
			Severity:          "Low",
			InfectedFilePaths: []string{"missing.txt"},
			LineNumber:        1,
			ExposureDetails:   &services.ExposureDetails{BaseJasDetails: services.BaseJasDetails{Id: "EXP-UNKNOWN-xyz"}},
		},
	})
	require.NoError(t, err)
	require.Len(t, got.Secrets, 1)
	require.Len(t, got.Services, 1)
	require.Len(t, got.Iac, 1)
	assert.Equal(t, violationutils.SecretsViolationType, got.Secrets[0].ViolationType)
	assert.Equal(t, violationutils.ServicesViolationType, got.Services[0].ViolationType)
	assert.Equal(t, violationutils.IacViolationType, got.Iac[0].ViolationType)
	assert.Equal(t, "sec-vio", got.Secrets[0].ViolationId)
	assert.Equal(t, "svc-vio", got.Services[0].ViolationId)
	assert.Equal(t, "iac-vio", got.Iac[0].ViolationId)
}

func TestConvertToExposureJasViolation_skipsWhenNoMatch(t *testing.T) {
	cmdResults := results.NewCommandResults(utils.SourceCode).SetEntitledForJas(true)
	cmdResults.NewScanResults(results.ScanTarget{Target: "target"})

	got, jasType := convertToExposureJasViolation(cmdResults, services.XrayViolation{
		Id:                "missing",
		InfectedFilePaths: []string{"file.txt"},
		LineNumber:        1,
		ExposureDetails:   &services.ExposureDetails{BaseJasDetails: services.BaseJasDetails{Id: "EXP-REQ.SECRET.KEYS-abc"}},
	})
	assert.Nil(t, got)
	assert.Empty(t, jasType)
}
