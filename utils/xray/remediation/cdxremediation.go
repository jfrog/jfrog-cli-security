package remediation

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func GetCveRemediation(xrayManager *xray.XrayServicesManager, bom *cyclonedx.BOM, cve string) (*services.RemediationResponse, error) {
	return xrayManager.CveRemediation(bom, cve)
}

func GetDirectComponentsRemediation(xrayManager *xray.XrayServicesManager, bom *cyclonedx.BOM) (*services.RemediationResponse, error) {
	return xrayManager.DirectComponentsRemediation(bom)
}
