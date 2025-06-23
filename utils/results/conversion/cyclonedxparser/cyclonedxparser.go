package cyclonedxparser

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-client-go/xray/services"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type CmdResultsCycloneDxConverter struct {
	bom *cyclonedx.BOM
}

func NewCmdResultsCycloneDxConverter() *CmdResultsCycloneDxConverter {
	return &CmdResultsCycloneDxConverter{}
}

func (cdc *CmdResultsCycloneDxConverter) Get() (*cyclonedx.BOM, error) {
	if cdc.bom == nil {
		return cyclonedx.NewBOM(), nil
	}
	return cdc.bom, nil
}

func (cdc *CmdResultsCycloneDxConverter) Reset(cmdType utils.CommandType, multiScanId, xrayVersion string, entitledForJas, multipleTargets bool, generalError error) (err error) {
	// Reset the BOM
	cdc.bom = cyclonedx.NewBOM()
	cdc.bom.SerialNumber = cdxutils.GetSerialNumber(multiScanId)
	cdc.bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Authors:   &[]cyclonedx.OrganizationalContact{{Name: "JFrog"}},
	}
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) DeprecatedParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) DeprecatedParseLicenses(target results.ScanTarget, scaResponse results.ScanResult[services.ScanResponse]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbom(target results.ScanTarget, sbom *cyclonedx.BOM) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSbomLicenses(target results.ScanTarget, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseCVEs(target results.ScanTarget, enrichedSbom results.ScanResult[*cyclonedx.BOM], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSecrets(target results.ScanTarget, violations bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseIacs(target results.ScanTarget, violations bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	return
}

func (cdc *CmdResultsCycloneDxConverter) ParseViolations(target results.ScanTarget, violations []services.Violation, applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	return
}
