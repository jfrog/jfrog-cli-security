package scangraph

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type ScanGraphParams struct {
	serverDetails       *config.ServerDetails
	technology          techutils.Technology
	xrayGraphScanParams *services.XrayGraphScanParams
	fixableOnly         bool
	severityLevel       int
}

func NewScanGraphParams() *ScanGraphParams {
	return &ScanGraphParams{}
}

func (sgp *ScanGraphParams) SetServerDetails(serverDetails *config.ServerDetails) *ScanGraphParams {
	sgp.serverDetails = serverDetails
	return sgp
}

func (sgp *ScanGraphParams) SetXrayGraphScanParams(params *services.XrayGraphScanParams) *ScanGraphParams {
	sgp.xrayGraphScanParams = params
	return sgp
}

func (sgp *ScanGraphParams) SetSeverityLevel(severity string) *ScanGraphParams {
	sgp.severityLevel = getLevelOfSeverity(severity)
	return sgp
}

func (sgp *ScanGraphParams) XrayGraphScanParams() *services.XrayGraphScanParams {
	return sgp.xrayGraphScanParams
}

func (sgp *ScanGraphParams) ServerDetails() *config.ServerDetails {
	return sgp.serverDetails
}

func (sgp *ScanGraphParams) FixableOnly() bool {
	return sgp.fixableOnly
}

func (sgp *ScanGraphParams) SetFixableOnly(fixable bool) *ScanGraphParams {
	sgp.fixableOnly = fixable
	return sgp
}

func (sgp *ScanGraphParams) SetTechnology(technology techutils.Technology) *ScanGraphParams {
	sgp.technology = technology
	return sgp
}

func (sgp *ScanGraphParams) Technology() techutils.Technology {
	return sgp.technology
}
