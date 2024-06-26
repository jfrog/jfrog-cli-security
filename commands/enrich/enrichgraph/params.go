package enrichgraph

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type EnrichGraphParams struct {
	serverDetails         *config.ServerDetails
	xrayGraphImportParams *services.XrayGraphImportParams
	xrayVersion           string
}

func NewEnrichGraphParams() *EnrichGraphParams {
	return &EnrichGraphParams{}
}

func (sgp *EnrichGraphParams) SetServerDetails(serverDetails *config.ServerDetails) *EnrichGraphParams {
	sgp.serverDetails = serverDetails
	return sgp
}

func (sgp *EnrichGraphParams) SetXrayGraphScanParams(params *services.XrayGraphImportParams) *EnrichGraphParams {
	sgp.xrayGraphImportParams = params
	return sgp
}

func (sgp *EnrichGraphParams) SetXrayVersion(xrayVersion string) *EnrichGraphParams {
	sgp.xrayVersion = xrayVersion
	return sgp
}

func (sgp *EnrichGraphParams) XrayGraphImportParams() *services.XrayGraphImportParams {
	return sgp.xrayGraphImportParams
}

func (sgp *EnrichGraphParams) XrayVersion() string {
	return sgp.xrayVersion
}

func (sgp *EnrichGraphParams) ServerDetails() *config.ServerDetails {
	return sgp.serverDetails
}
