package enrichgraph

import (
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	EnrichMinimumVersionXray = "3.101.3"
)

func RunImportGraphAndGetResults(params *EnrichGraphParams, xrayManager *xray.XrayServicesManager) (*services.ScanResponse, error) {
	scanId, err := xrayManager.ImportGraph(*params.xrayGraphImportParams)
	if err != nil {
		return nil, err
	}

	scanResult, err := xrayManager.GetImportGraphResults(scanId)
	if err != nil {
		return nil, err
	}
	return scanResult, nil
}
