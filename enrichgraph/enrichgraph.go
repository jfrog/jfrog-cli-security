package enrichgraph

import (
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	ScanTypeMinXrayVersion = "3.37.2"
)

func RunImportGraphAndGetResults(params *EnrichGraphParams, xrayManager *xray.XrayServicesManager) (*services.ScanResponse, error) {
	err := clientutils.ValidateMinimumVersion(clientutils.Xray, params.xrayVersion, ScanTypeMinXrayVersion)
	if err != nil {
		// Remove scan type param if Xray version is under the minimum supported version
		params.xrayGraphImportParams.ScanType = ""
	}

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
