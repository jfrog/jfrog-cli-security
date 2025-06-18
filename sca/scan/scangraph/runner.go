package scangraph

import (
	"github.com/CycloneDX/cyclonedx-go"

	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/xray/services"

	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
)

type ScanGraphStrategy struct {
	scangraph.ScanGraphParams
}

func NewScanGraphStrategy() *ScanGraphStrategy {
	return &ScanGraphStrategy{
		ScanGraphParams: scangraph.ScanGraphParams{},
	}
}

func WithParams(params scangraph.ScanGraphParams) scan.SbomScanOption {
	return func(ss scan.SbomScanStrategy) error {
		sg, ok := ss.(*ScanGraphStrategy)
		if !ok {
			return nil
		}
		sg.ScanGraphParams = params
		return nil
	}
}

func (sg *ScanGraphStrategy) PrepareStrategy(options ...scan.SbomScanOption) error {
	for _, option := range options {
		if err := option(sg); err != nil {
			return err
		}
	}
	return clientutils.ValidateMinimumVersion(clientutils.Xray, sg.XrayGraphScanParams().XrayVersion, scangraph.GraphScanMinXrayVersion)
}

func (sg *ScanGraphStrategy) DeprecatedScanTask(target *cyclonedx.BOM) (services.ScanResponse, error) {
	return services.ScanResponse{}, nil
}
