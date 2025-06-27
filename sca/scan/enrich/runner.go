package enrich

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type EnrichScanStrategy struct {
}

func (ess *EnrichScanStrategy) WithOptions(options ...scan.SbomScanOption) scan.SbomScanStrategy {
	for _, option := range options {
		option(ess)
	}
	return ess
}

func (ess *EnrichScanStrategy) PrepareStrategy() (err error) {
	return
}

func (ess *EnrichScanStrategy) SbomEnrichTask(target *cyclonedx.BOM) (enriched *cyclonedx.BOM, violations []services.Violation, err error) {
	return
}

func (ess *EnrichScanStrategy) DeprecatedScanTask(target *cyclonedx.BOM) (techResults services.ScanResponse, err error) {
	return
}
