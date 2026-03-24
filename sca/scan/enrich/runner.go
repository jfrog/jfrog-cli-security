package enrich

import (
	"errors"
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"

	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/utils/catalog"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/remediation"
)

type EnrichScanStrategy struct {
	serverDetails *config.ServerDetails
	projectKey    string
	// Fix version attachment is not critical, so we continue even if it fails without returning an error
	failOnRemediationError bool
}

func NewEnrichScanStrategy() *EnrichScanStrategy {
	return &EnrichScanStrategy{}
}

func WithParams(serverDetails *config.ServerDetails, projectKey string) scan.SbomScanOption {
	return func(sss scan.SbomScanStrategy) {
		if ess, ok := sss.(*EnrichScanStrategy); ok {
			ess.serverDetails = serverDetails
			ess.projectKey = projectKey
		}
	}
}

func (ess *EnrichScanStrategy) WithOptions(options ...scan.SbomScanOption) scan.SbomScanStrategy {
	for _, option := range options {
		option(ess)
	}
	return ess
}

func WithFailOnRemediationError(failOnRemediationError bool) scan.SbomScanOption {
	return func(sss scan.SbomScanStrategy) {
		if ess, ok := sss.(*EnrichScanStrategy); ok {
			ess.failOnRemediationError = failOnRemediationError
		}
	}
}

func (ess *EnrichScanStrategy) PrepareStrategy() (err error) {
	catalogManager, err := catalog.CreateCatalogServiceManager(ess.serverDetails, catalog.WithScopedProjectKey(ess.projectKey))
	if err != nil {
		return fmt.Errorf("failed to create catalog service manager: %w", err)
	}
	catalogVersion, err := catalogManager.GetVersion()
	if err != nil {
		return fmt.Errorf("failed to get catalog version: %w", err)
	}
	log.Debug(fmt.Sprintf("Catalog version: %s", catalogVersion))
	return
}

func (ess *EnrichScanStrategy) SbomEnrichTask(target *cyclonedx.BOM) (enriched *cyclonedx.BOM, err error) {
	catalogManager, err := catalog.CreateCatalogServiceManager(ess.serverDetails, catalog.WithScopedProjectKey(ess.projectKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create catalog service manager: %w", err)
	}
	enriched, err = catalogManager.Enrich(target)
	if err != nil {
		return nil, fmt.Errorf("failed to enrich SBOM: %w", err)
	}
	log.Debug("SBOM enrichment completed successfully")
	// Fixed versions are not returned from the enrich API, next we need to enrich with remediation API.
	if e := ess.attachFixedVersionsToVulnerabilities(enriched); e != nil {
		e = fmt.Errorf("failed to enrich SBOM with remediation: %w", e)
		if ess.failOnRemediationError {
			return enriched, e
		}
		log.Error(e.Error())
	} else {
		log.Debug("SBOM remediation enrichment completed successfully")
	}
	return enriched, nil
}

func (ess *EnrichScanStrategy) attachFixedVersionsToVulnerabilities(bom *cyclonedx.BOM) error {
	xrayManager, err := xray.CreateXrayServiceManager(ess.serverDetails, xray.WithScopedProjectKey(ess.projectKey))
	if err != nil {
		return fmt.Errorf("failed to create Xray service manager: %w", err)
	}
	if e := remediation.AttachFixedVersionsToVulnerabilities(xrayManager, bom); e != nil {
		return fmt.Errorf("failed to attach fixed versions to vulnerabilities: %w", e)
	}
	return nil
}

func (ess *EnrichScanStrategy) DeprecatedScanTask(target *cyclonedx.BOM) (techResults services.ScanResponse, err error) {
	return services.ScanResponse{}, errors.New("EnrichScanStrategy does not support DeprecatedScanTask")
}
