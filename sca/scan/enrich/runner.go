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
)

type EnrichScanStrategy struct {
	serverDetails *config.ServerDetails
	projectKey    string
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

func (ess *EnrichScanStrategy) SbomEnrichTask(target *cyclonedx.BOM) (enriched *cyclonedx.BOM, violations []services.Violation, err error) {
	catalogManager, err := catalog.CreateCatalogServiceManager(ess.serverDetails, catalog.WithScopedProjectKey(ess.projectKey))
	if err != nil {
		return nil, []services.Violation{}, fmt.Errorf("failed to create catalog service manager: %w", err)
	}
	enriched, err = catalogManager.Enrich(target)
	return
}

func (ess *EnrichScanStrategy) DeprecatedScanTask(target *cyclonedx.BOM) (techResults services.ScanResponse, err error) {
	return services.ScanResponse{}, errors.New("EnrichScanStrategy does not support DeprecatedScanTask")
}
