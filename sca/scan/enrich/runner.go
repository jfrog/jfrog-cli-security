package enrich

import (
	"errors"
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"

	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/utils/catalog"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/remediation"
)

type EnrichScanStrategy struct {
	serverDetails  *config.ServerDetails
	projectKey     string
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

func (ess *EnrichScanStrategy) DeprecatedScanTask(target *cyclonedx.BOM) (techResults services.ScanResponse, err error) {
	return services.ScanResponse{}, errors.New("EnrichScanStrategy does not support DeprecatedScanTask")
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
	if enriched, err = catalogManager.Enrich(target); errorutils.CheckError(err) != nil {
		return nil, []services.Violation{}, fmt.Errorf("failed to enrich SBOM: %w", err)
	}
	if err = ess.enrichWithRemediation(enriched); errorutils.CheckError(err) != nil {
		return nil, []services.Violation{}, fmt.Errorf("failed to enrich SBOM with remediation: %w", err)
	}
	return
}

func (ess *EnrichScanStrategy) enrichWithRemediation(enriched *cyclonedx.BOM) error {
	xrayManager, err := xray.CreateXrayServiceManager(ess.serverDetails)
	if err != nil {
		return fmt.Errorf("failed to create Xray service manager: %w", err)
	}
	response, err := remediation.GetDirectComponentsRemediation(xrayManager, enriched)
	if err != nil {
		return fmt.Errorf("failed to get direct components remediation: %w", err)
	}
	cveRemediationMap := remediationResponseToCveComponentsMap(response)
	// Append remediation information to the SBOM vulnerabilities
	for _, vulnerability := range *enriched.Vulnerabilities {
		if _, found := cveRemediationMap[vulnerability.ID]; !found {
			continue
		}
		vulnerabilityFixes := cveRemediationMap[vulnerability.ID]
		// Append the remediation information to all the affected components of the vulnerability
		for _, affectedComponent := range *vulnerability.Affects {
			if _, found := vulnerabilityFixes[affectedComponent.Ref]; !found {
				continue
			}
			cdxutils.AppendAffectedVersions(&affectedComponent, vulnerabilityFixes[affectedComponent.Ref]...)
		}
	}
	return nil
}

func remediationResponseToCveComponentsMap(remediationResponse *services.RemediationResponse) map[string]map[string][]cyclonedx.AffectedVersions {
	cveComponentsMap := make(map[string]map[string][]cyclonedx.AffectedVersions)
	return cveComponentsMap
}
