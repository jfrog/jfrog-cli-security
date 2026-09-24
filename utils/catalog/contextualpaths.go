package catalog

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	catalogServices "github.com/jfrog/jfrog-client-go/catalog/services"

	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
)

// GetIndirectCvePaths asks Catalog for the dependency-chain path(s) that make each of the given indirect CVEs
// reachable, given the packages resolved in the BOM.
func GetIndirectCvePaths(serverDetails *config.ServerDetails, projectKey string, indirectCves []string, bom *cyclonedx.BOM) (map[string]catalogServices.IndirectContextualResponse, error) {
	if len(indirectCves) == 0 || bom == nil {
		return nil, nil
	}
	catalogManager, err := CreateCatalogServiceManager(serverDetails, WithScopedProjectKey(projectKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create catalog service manager: %w", err)
	}
	return catalogManager.GetContextualPaths(indirectCves, cdxutils.ExtractPackageVersionKeys(bom))
}
