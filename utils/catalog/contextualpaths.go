package catalog

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	catalogServices "github.com/jfrog/jfrog-client-go/catalog/services"
	xrayutils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
)

const (
	catalogNamespacePublic = "public"
	purlTypeGolang         = "golang"
	purlTypeNPM            = "npm"
	purlTypeMaven          = "maven"
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
	packages := toCatalogPackageVersionKeys(cdxutils.ExtractPackageVersionKeys(bom))
	return catalogManager.GetContextualPaths(indirectCves, packages)
}

// toCatalogPackageVersionKeys rewrites SBOM purl coordinates into the package identity Catalog stores.
// Catalog keeps namespace "public" and folds the purl namespace into the name.
func toCatalogPackageVersionKeys(packages []xrayutils.PackageVersionKey) []xrayutils.PackageVersionKey {
	if len(packages) == 0 {
		return packages
	}
	normalized := make([]xrayutils.PackageVersionKey, len(packages))
	for i, pkg := range packages {
		normalized[i] = toCatalogPackageVersionKey(pkg)
	}
	return normalized
}

func toCatalogPackageVersionKey(pkg xrayutils.PackageVersionKey) xrayutils.PackageVersionKey {
	name := pkg.Name
	version := pkg.Version
	pkgType := pkg.Type
	switch pkg.Type {
	case purlTypeGolang:
		// Contextual analysis keys Go packages by purl type "golang", not the stored catalog type "go".
		name = joinPackageName(pkg.Namespace, pkg.Name, "/")
		if version != "" && !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
	case purlTypeNPM:
		name = joinPackageName(pkg.Namespace, pkg.Name, "/")
	case purlTypeMaven:
		name = joinPackageName(pkg.Namespace, pkg.Name, ":")
	}
	return xrayutils.PackageVersionKey{
		Type:      pkgType,
		Name:      name,
		Namespace: catalogNamespacePublic,
		Version:   version,
		Ecosystem: xrayutils.GenericEcosystem,
	}
}

func joinPackageName(namespace, name, separator string) string {
	if namespace == "" {
		return name
	}
	return namespace + separator + name
}
