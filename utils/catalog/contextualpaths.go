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
	catalogNamespacePublic      = "public"
	purlTypeGolang              = "golang"
	purlTypeMaven               = "maven"
	defaultPackageNameSeparator = "/"
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

// toCatalogPackageVersionKey folds a non-empty purl namespace into the name for every package type (Maven uses
// its own "groupId:artifactId" separator, everything else uses "/"), since Catalog forces namespace to "public"
// below and would otherwise silently lose it.
func toCatalogPackageVersionKey(pkg xrayutils.PackageVersionKey) xrayutils.PackageVersionKey {
	separator := defaultPackageNameSeparator
	if pkg.Type == purlTypeMaven {
		separator = ":"
	}
	version := pkg.Version
	if pkg.Type == purlTypeGolang {
		// Catalog's Go index is built from go.sum/proxy data, which always carries the "v" prefix (v1.2.3,
		// pseudo-versions like v0.0.0-...).
		if version != "" && !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
	}
	return xrayutils.PackageVersionKey{
		Type:      pkg.Type,
		Name:      joinPackageName(pkg.Namespace, pkg.Name, separator),
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
