package catalog

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/catalog"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
)

// Options for creating an Catalog service manager.
type CatalogManagerOption func(f *catalog.CatalogServicesManager)

// Global reference to the project key, used for API endpoints that require it for authentication
func WithScopedProjectKey(projectKey string) CatalogManagerOption {
	return func(f *catalog.CatalogServicesManager) {
		f.SetProjectKey(projectKey)
	}
}

func CreateCatalogServiceManager(serverDetails *config.ServerDetails, options ...CatalogManagerOption) (manager *catalog.CatalogServicesManager, err error) {
	certsPath, err := coreutils.GetJfrogCertsDir()
	if err != nil {
		return
	}
	catalogDetails, err := serverDetails.CreateCatalogAuthConfig()
	if err != nil {
		return
	}
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(catalogDetails).
		SetCertificatesPath(certsPath).
		SetInsecureTls(serverDetails.InsecureTls).
		Build()
	if err != nil {
		return
	}
	manager, err = catalog.New(serviceConfig)
	if err != nil {
		return nil, err
	}
	for _, option := range options {
		option(manager)
	}
	return
}
