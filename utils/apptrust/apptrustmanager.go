package apptrust

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/apptrust"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
)

func CreateApptrustServiceManager(serviceDetails *config.ServerDetails) (*apptrust.ApptrustServicesManager, error) {
	certsPath, err := coreutils.GetJfrogCertsDir()
	if err != nil {
		return nil, err
	}

	apptrustDetails, err := serviceDetails.CreateApptrustAuthConfig()
	if err != nil {
		return nil, err
	}

	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(apptrustDetails).
		SetCertificatesPath(certsPath).
		SetInsecureTls(serviceDetails.InsecureTls).
		Build()
	if err != nil {
		return nil, err
	}
	return apptrust.New(serviceConfig)
}
