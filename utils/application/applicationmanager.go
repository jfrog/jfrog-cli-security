package application

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/application"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
)

func CreateApplicationService(serviceDetails *config.ServerDetails) (*application.ApplicationServicesManager, error) {
	applicationDetails, err := serviceDetails.CreateApplicationAuthConfig()
	if err != nil {
		return nil, err
	}
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(applicationDetails).
		SetInsecureTls(serviceDetails.InsecureTls).
		Build()
	if err != nil {
		return nil, err
	}
	return application.New(serviceConfig)
}
