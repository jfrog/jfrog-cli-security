package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/xsc"
)

func CreateXscServiceManager(serviceDetails *config.ServerDetails) (*xsc.XscServicesManager, error) {
	xscDetails, err := serviceDetails.CreateXscAuthConfig()
	if err != nil {
		return nil, err
	}
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(xscDetails).
		Build()
	if err != nil {
		return nil, err
	}
	return xsc.New(serviceConfig)
}
