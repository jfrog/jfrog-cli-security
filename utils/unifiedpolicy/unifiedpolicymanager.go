package unifiedpolicy

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientconfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-client-go/unifiedpolicy"
)

func CreateUnifiedPolicyService(serviceDetails *config.ServerDetails) (*unifiedpolicy.UnifiedPolicyServicesManager, error) {
	unifiedPolicyDetails, err := serviceDetails.CreateUnifiedPolicyAuthConfig()
	if err != nil {
		return nil, err
	}
	serviceConfig, err := clientconfig.NewConfigBuilder().
		SetServiceDetails(unifiedPolicyDetails).
		SetInsecureTls(serviceDetails.InsecureTls).
		Build()
	if err != nil {
		return nil, err
	}
	return unifiedpolicy.New(serviceConfig)
}
