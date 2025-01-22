package unifiedpolicy

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/unifiedpolicy/services"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func Evaluate(serviceDetails *config.ServerDetails, evaluateRequest *services.EvaluateRequest) (resp *services.EvaluateResponse, err error) {
	evaluateService, err := CreateUnifiedPolicyService(serviceDetails)
	if err != nil {
		log.Debug(fmt.Sprintf("failed to create unified policy manager for evaluate service, error: %s ", err.Error()))
		return
	}
	resp, err = evaluateService.Evaluate(evaluateRequest)
	if err != nil {
		log.Debug(fmt.Sprintf("failed sending evaluate request to unified policy, error: %s ", err.Error()))
		return
	}
	return
}
