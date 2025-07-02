package apptrust

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/apptrust/services"
)

const (
	evaluationPrAction         = "application:pr"
	evaluationDevelopmentStage = "development"
	evaluationPrResourceType   = "pr"
)

func GetEvaluation(serverDetails *config.ServerDetails, applicationKey, msi, gitRepoUrl string) (*services.EvaluateResponse, error) {
	apptrustService, err := CreateApptrustServiceManager(serverDetails)
	if err != nil {
		return nil, err
	}

	// TODO eran: the parameters here got changed, revisit implementation
	requestParams := services.EvaluateRequest{
		Action:  evaluationPrAction,                                          // TODO eran: are there other options here?
		Context: services.EvaluateContext{Stage: evaluationDevelopmentStage}, // TODO eran: are there other options here?
		Resource: services.EvaluateResource{
			ApplicationKey: applicationKey,
			Type:           evaluationPrResourceType, // TODO eran: are there other options here?
			MultiScanId:    msi,
			GitRepoUrl:     gitRepoUrl,
		},
	}

	evaluation, err := apptrustService.Evaluate(requestParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get evaluation for '%s' application with msi '%s' and git repo '%s': %w", applicationKey, msi, err)
	}
	return &evaluation, nil
}
