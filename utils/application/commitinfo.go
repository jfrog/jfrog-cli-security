package application

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/application/services"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func SendCommitInfo(applicationKey string, serviceDetails *config.ServerDetails, commitInfo services.CreateApplicationCommitInfo) (err error) {
	applicationService, err := CreateApplicationService(serviceDetails)
	if err != nil {
		log.Debug(fmt.Sprintf("failed to create application manager for commit info service, error: %s ", err.Error()))
		return
	}
	if err = applicationService.AddCommitInfo(commitInfo, applicationKey); err != nil {
		log.Debug(fmt.Sprintf("failed sending commit info request to application service, error: %s ", err.Error()))
		return
	}
	return
}
