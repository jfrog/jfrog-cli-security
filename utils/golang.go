package utils

import (
	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func GetDependenciesList(projectDir string, errorFunc utils.HandleErrorFunc) (map[string]bool, error) {
	deps, err := utils.GetDependenciesList(projectDir, log.Logger, errorFunc)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	return deps, nil
}

func GetDependenciesGraph(projectDir string) (map[string][]string, error) {
	deps, err := utils.GetDependenciesGraph(projectDir, log.Logger)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	return deps, nil
}
