package technologies

import (
	"github.com/jfrog/jfrog-cli-security/technologies/java"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

var TechnologyHandlers = map[techutils.Technology]TechnologyHandler {
	techutils.Maven: java.MavenHandler{},
}

// All the basic functions that each technology should provide to be supported by our commands
type TechnologyHandler interface {
	// Get the dependency tree of the technology in the current directory
	GetTechDependencyTree(descriptorPaths ...string) (DependencyTreeResult, error)
}

func GetTechnologyHandler(technology techutils.Technology) TechnologyHandler {
	return TechnologyHandlers[technology]
}

func GetDependencyTree(technology techutils.Technology) (DependencyTreeResult, error) {
	handler := GetTechnologyHandler(technology)
	if handler == nil {
		return nil, nil
	}
	return handler.GetTechDependencyTree()
}