package technologies

import (
	"errors"
	"fmt"

	"github.com/jfrog/jfrog-cli-security/sca/dependencytree"
	"github.com/jfrog/jfrog-cli-security/sca/technologies/java"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	// "github.com/owenrumney/go-sarif/v2/sarif"
)

var TechnologyHandlers = map[techutils.Technology]TechnologyHandler{
	techutils.Maven: java.MavenHandler{},
}

type TechError struct {
	techutils.Technology
	ErrorMsg string
}

func (err TechError) Error() string {
	return fmt.Sprintf("Error in '%s' technology: %s", err.Technology, err.ErrorMsg)
}

func NewTechError(tech techutils.Technology, msg string) error {
	return TechError{Technology: tech, ErrorMsg: msg}
}

// All the basic functions that each technology should provide to be supported by our commands
type TechnologyHandler interface {
	// Run a technology-specific command in a given working directory
	RunCmd(wd string, args ...string) (string, error)
	// Get the dependency tree of the technology in the current directory (TODO: remove constraint on the working directory)
	GetTechDependencyTree(params dependencytree.DetectDependencyTreeParams) (dependencytree.DependencyTreeResult, error)

	// TODO: Implement and support this in the future

	// Get the location of a direct dependency in a given dependencies descriptor file (e.g. pom.xml, package.json, etc.)
	// GetTechDependencyLocation(directDependencyName, directDependencyVersion, descriptorPath string) ([]*sarif.Location, error)

	// Fix a direct dependency in a given dependencies descriptor file (e.g. pom.xml, package.json, etc.)
	// if not specified file. try in the current directory?
	// Maybe inputs will be (dependencyLocation *sarif.Location, fixVersion string)
	// FixTechDependency(dependencyName, dependencyVersion, fixVersion, descriptorPath string) error
}

func GetTechnologyHandler(technology techutils.Technology) TechnologyHandler {
	return TechnologyHandlers[technology]
}

func GetDependencyTree(params dependencytree.DetectDependencyTreeParams) (tree dependencytree.DependencyTreeResult, err error) {
	if params.GetTechnology() == "" {
		return tree, errors.New("Technology is required to be set in the parameters to get the dependency tree")
	}
	handler := GetTechnologyHandler(params.GetTechnology())
	if handler == nil {
		return tree, NewTechError(params.GetTechnology(), "Dependency graph detection is not supported for this technology yet.")
	}
	return dependencytree.GetDependencyTree(&params, handler.GetTechDependencyTree)
}
