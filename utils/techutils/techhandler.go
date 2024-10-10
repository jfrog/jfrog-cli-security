package techutils

import (
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

// In order to support a new technology with the security commands, you need to implement this interface.
type TechnologyHandler interface {
	// Get a dependency tree for each descriptor file, the tree will have a root node id with the descriptor/project id, second level nodes are the direct dependencies...
	// If no descriptor files are provided, the handler will try to use cwd as the context to find the dependencies.
	GetTechDependencyTree(params DetectDependencyTreeParams) (TechnologyDependencyTrees, error)
	// Get the locations of the direct dependency in the given descriptor files. if no descriptor files are provided, the handler will try to find at cwd.
	GetTechDependencyLocations(directDependencyName, directDependencyVersion string, descriptorPaths ...string) ([]*sarif.Location, error) // maybe ([]formats.ComponentRow, error)
	// Change a direct dependency version in the given descriptor files. if no descriptor files are provided, the handler will try to find at cwd.
	ChangeTechDependencyVersion(directDependencyName, directDependencyVersion, fixVersion string, descriptorPaths ...string) error
}

type DetectDependencyTreeParams struct {
	Technology Technology `json:"technology"`
	// If the tech need to create temp file for the output of the command it should output it to this path.
	OutputDirPath string `json:"outputDirPath,omitempty"`
	// Files that the technology handlers use to detect the project's dependencies.
	Descriptors []string `json:"descriptors"`
	// Artifactory related options
	DependenciesRepository string `json:"dependenciesRepository,omitempty"`
	// Curation related options
	IncludeCuration bool `json:"includeCuration,omitempty"`
	ServerDetails *config.ServerDetails `json:"artifactoryServerDetails,omitempty"`
	CurationCacheFolder string `json:"curationCacheFolder,omitempty"`
	
	// Common Tech options
	UseWrapper bool `json:"useWrapper,omitempty"`

	// Specific Maven options
	IsMavenDepTreeInstalled bool `json:"isMavenDepTreeInstalled,omitempty"`
}

type TechnologyDependencyTrees struct {
	UniqueDependencies []string `json:"uniqueDependencies"`
	DownloadUrls       map[string]string `json:"downloadUrls,omitempty"`
	// descriptor path -> dependency tree
	DependencyTrees map[string]*xrayUtils.GraphNode `json:"dependencyTrees,omitempty"`
}

func (tdr TechnologyDependencyTrees) GetAsXrayScaScanParam() *xrayUtils.GraphNode {
	return &xrayUtils.GraphNode{
		Id: "root",
	}
}

func (tdr TechnologyDependencyTrees) GetUnifiedTree() []*xrayUtils.GraphNode {
	return []*xrayUtils.GraphNode{}
}
