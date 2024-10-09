package java

import (
	"fmt"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

const (
	mavenDepTreeJarFile    = "maven-dep-tree.jar"
	mavenDepTreeOutputFile = "mavendeptree.out"
	// Changing this version also requires a change in MAVEN_DEP_TREE_VERSION within buildscripts/download_jars.sh
	mavenDepTreeVersion = "1.1.1"
	settingsXmlFile     = "settings.xml"
)

type MavenTechnologyHandler struct {}

func (handler *MavenTechnologyHandler) GetTechDependencyTree(params techutils.DetectDependencyTreeParams) (techutils.TechnologyDependencyTrees, error) {
	return techutils.TechnologyDependencyTrees{}, fmt.Errorf("Not implemented")
}

func (handler *MavenTechnologyHandler) GetTechDependencyLocations(directDependencyName, directDependencyVersion string, descriptorPaths ...string) ([]*sarif.Location, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (handler *MavenTechnologyHandler) ChangeTechDependencyVersion(directDependencyName, directDependencyVersion, fixVersion string, descriptorPaths ...string) error {
	return fmt.Errorf("Not implemented")
}