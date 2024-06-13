package java

import (
	"github.com/jfrog/jfrog-cli-security/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

type MavenHandler struct {
}

func (mavenHandler *MavenHandler) GetTechDependencyTree(descriptorPaths ...string) (sca.DependencyTreeResult, error) {
	return GetTechDependencyTree(techutils.Maven, DependencyTreeParams{})
}
