package sca

import (
	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/sca/npm"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

func GetTechDependencyLocations(tech techutils.Technology, directDependencyName, directDependencyVersion string, filesToSearch ...string) ([]*sarif.Location, error) {
	switch tech {
	case techutils.Npm:
		nh := npm.NpmHandler{}
		return nh.GetTechDependencyLocations(directDependencyName, directDependencyVersion, filesToSearch...)
	}
	return nil, nil
}
