package utils

import (
	"errors"
	"fmt"

	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
)

// Associates a technology with another of a different type in the structure.
// Docker is not present, as there is no docker-config command and, consequently, no docker.yaml file we need to operate on.
var TechType = map[coreutils.Technology]project.ProjectType{
	coreutils.Maven: project.Maven, coreutils.Gradle: project.Gradle, coreutils.Npm: project.Npm, coreutils.Yarn: project.Yarn, coreutils.Go: project.Go, coreutils.Pip: project.Pip,
	coreutils.Pipenv: project.Pipenv, coreutils.Poetry: project.Poetry, coreutils.Nuget: project.Nuget, coreutils.Dotnet: project.Dotnet,
}

type ArtifactoryResolutionParams struct {
	Repository string // DepsRepo
	IgnoreTechConfigFile bool // IgnoreConfigFile
}

// Verifies the existence of depsRepo. If it doesn't exist, it searches for a configuration file based on the technology type. If found, it assigns depsRepo in the AuditParams.
func SetResolutionRepoIfExists(params AuditParams, tech coreutils.Technology) (err error) {
	if params.DepsRepo() != "" || params.IgnoreConfigFile() {
		// If the depsRepo is already set or the configuration file is ignored, there is no need to search for the configuration file.
		return
	}
	// If the resolver repository doesn't exist and triggers a MissingResolverErr in ReadResolutionOnlyConfiguration, the repoConfig becomes nil. In this scenario, there is no depsRepo to set, nor is there a necessity to do so.
	if repoConfig, e := GetArtifactoryRepositoryConfig(tech); e != nil {
		err = fmt.Errorf("failed getting artifactory repository config: %s", e.Error())
	} else if repoConfig != nil {
		// If the configuration file is found, the server details and the target repository are extracted from it.
		details, e := repoConfig.ServerDetails()
		if e != nil {
			err = fmt.Errorf("failed getting server details: %s", e.Error())
		} else {
			params.SetServerDetails(details)
			params.SetDepsRepo(repoConfig.TargetRepo())
		}
	}
	return
}

// Searches for the configuration file based on the technology type. If found, it extracts the resolver repository from it.
func GetArtifactoryRepositoryConfig(tech coreutils.Technology) (repoConfig *project.RepositoryConfig, err error) {
	configFilePath, exists, err := project.GetProjectConfFilePath(TechType[tech])
	if err != nil {
		err = fmt.Errorf("failed while searching for %s.yaml config file: %s", tech.String(), err.Error())
		return
	}
	if !exists {
		// Nuget and Dotnet are identified similarly in the detection process. To prevent redundancy, Dotnet is filtered out earlier in the process, focusing solely on detecting Nuget.
		// Consequently, it becomes necessary to verify the presence of dotnet.yaml when Nuget detection occurs.
		if tech == coreutils.Nuget {
			configFilePath, exists, err = project.GetProjectConfFilePath(TechType[coreutils.Dotnet])
			if err != nil {
				err = fmt.Errorf("failed while searching for %s.yaml config file: %s", tech.String(), err.Error())
				return
			}
			if !exists {
				log.Debug(fmt.Sprintf("No %s.yaml nor %s.yaml configuration file was found. Resolving dependencies from %s default registry", coreutils.Nuget.String(), coreutils.Dotnet.String(), tech.String()))
				return
			}
		} else {
			log.Debug(fmt.Sprintf("No %s.yaml configuration file was found. Resolving dependencies from %s default registry", tech.String(), tech.String()))
			return
		}
	}
	// If the configuration file is found, the resolver repository is extracted from it.
	repoConfig, err = project.ReadResolutionOnlyConfiguration(configFilePath)
	if err != nil {
		var missingResolverErr *project.MissingResolverErr
		if !errors.As(err, &missingResolverErr) {
			err = fmt.Errorf("failed while reading %s.yaml config file: %s", tech.String(), err.Error())
			return
		}
		// When the resolver repository is absent from the configuration file, ReadResolutionOnlyConfiguration throws an error.
		// However, this situation isn't considered an error here as the resolver repository isn't mandatory for constructing the dependencies tree.
		err = nil
	}
	if repoConfig != nil {
		log.Debug("Using resolver config from", configFilePath)
	}
	return
}