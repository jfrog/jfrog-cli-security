package artifactory

import (
	"errors"
	"fmt"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
)

type ArtifactoryDetails struct {
	ServerDetails    *config.ServerDetails
	TargetRepository string
}

// Searches for a configuration file based on the technology type in the current directory.
// If found, it extract ArtifactoryDetails from it to used as registry resolution target.
func GetResolutionRepoIfExists(tech techutils.Technology) (details *ArtifactoryDetails, err error) {
	// If the resolver repository doesn't exist and triggers a MissingResolverErr in ReadResolutionOnlyConfiguration, the repoConfig becomes nil. In this scenario, there is no depsRepo to set, nor is there a necessity to do so.
	if repoConfig, e := getArtifactoryRepositoryConfig(tech); e != nil {
		err = fmt.Errorf("failed getting artifactory repository config: %s", e.Error())
	} else if repoConfig != nil {
		// If the configuration file is found, the server details and the target repository are extracted from it.
		serverDetails, e := repoConfig.ServerDetails()
		if e != nil {
			err = fmt.Errorf("failed getting server details: %s", e.Error())
		} else {
			details = &ArtifactoryDetails{ServerDetails: serverDetails, TargetRepository: repoConfig.TargetRepo()}
		}
	}
	return
}

// Searches for the configuration file based on the technology type. If found, it extracts the resolver repository from it.
func getArtifactoryRepositoryConfig(tech techutils.Technology) (repoConfig *project.RepositoryConfig, err error) {
	configFilePath, exists, err := project.GetProjectConfFilePath(techutils.TechToProjectType[tech])
	if err != nil {
		err = fmt.Errorf("failed while searching for %s.yaml config file: %s", tech.String(), err.Error())
		return
	}
	if !exists {
		// Nuget and Dotnet are identified similarly in the detection process. To prevent redundancy, Dotnet is filtered out earlier in the process, focusing solely on detecting Nuget.
		// Consequently, it becomes necessary to verify the presence of dotnet.yaml when Nuget detection occurs.
		if tech == techutils.Nuget {
			configFilePath, exists, err = project.GetProjectConfFilePath(techutils.TechToProjectType[techutils.Dotnet])
			if err != nil {
				err = fmt.Errorf("failed while searching for %s.yaml config file: %s", tech.String(), err.Error())
				return
			}
			if !exists {
				log.Debug(fmt.Sprintf("No %s.yaml nor %s.yaml configuration file was found. Resolving dependencies from %s default registry", techutils.Nuget.String(), techutils.Dotnet.String(), tech.String()))
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
