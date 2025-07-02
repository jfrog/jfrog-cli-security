package artifactory

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/artifactory/services"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	artifactoryUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/common/spec"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/generic"
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

func UploadArtifactsByPattern(pattern string, serverDetails *config.ServerDetails, repo, relatedProjectKey string) (err error) {
	if strings.Contains(repo, "/") && !strings.HasSuffix(repo, "/") {
		// target repo is <repository name>/<repository path>, If the target path ends with a slash, the path is assumed to be a folder.
		// Else it is assumed to be a file. so we add a slash to the end of the repo to indicate that it is a folder.
		repo = fmt.Sprintf("%s/", repo)
	}
	uploadCmd := generic.NewUploadCommand()
	uploadCmd.SetUploadConfiguration(&artifactoryUtils.UploadConfiguration{Threads: 1}).SetServerDetails(serverDetails).SetSpec(spec.NewBuilder().Pattern(pattern).Project(relatedProjectKey).Target(repo).Flat(true).BuildSpec())
	uploadCmd.SetDetailedSummary(true)
	err = uploadCmd.Run()
	result := uploadCmd.Result()
	defer common.CleanupResult(result, &err)
	return common.PrintDeploymentView(result.Reader())
}

func IsRepoExists(repoKey string, serverDetails *config.ServerDetails) (exists bool, err error) {
	if repoKey == "" || serverDetails == nil {
		return false, errors.New("repository key and server details must be provided")
	}
	servicesManager, err := artifactoryUtils.CreateServiceManager(serverDetails, -1, 0, false)
	if err != nil {
		return false, err
	}
	return servicesManager.IsRepoExists(repoKey)
}

func CreateGenericLocalRepository(repoKey string, serverDetails *config.ServerDetails, xrayIndex bool, relatedProjectKey string) (err error) {
	if repoKey == "" || serverDetails == nil {
		return errors.New("repository key and server details must be provided")
	}
	servicesManager, err := artifactoryUtils.CreateServiceManager(serverDetails, -1, 0, false)
	if err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Creating generic local repository %s (xrayIndex: %t)", repoKey, xrayIndex))
	params := services.NewGenericLocalRepositoryParams()
	params.Key = repoKey
	params.ProjectKey = relatedProjectKey
	params.XrayIndex = clientUtils.Pointer(xrayIndex)
	return servicesManager.CreateLocalRepository().Generic(params)
}

func SearchArtifactsInRepo(serverDetails *config.ServerDetails, pattern, repo string) ([]artifactoryUtils.SearchResult, error) {
	searchCmd := generic.NewSearchCommand()
	if repo != "" {
		pattern = fmt.Sprintf("%s/%s", repo, pattern)
	}
	searchCmd.SetServerDetails(serverDetails).SetSpec(spec.NewBuilder().Pattern(pattern).BuildSpec())
	reader, err := searchCmd.Search()
	if err != nil {
		return nil, fmt.Errorf("failed to search for artifacts in repository %s: %w", repo, err)
	}
	var resultItems []artifactoryUtils.SearchResult
	readerNoDate, err := artifactoryUtils.SearchResultNoDate(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to get search results without date for repository %s: %w", repo, err)
	}
	for searchResult := new(artifactoryUtils.SearchResult); readerNoDate.NextRecord(searchResult) == nil; searchResult = new(artifactoryUtils.SearchResult) {
		resultItems = append(resultItems, *searchResult)
	}
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("couldn't close reader: %w", err)
	}
	if err := reader.GetError(); err != nil {
		return nil, fmt.Errorf("couldn't get reader error: %w", err)
	}
	return resultItems, nil
}
