package configs

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

// User input (flags, args, env) to configure the technology configurations on a target
type DetectTechParams struct {
	Descriptors    []string `json:"descriptors,omitempty"`

	// Control target technologies configuration
	RequestedTechnologies           []string
	RequestedDescriptorsCustomNames map[techutils.Technology][]string
	RequestedInstallCommands        map[techutils.Technology]string
	InstallParams
	// Params for specific package manager that supports those features
	UseWrapper                    bool   `json:"use_wrapper,omitempty"`
	DependencyScope map[techutils.Technology]string `json:"dependency_scope,omitempty"`

	// TODO: remove below, Use descriptors info instead
	//CustomPipDependenciesFilePath string `json:"customPipDependenciesFilePath,omitempty"`
}

// Configuration for handling technology configurations on a target (install, build dependency tree...)
type TechParams struct {
	Descriptors    []string `json:"descriptors,omitempty"`
	InstallParams
	// If not nil, Artifactory server should be used as a resolution repository for the target dependencies
	ArtifactoryAsRegistry *ArtifactoryRegistryConfig `json:"artifactory_config,omitempty"`
	// Specific package manager params
	UseWrapper                    bool   `json:"use_wrapper,omitempty"`
	DependencyScope string `json:"dependency_scope,omitempty"`
}

type InstallParams struct {
	// If true, the target dependencies should be installed before the scan
	InstallTarget bool     `json:"install_target,omitempty"`
	// If not empty, the target dependencies should be installed with the provided command
	InstallCommand string   `json:"install_command,omitempty"`
	// If not nil, the target dependencies should be installed with curation checks (must be provided with InstallCommand = true)
	CurationConfig		*CurationConfig `json:"curation_config,omitempty"`
}

// Configurations for source code dependencies scan
type TargetTechConfig struct {
	DetectTechParams
	// Include third party dependencies source code in the applicability scan.
	ThirdPartyApplicabilityScan bool
}

type ArtifactoryRegistryConfig struct {
	// Artifactory server details as a resolution repository target
	ServerDetails *config.ServerDetails
	Repository    string `json:"repository,omitempty"`
}



type CurationConfig struct {
	// Curation params
	ApplyCuration       bool   `json:"applyCuration,omitempty"`
	CurationCacheFolder string `json:"curationCacheFolder,omitempty"`
}