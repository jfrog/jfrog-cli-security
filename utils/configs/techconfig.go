package configs

import "github.com/jfrog/jfrog-cli-core/v2/utils/config"

// User input (flags, args, env) to configure the technology configurations on a target
type TechParams struct {
	Descriptors    []string `json:"descriptors,omitempty"`
	// If not nil, Artifactory server should be used as a resolution repository for the target dependencies
	ArtifactoryAsRegistry *ArtifactoryRegistryConfig
	InstallParams
	// Specific package manager params
	UseWrapper                    bool   `json:"useWrapper,omitempty"`
	// TODO: remove below, Use descriptors info instead
	//CustomPipDependenciesFilePath string `json:"customPipDependenciesFilePath,omitempty"`
}

type InstallParams struct {
	InstallTarget bool     `json:"install_target,omitempty"`
	InstallCommand string   `json:"install_command,omitempty"`
	// If not n
	CurationConfig		*CurationConfig `json:"curation_config,omitempty"`
}

// Configurations for source code dependencies scan
type TargetTechConfig struct {
	// Optional field (used in audit) to provide the descriptor path that provided the dependencies for the scan
	// If not exists (binary / docker scan) the field should be empty and the data is in `Target`
	Descriptors    []string `json:"descriptors,omitempty"`
	InstallCommand string   `json:"install_command,omitempty"`
	// Include third party dependencies source code in the applicability scan.
	ThirdPartyApplicabilityScan bool

	TechParams
}

type ArtifactoryRegistryConfig struct {
	// Artifactory server details as a resolution repository target
	ServerDetails *config.ServerDetails
	Repository    string `json:"artifactoryRepository,omitempty"`
}



type CurationConfig struct {
	// Curation params
	ApplyCuration       bool   `json:"applyCuration,omitempty"`
	CurationCacheFolder string `json:"curationCacheFolder,omitempty"`
}