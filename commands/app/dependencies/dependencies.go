package dependencies

import (
	"fmt"
	"os"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/configs"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	// "github.com/jfrog/jfrog-client-go/utils/log"
)

type DetectDependenciesParams struct {
	Target *configs.ScanTarget
	TargetConfig *configs.TargetTechConfig
}

type BuildDependencyTreeParams struct {
	// General params
	Descriptors []string `json:"descriptors,omitempty"`
	IsInstalled bool     `json:"isInstalled,omitempty"`
	// Artifactory server details as a resolution repository target
	ServerDetails *config.ServerDetails
	Repository    string `json:"artifactoryRepository,omitempty"`
	// Curation params
	ApplyCuration       bool   `json:"applyCuration,omitempty"`
	CurationCacheFolder string `json:"curationCacheFolder,omitempty"`
	// Specific package manager params
	UseWrapper                    bool   `json:"useWrapper,omitempty"`
	CustomPipDependenciesFilePath string `json:"customPipDependenciesFilePath,omitempty"`
}

type DetectDependenciesCommand struct {
	serverDetails *config.ServerDetails
	params 	  *DetectDependenciesParams
}

func NewDetectDependenciesCommand() *DetectDependenciesCommand {
	return &DetectDependenciesCommand{}
}

func (ddCmd *DetectDependenciesCommand) CommandName() string {
	return "dependencies"
}

func (ddCmd *DetectDependenciesCommand) ServerDetails() (*config.ServerDetails, error) {
	return ddCmd.serverDetails, nil
}

func (ddCmd *DetectDependenciesCommand) Run() (err error) {
	currentWorkingDir, err := os.Getwd()
	if err != nil {
		return errorutils.CheckError(err)
	}
	if err := os.Chdir(ddCmd.params.Target.Target); err != nil {
		return errorutils.CheckError(err)
	}
	defer func() {
		err = errorutils.CheckError(os.Chdir(currentWorkingDir))
	}()
	if treeResult.FlatTree == nil || len(treeResult.FlatTree.Nodes) == 0 {
		return nil, errorutils.CheckErrorf("no dependencies were found. Please try to build your project and re-run the audit command")
	}
}

func RunDetectTargetDependencies(target *configs.ScanTarget ,params *DetectDependenciesParams) (err error) {
	
	treeResult, techErr := GetTechDependencyTree(params.AuditBasicParams, scan.Technology)
	if techErr != nil {
		return nil, fmt.Errorf("failed while building '%s' dependency tree:\n%s", scan.Technology, techErr.Error())
	}
	
	return nil
}