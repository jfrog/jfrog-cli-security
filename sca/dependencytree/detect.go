package dependencytree

import (
	"encoding/json"
	"fmt"
	"time"

	// "fmt"
	// "time"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	// "github.com/jfrog/jfrog-cli-security/commands/scans/audit/sca/java"
	// _go "github.com/jfrog/jfrog-cli-security/commands/audit/sca/go"
	// "github.com/jfrog/build-info-go/utils/pythonutils"
	// "github.com/jfrog/jfrog-cli-security/commands/audit/sca/npm"
	// "github.com/jfrog/jfrog-cli-security/commands/audit/sca/nuget"
	// "github.com/jfrog/jfrog-cli-security/commands/audit/sca/pnpm"
	// "github.com/jfrog/jfrog-cli-security/commands/audit/sca/python"
	// "github.com/jfrog/jfrog-cli-security/commands/audit/sca/yarn"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	clientutils "github.com/jfrog/jfrog-client-go/utils"
	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

// Parameters for generating a dependency tree
type DetectDependencyTreeParams interface {
	// General params
	GetTechnology() techutils.Technology
	GetDescriptors() []string
	GetIsInstalled() bool
	// (Optional) Artifactory server details as a resolution repository target
	GetServerDetails() *config.ServerDetails
	GetRepository() string
	// Curation (Optional) params
	GetApplyCuration() bool
	GetCurationCacheFolder() string
	// Specific (Optional) package manager params
	GetUseWrapper() bool
	GetCustomPipDependenciesFilePath() string
}

type DependencyTreeParams struct {
	Technology techutils.Technology `json:"technology"`
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

type DependencyTreeResult struct {
	FlatTree     *xrayClientUtils.GraphNode
	DownloadUrls map[string]string

	FullDepTrees []*xrayClientUtils.GraphNode
}

type techTreeGenerationFunc func(params DetectDependencyTreeParams) (DependencyTreeResult, error)

type DepTreeNode struct {
	Classifier *string   `json:"classifier"`
	Types      *[]string `json:"types"`
	Children   []string  `json:"children"`
}

// Detect and return the dependency tree of a technology in the current directory
// func GetTechDependencyTree(tech techutils.Technology, params DependencyTreeParams) (depTreeResult DependencyTreeResult, err error) {
// 	var uniqueDeps []string
// 	var uniqDepsWithTypes map[string]*DepTreeNode
// 	startTime := time.Now()

// 	switch tech {
// 	case techutils.Maven, techutils.Gradle:
// 		depTreeResult.FullDepTrees, uniqDepsWithTypes, err = java.BuildDependencyTree(java.DepTreeParams{
// 			Server:                  params.ServerDetails,
// 			DepsRepo:                params.Repository,
// 			IsMavenDepTreeInstalled: params.IsInstalled,
// 			UseWrapper:              params.UseWrapper,
// 			IsCurationCmd:           params.ApplyCuration,
// 			CurationCacheFolder:     params.CurationCacheFolder,
// 		}, tech)
// 	// case techutils.Npm:
// 	// 	depTreeResult.FullDepTrees, uniqueDeps, err = npm.BuildDependencyTree(params)
// 	// case techutils.Pnpm:
// 	// 	depTreeResult.FullDepTrees, uniqueDeps, err = pnpm.BuildDependencyTree(params)
// 	// case techutils.Yarn:
// 	// 	depTreeResult.FullDepTrees, uniqueDeps, err = yarn.BuildDependencyTree(params)
// 	// case techutils.Go:
// 	// 	depTreeResult.FullDepTrees, uniqueDeps, err = _go.BuildDependencyTree(params)
// 	// case techutils.Pipenv, techutils.Pip, techutils.Poetry:
// 	// 	depTreeResult.FullDepTrees, uniqueDeps,
// 	// 		depTreeResult.DownloadUrls, err = python.BuildDependencyTree(&python.AuditPython{
// 	// 		Server:              params.ServerDetails,
// 	// 		Tool:                pythonutils.PythonTool(tech),
// 	// 		RemotePypiRepo:      params.Repository,
// 	// 		PipRequirementsFile: params.CustomPipDependenciesFilePath,
// 	// 		IsCurationCmd:       params.ApplyCuration,
// 	// 	})
// 	// case techutils.Nuget:
// 	// 	depTreeResult.FullDepTrees, uniqueDeps, err = nuget.BuildDependencyTree(params)
// 	default:
// 		err = errorutils.CheckErrorf("%s is currently not supported", string(tech))
// 	}
// 	if err != nil || (len(uniqueDeps) == 0 && len(uniqDepsWithTypes) == 0) {
// 		return
// 	}
// 	log.Debug(fmt.Sprintf("Created '%s' dependency tree with %d nodes. Elapsed time: %.1f seconds.", tech.ToFormal(), len(uniqueDeps), time.Since(startTime).Seconds()))
// 	if len(uniqDepsWithTypes) > 0 {
// 		depTreeResult.FlatTree, err = createFlatTreeWithTypes(uniqDepsWithTypes)
// 		return
// 	}
// 	depTreeResult.FlatTree, err = createFlatTree(uniqueDeps)
// 	return
// }

func GenerateTree(params DetectDependencyTreeParams, generateTree techTreeGenerationFunc) (depTreeResult DependencyTreeResult, err error) {
	formatTech := params.GetTechnology().ToFormal()
	logMessage := fmt.Sprintf("Calculating %s dependencies", formatTech)
	curationLogMsg, curationCacheFolder, err := getCurationCacheFolderAndLogMsg(params, params.GetTechnology())
	if err != nil {
		return
	}
	// In case it's not curation command these 'curationLogMsg' be empty
	logMessage += curationLogMsg
	log.Info(logMessage + "...")

	startTime := time.Now()

	fullDepTree, uniqueDeps, err := generateTree(params)

	if err != nil || (len(uniqueDeps) == 0) {
		return
	}
	log.Debug(fmt.Sprintf("Created '%s' dependency tree with %d unique nodes. Elapsed time: %.1f seconds.", formatTech, len(uniqueDeps), time.Since(startTime).Seconds()))
	return DependencyTreeResult{}
}

func getCurationCacheFolderAndLogMsg(params DetectDependencyTreeParams, tech techutils.Technology) (logMessage string, curationCacheFolder string, err error) {
	if !params.GetApplyCuration() {
		return
	}
	if curationCacheFolder, err = getCurationCacheByTech(tech); err != nil || curationCacheFolder == "" {
		return
	}

	dirExist, err := fileutils.IsDirExists(curationCacheFolder, false)
	if err != nil {
		return
	}

	if dirExist {
		if dirIsEmpty, scopErr := fileutils.IsDirEmpty(curationCacheFolder); scopErr != nil || !dirIsEmpty {
			err = scopErr
			return
		}
	}

	logMessage = ". Quick note: we're running our first scan on the project with curation-audit. Expect this one to take a bit longer. Subsequent scans will be faster. Thanks for your patience"

	return logMessage, curationCacheFolder, err
}

func getCurationCacheByTech(tech techutils.Technology) (string, error) {
	if tech == techutils.Maven {
		return xrayutils.GetCurationMavenCacheFolder()
	}
	return "", nil
}

func createFlatTreeWithTypes(uniqueDeps map[string]*DepTreeNode) (*xrayClientUtils.GraphNode, error) {
	if err := logDeps(uniqueDeps); err != nil {
		return nil, err
	}
	var uniqueNodes []*xrayClientUtils.GraphNode
	for uniqueDep, nodeAttr := range uniqueDeps {
		node := &xrayClientUtils.GraphNode{Id: uniqueDep}
		if nodeAttr != nil {
			node.Types = nodeAttr.Types
			node.Classifier = nodeAttr.Classifier
		}
		uniqueNodes = append(uniqueNodes, node)
	}
	return &xrayClientUtils.GraphNode{Id: "root", Nodes: uniqueNodes}, nil
}

func createFlatTree(uniqueDeps []string) (*xrayClientUtils.GraphNode, error) {
	if err := logDeps(uniqueDeps); err != nil {
		return nil, err
	}
	uniqueNodes := []*xrayClientUtils.GraphNode{}
	for _, uniqueDep := range uniqueDeps {
		uniqueNodes = append(uniqueNodes, &xrayClientUtils.GraphNode{Id: uniqueDep})
	}
	return &xrayClientUtils.GraphNode{Id: "root", Nodes: uniqueNodes}, nil
}

func logDeps(uniqueDeps any) (err error) {
	if log.GetLogger().GetLogLevel() != log.DEBUG {
		// Avoid printing and marshaling if not on DEBUG mode.
		return
	}
	jsonList, err := json.Marshal(uniqueDeps)
	if errorutils.CheckError(err) != nil {
		return err
	}
	log.Debug("Unique dependencies list:\n" + clientutils.IndentJsonArray(jsonList))

	return
}
