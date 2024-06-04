package softwarecomponents

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jfrog/build-info-go/utils/pythonutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	_go "github.com/jfrog/jfrog-cli-security/commands/audit/sca/go"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/java"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/npm"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/nuget"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/pnpm"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/python"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/yarn"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
)

// Parameters for generating a dependency tree
type DependencyTreeParams struct {
	// General params
	IsInstalled bool
	// Artifactory server details as a resolution repository target
	ServerDetails *config.ServerDetails
	Repository   string
	// Curation params
	ApplyCuration bool
	CurationCacheFolder string
	// Specific package manager params
	UseWrapper bool
	CustomPipDependenciesFilePath string
}

type DependencyTreeResult struct {
	FlatTree     *xrayClientUtils.GraphNode
	FullDepTrees []*xrayClientUtils.GraphNode
	DownloadUrls map[string]string
}

// Detect and return the dependency tree of a technology in the current directory
func GetTechDependencyTree(tech techutils.Technology, params DependencyTreeParams) (depTreeResult DependencyTreeResult, err error) {
	var uniqueDeps []string
	var uniqDepsWithTypes map[string]*utils.DepTreeNode
	startTime := time.Now()

	switch tech {
	case techutils.Maven, techutils.Gradle:
		depTreeResult.FullDepTrees, uniqDepsWithTypes, err = java.BuildDependencyTree(java.DepTreeParams{
			Server:                  params.ServerDetails,
			DepsRepo:                params.Repository,
			IsMavenDepTreeInstalled: params.IsInstalled,
			UseWrapper:              params.UseWrapper,
			IsCurationCmd:           params.ApplyCuration,
			CurationCacheFolder:     params.CurationCacheFolder,
		}, tech)
	case techutils.Npm:
		depTreeResult.FullDepTrees, uniqueDeps, err = npm.BuildDependencyTree(params)
	case techutils.Pnpm:
		depTreeResult.FullDepTrees, uniqueDeps, err = pnpm.BuildDependencyTree(params)
	case techutils.Yarn:
		depTreeResult.FullDepTrees, uniqueDeps, err = yarn.BuildDependencyTree(params)
	case techutils.Go:
		depTreeResult.FullDepTrees, uniqueDeps, err = _go.BuildDependencyTree(params)
	case techutils.Pipenv, techutils.Pip, techutils.Poetry:
		depTreeResult.FullDepTrees, uniqueDeps,
			depTreeResult.DownloadUrls, err = python.BuildDependencyTree(&python.AuditPython{
			Server:              params.ServerDetails,
			Tool:                pythonutils.PythonTool(tech),
			RemotePypiRepo:      params.Repository,
			PipRequirementsFile: params.CustomPipDependenciesFilePath,
			IsCurationCmd:       params.ApplyCuration,
		})
	case techutils.Nuget:
		depTreeResult.FullDepTrees, uniqueDeps, err = nuget.BuildDependencyTree(params)
	default:
		err = errorutils.CheckErrorf("%s is currently not supported", string(tech))
	}
	if err != nil || (len(uniqueDeps) == 0 && len(uniqDepsWithTypes) == 0) {
		return
	}
	log.Debug(fmt.Sprintf("Created '%s' dependency tree with %d nodes. Elapsed time: %.1f seconds.", tech.ToFormal(), len(uniqueDeps), time.Since(startTime).Seconds()))
	if len(uniqDepsWithTypes) > 0 {
		depTreeResult.FlatTree, err = createFlatTreeWithTypes(uniqDepsWithTypes)
		return
	}
	depTreeResult.FlatTree, err = createFlatTree(uniqueDeps)
	return
}

func createFlatTreeWithTypes(uniqueDeps map[string]*utils.DepTreeNode) (*xrayClientUtils.GraphNode, error) {
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