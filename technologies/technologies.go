package technologies

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jfrog/build-info-go/utils/pythonutils"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/conan"
	_go "github.com/jfrog/jfrog-cli-security/commands/audit/sca/go"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/java"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/npm"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/nuget"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/pnpm"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/python"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/yarn"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
)

var TechnologyHandlers = map[techutils.Technology]techutils.TechnologyHandler{

}

func GetDependencyTree(params techutils.DetectDependencyTreeParams) (*techutils.TechnologyDependencyTrees, error) {
	if handler, ok := TechnologyHandlers[params.Technology]; ok {
		log.Info(fmt.Sprintf("Handler Calculating %s dependencies...", params.Technology.ToFormal()))
		if tree, err := handler.GetTechDependencyTree(params); err == nil {
			return tree, nil
		}
		log.Warn(fmt.Sprintf("Handler failed to calculate %s dependencies, falling back to default handler", params.Technology.ToFormal()))
	}
	log.Info(fmt.Sprintf("Calculating %s dependencies...", params.Technology.ToFormal()))
	return nil, fmt.Errorf("%s is currently not supported", string(params.Technology))
}

type DependencyTreeResult struct {
	FlatTree     *xrayUtils.GraphNode
	FullDepTrees []*xrayUtils.GraphNode
	DownloadUrls map[string]string
}

func GetTechDependencyTree(params utils.AuditParams, artifactoryServerDetails *config.ServerDetails, tech techutils.Technology) (depTreeResult DependencyTreeResult, err error) {
	logMessage := fmt.Sprintf("Calculating %s dependencies", tech.ToFormal())
	curationLogMsg, curationCacheFolder, err := getCurationCacheFolderAndLogMsg(params, tech)
	if err != nil {
		return
	}
	// In case it's not curation command these 'curationLogMsg' be empty
	logMessage += curationLogMsg
	log.Info(logMessage + "...")
	if params.Progress() != nil {
		params.Progress().SetHeadlineMsg(logMessage)
	}

	var uniqueDeps []string
	var uniqDepsWithTypes map[string]*xray.DepTreeNode
	startTime := time.Now()

	switch tech {
	case techutils.Maven, techutils.Gradle:
		depTreeResult.FullDepTrees, uniqDepsWithTypes, err = java.BuildDependencyTree(java.DepTreeParams{
			Server:                  artifactoryServerDetails,
			DepsRepo:                params.DepsRepo(),
			IsMavenDepTreeInstalled: params.IsMavenDepTreeInstalled(),
			UseWrapper:              params.UseWrapper(),
			IsCurationCmd:           params.IsCurationCmd(),
			CurationCacheFolder:     curationCacheFolder,
		}, tech)
	case techutils.Npm:
		depTreeResult.FullDepTrees, uniqueDeps, err = npm.BuildDependencyTree(params)
	case techutils.Pnpm:
		depTreeResult.FullDepTrees, uniqueDeps, err = pnpm.BuildDependencyTree(params)
	case techutils.Conan:
		depTreeResult.FullDepTrees, uniqueDeps, err = conan.BuildDependencyTree(params)
	case techutils.Yarn:
		depTreeResult.FullDepTrees, uniqueDeps, err = yarn.BuildDependencyTree(params)
	case techutils.Go:
		depTreeResult.FullDepTrees, uniqueDeps, err = _go.BuildDependencyTree(params)
	case techutils.Pipenv, techutils.Pip, techutils.Poetry:
		depTreeResult.FullDepTrees, uniqueDeps,
			depTreeResult.DownloadUrls, err = python.BuildDependencyTree(&python.AuditPython{
			Server:              artifactoryServerDetails,
			Tool:                pythonutils.PythonTool(tech),
			RemotePypiRepo:      params.DepsRepo(),
			PipRequirementsFile: params.PipRequirementsFile(),
			InstallCommandArgs:  params.InstallCommandArgs(),
			IsCurationCmd:       params.IsCurationCmd(),
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

func createFlatTreeWithTypes(uniqueDeps map[string]*xray.DepTreeNode) (*xrayUtils.GraphNode, error) {
	if err := logDeps(uniqueDeps); err != nil {
		return nil, err
	}
	var uniqueNodes []*xrayUtils.GraphNode
	for uniqueDep, nodeAttr := range uniqueDeps {
		node := &xrayUtils.GraphNode{Id: uniqueDep}
		if nodeAttr != nil {
			node.Types = nodeAttr.Types
			node.Classifier = nodeAttr.Classifier
		}
		uniqueNodes = append(uniqueNodes, node)
	}
	return &xrayUtils.GraphNode{Id: "root", Nodes: uniqueNodes}, nil
}

func createFlatTree(uniqueDeps []string) (*xrayUtils.GraphNode, error) {
	if err := logDeps(uniqueDeps); err != nil {
		return nil, err
	}
	uniqueNodes := []*xrayUtils.GraphNode{}
	for _, uniqueDep := range uniqueDeps {
		uniqueNodes = append(uniqueNodes, &xrayUtils.GraphNode{Id: uniqueDep})
	}
	return &xrayUtils.GraphNode{Id: "root", Nodes: uniqueNodes}, nil
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
	log.Debug("Unique dependencies list:\n" + clientUtils.IndentJsonArray(jsonList))

	return
}

func getCurationCacheFolderAndLogMsg(params utils.AuditParams, tech techutils.Technology) (logMessage string, curationCacheFolder string, err error) {
	if !params.IsCurationCmd() {
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
	if tech == techutils.Maven || tech == techutils.Go {
		return utils.GetCurationCacheFolderByTech(tech)
	}
	return "", nil
}