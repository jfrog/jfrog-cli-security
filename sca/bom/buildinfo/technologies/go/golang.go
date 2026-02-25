package _go

import (
	"errors"
	"strings"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	goutils "github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/golang"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	goPackageTypeIdentifier = "go://"
	goSourceCodePrefix      = "github.com/golang/go:v"
)

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}

	goProxyParams := goutils.GoProxyUrlParams{Direct: true}
	// in case of curation command, we set an alternative cache folder when building go dep tree,
	// also, it's not using the "direct" option, artifacts should be resolved only from the configured repo.
	if params.IsCurationCmd {
		goProxyParams.EndpointPrefix = coreutils.CurationPassThroughApi
		goProxyParams.Direct = false
		projCacheDir, errCacheFolder := utils.GetCurationCacheFolderByTech(techutils.Go)
		if errCacheFolder != nil {
			err = errCacheFolder
			return
		}
		if err = goutils.SetGoModCache(projCacheDir); err != nil {
			return
		}
	}

	remoteGoRepo := params.DependenciesRepository
	if remoteGoRepo != "" {
		if err = goutils.SetArtifactoryAsResolutionServer(params.ServerDetails, remoteGoRepo, goProxyParams); err != nil {
			return
		}
	}

	// Calculate go dependencies graph
	dependenciesGraph, err := getDependenciesGraph(currentDir)
	if err != nil || len(dependenciesGraph) == 0 {
		return
	}
	var dependenciesList map[string]bool
	if !params.IsInstallMode {
		dependenciesList, err = getDependenciesList(currentDir, handleCurationGoError)
		if err != nil {
			return
		}
	}
	// Get root module name
	rootModuleName, err := goutils.GetModuleName(currentDir)
	if err != nil {
		return
	}
	// Parse the dependencies into Xray dependency tree format
	rootNode := &xrayUtils.GraphNode{
		Id:    goPackageTypeIdentifier + rootModuleName,
		Nodes: []*xrayUtils.GraphNode{},
	}
	uniqueDepsSet := datastructures.MakeSet[string]()
	populateGoDependencyTree(rootNode, dependenciesGraph, dependenciesList, uniqueDepsSet, params.IsInstallMode)

	// In case of curation command, go version is not relevant as it can't be resolved from go repo
	if !params.IsCurationCmd {
		if gotErr := addGoVersionToTree(rootNode, uniqueDepsSet); gotErr != nil {
			err = gotErr
			return
		}
	}

	dependencyTree = []*xrayUtils.GraphNode{rootNode}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

func addGoVersionToTree(rootNode *xrayUtils.GraphNode, uniqueDepsSet *datastructures.Set[string]) error {
	goVersionDependency, err := getGoVersionAsDependency()
	if err != nil {
		return err
	}
	rootNode.Nodes = append(rootNode.Nodes, goVersionDependency)
	uniqueDepsSet.Add(goVersionDependency.Id)
	return err
}

func handleCurationGoError(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	if msgToUser := technologies.GetMsgToUserForCurationBlock(true, techutils.Go, err.Error()); msgToUser != "" {
		return true, errors.New(msgToUser)
	}
	return false, nil
}

func populateGoDependencyTree(currNode *xrayUtils.GraphNode, dependenciesGraph map[string][]string, dependenciesList map[string]bool, uniqueDepsSet *datastructures.Set[string], isInstallMode bool) {
	if currNode.NodeHasLoop() {
		return
	}
	uniqueDepsSet.Add(currNode.Id)
	currDepChildren := dependenciesGraph[strings.TrimPrefix(currNode.Id, goPackageTypeIdentifier)]
	// Recursively create & append all node's dependencies.
	for _, childName := range currDepChildren {
		if isInstallMode {
			if isGoToolchainDep(childName) {
				continue
			}
		} else if !dependenciesList[childName] {
			// 'go list all' is more accurate than 'go graph' so we filter out deps that don't exist in go list
			continue
		}
		childNode := &xrayUtils.GraphNode{
			Id:     goPackageTypeIdentifier + childName,
			Nodes:  []*xrayUtils.GraphNode{},
			Parent: currNode,
		}
		currNode.Nodes = append(currNode.Nodes, childNode)
		populateGoDependencyTree(childNode, dependenciesGraph, dependenciesList, uniqueDepsSet, isInstallMode)
	}
}

func getGoVersionAsDependency() (*xrayUtils.GraphNode, error) {
	goVersion, err := biutils.GetParsedGoVersion()
	if err != nil {
		return nil, err
	}
	// Convert "go1.17.3" to "github.com/golang/go:v1.17.3"
	goVersionID := strings.ReplaceAll(goVersion.GetVersion(), "go", goSourceCodePrefix)
	return &xrayUtils.GraphNode{
		Id: goPackageTypeIdentifier + goVersionID,
	}, nil
}

func getDependenciesList(projectDir string, errorFunc biutils.HandleErrorFunc) (map[string]bool, error) {
	deps, err := biutils.GetDependenciesList(projectDir, log.Logger, errorFunc)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	return deps, nil
}

func getDependenciesGraph(projectDir string) (map[string][]string, error) {
	deps, err := biutils.GetDependenciesGraph(projectDir, log.Logger)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	return deps, nil
}

func isGoToolchainDep(dep string) bool {
	return strings.HasPrefix(dep, "toolchain@") || strings.HasPrefix(dep, "go@")
}
