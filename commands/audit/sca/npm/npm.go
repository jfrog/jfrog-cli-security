package npm

import (
	"errors"
	"fmt"
	biutils "github.com/jfrog/build-info-go/build/utils"
	buildinfo "github.com/jfrog/build-info-go/entities"
	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/npm"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

const (
	IgnoreScriptsFlag = "--ignore-scripts"
)

func BuildDependencyTree(params utils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	npmVersion, npmExecutablePath, err := biutils.GetNpmVersionAndExecPath(log.Logger)
	if err != nil {
		return
	}
	packageInfo, err := biutils.ReadPackageInfoFromPackageJsonIfExists(currentDir, npmVersion)
	if err != nil {
		return
	}

	treeDepsParam := createTreeDepsParam(params)

	clearResolutionServerFunc, err := configNpmResolutionServerIfNeeded(params)
	if err != nil {
		err = fmt.Errorf("failed while configuring a resolution server: %s", err.Error())
		return
	}
	defer func() {
		if clearResolutionServerFunc != nil {
			err = errors.Join(err, clearResolutionServerFunc())
		}
	}()

	// Calculate npm dependencies
	dependenciesMap, err := biutils.CalculateDependenciesMap(npmExecutablePath, currentDir, packageInfo.BuildInfoModuleId(), treeDepsParam, log.Logger, params.SkipAutoInstall())
	if err != nil {
		log.Info("Used npm version:", npmVersion.GetVersion())
		return
	}
	var dependenciesList []buildinfo.Dependency
	for _, dependency := range dependenciesMap {
		dependenciesList = append(dependenciesList, dependency.Dependency)
	}
	// Parse the dependencies into Xray dependency tree format
	dependencyTree, uniqueDeps := parseNpmDependenciesList(dependenciesList, packageInfo)
	dependencyTrees = []*xrayUtils.GraphNode{dependencyTree}
	return
}

// Generates a .npmrc file to configure an Artifactory server as the resolver server.
func configNpmResolutionServerIfNeeded(params utils.AuditParams) (clearResolutionServerFunc func() error, err error) {
	// If we don't have an artifactory repo's name we don't need to configure any Artifactory server as resolution server
	if params.DepsRepo() == "" {
		return
	}

	serverDetails, err := params.ServerDetails()
	if err != nil {
		return
	}

	clearResolutionServerFunc, err = npm.SetArtifactoryAsResolutionServer(serverDetails, params.DepsRepo())
	return
}

func createTreeDepsParam(params utils.AuditParams) biutils.NpmTreeDepListParam {
	if params == nil {
		return biutils.NpmTreeDepListParam{
			Args: addIgnoreScriptsFlag([]string{}),
		}
	}
	npmTreeDepParam := biutils.NpmTreeDepListParam{
		Args:               addIgnoreScriptsFlag(params.Args()),
		InstallCommandArgs: params.InstallCommandArgs(),
	}
	if npmParams, ok := params.(utils.AuditNpmParams); ok {
		npmTreeDepParam.IgnoreNodeModules = npmParams.NpmIgnoreNodeModules()
		npmTreeDepParam.OverwritePackageLock = npmParams.NpmOverwritePackageLock()
	}
	return npmTreeDepParam
}

// Add the --ignore-scripts to prevent execution of npm scripts during npm install.
func addIgnoreScriptsFlag(npmArgs []string) []string {
	if !slices.Contains(npmArgs, IgnoreScriptsFlag) {
		return append(npmArgs, IgnoreScriptsFlag)
	}
	return npmArgs
}

// Parse the dependencies into an Xray dependency tree format
func parseNpmDependenciesList(dependencies []buildinfo.Dependency, packageInfo *biutils.PackageInfo) (*xrayUtils.GraphNode, []string) {
	treeMap := make(map[string]xray.DepTreeNode)
	for _, dependency := range dependencies {
		dependencyId := techutils.Npm.GetPackageTypeId() + dependency.Id
		for _, requestedByNode := range dependency.RequestedBy {
			parent := techutils.Npm.GetPackageTypeId() + requestedByNode[0]
			depTreeNode, ok := treeMap[parent]
			if ok {
				depTreeNode.Children = appendUniqueChild(depTreeNode.Children, dependencyId)
			} else {
				depTreeNode.Children = []string{dependencyId}
			}
			treeMap[parent] = depTreeNode
		}
	}
	graph, nodeMapTypes := xray.BuildXrayDependencyTree(treeMap, techutils.Npm.GetPackageTypeId()+packageInfo.BuildInfoModuleId())
	return graph, maps.Keys(nodeMapTypes)
}

func appendUniqueChild(children []string, candidateDependency string) []string {
	for _, existingChild := range children {
		if existingChild == candidateDependency {
			return children
		}
	}
	return append(children, candidateDependency)
}
