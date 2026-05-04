package npm

import (
	"errors"
	"fmt"
	"strings"

	biutils "github.com/jfrog/build-info-go/build/utils"
	buildinfo "github.com/jfrog/build-info-go/entities"
	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/npm"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

const (
	IgnoreScriptsFlag     = "--ignore-scripts"
	LegacyPeerDepsFlag    = "--legacy-peer-deps"
	artifactoryApiNpmPath = "/api/npm/"
	// npmAuthTokenSuffix is the npm config-key suffix used to look up a registry's auth token in .npmrc
	// (e.g. //registry.example.com/:_authToken=...). It is a key name, not a credential value.
	npmAuthTokenSuffix = ":_authToken" // #nosec G101 -- Not credentials, this is the npm config-key suffix.
)

// NpmrcRegistryConfig holds Artifactory connection details parsed from the native npm registry config.
type NpmrcRegistryConfig struct {
	ArtifactoryUrl string
	RepoName       string
	AuthToken      string
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
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

	treeDepsParam := createTreeDepsParam(&params)

	clearResolutionServerFunc, err := configNpmResolutionServerIfNeeded(&params)
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
	dependenciesMap, err := biutils.CalculateDependenciesMap(npmExecutablePath, currentDir, packageInfo.BuildInfoModuleId(), treeDepsParam, log.Logger, params.SkipAutoInstall)
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
// Skipped when NpmRunNative is set — the project's existing .npmrc is used as-is for dependency resolution.
func configNpmResolutionServerIfNeeded(params *technologies.BuildInfoBomGeneratorParams) (clearResolutionServerFunc func() error, err error) {
	if params.DependenciesRepository == "" || params.NpmRunNative {
		return
	}
	clearResolutionServerFunc, err = npm.SetArtifactoryAsResolutionServer(params.ServerDetails, params.DependenciesRepository)
	return
}

// GetNativeNpmRegistryConfig reads the npm registry URL from the native npm configuration
// (respecting .npmrc, Volta, and other environment settings) and parses it as an
// Artifactory npm repository URL to extract the RT base URL, repo name, and auth token.
func GetNativeNpmRegistryConfig() (*NpmrcRegistryConfig, error) {
	_, npmExecPath, err := biutils.GetNpmVersionAndExecPath(log.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to locate npm executable: %w", err)
	}

	registryData, _, err := biutils.RunNpmCmd(npmExecPath, "", []string{"config", "get", "registry"}, log.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to read npm registry from native config: %w", err)
	}
	registryUrl := strings.TrimSpace(string(registryData))

	rtBaseUrl, repoName, err := parseArtifactoryNpmRegistryUrl(registryUrl)
	if err != nil {
		return nil, err
	}

	authKey, err := buildNpmAuthTokenKey(registryUrl)
	if err != nil {
		return nil, err
	}
	tokenData, _, _ := biutils.RunNpmCmd(npmExecPath, "", []string{"config", "get", authKey}, log.Logger)
	authToken := strings.TrimSpace(string(tokenData))
	if authToken == "undefined" || authToken == "null" {
		authToken = ""
	}

	return &NpmrcRegistryConfig{
		ArtifactoryUrl: rtBaseUrl,
		RepoName:       repoName,
		AuthToken:      authToken,
	}, nil
}

// buildNpmAuthTokenKey returns the npm config key used to look up the auth token for a
// given registry URL — the registry URL with its scheme stripped and ":_authToken" appended,
// e.g. https://myrt.jfrog.io/artifactory/api/npm/my-repo/ → //myrt.jfrog.io/artifactory/api/npm/my-repo/:_authToken
//
// Returns a typed error (without slicing) when the registry value is malformed and lacks
// the "://" separator, so callers see an actionable message instead of a runtime panic.
// The original URL is preserved verbatim (including any trailing slash) so the lookup
// matches exactly what npm stored in .npmrc.
func buildNpmAuthTokenKey(registryUrl string) (string, error) {
	_, schemeRelative, ok := strings.Cut(registryUrl, "://")
	if !ok {
		return "", fmt.Errorf("npm registry %q is malformed: expected a scheme-prefixed URL (e.g. https://...)", registryUrl)
	}
	if schemeRelative == "" {
		return "", fmt.Errorf("npm registry %q is malformed: missing host", registryUrl)
	}
	return "//" + schemeRelative + npmAuthTokenSuffix, nil
}

// parseArtifactoryNpmRegistryUrl extracts the Artifactory base URL and repository name from
// a registry URL containing "/api/npm/<repo>/".
// Supports both standard URLs (https://<host>/artifactory/api/npm/<repo>/) and
// reverse-proxy URLs where the "/artifactory" context root is stripped
// (e.g. https://npm.company.com/api/npm/<repo>/).
func parseArtifactoryNpmRegistryUrl(registryUrl string) (rtBaseUrl, repoName string, err error) {
	apiNpmIdx := strings.Index(registryUrl, artifactoryApiNpmPath)
	if apiNpmIdx == -1 {
		return "", "", fmt.Errorf("npm registry %q does not appear to be an Artifactory npm registry (expected %q in URL)", registryUrl, artifactoryApiNpmPath)
	}
	rtBaseUrl = registryUrl[:apiNpmIdx] + "/"
	afterApiNpm := registryUrl[apiNpmIdx+len(artifactoryApiNpmPath):]
	repoName = strings.TrimSuffix(afterApiNpm, "/")
	if slashIdx := strings.Index(repoName, "/"); slashIdx != -1 {
		repoName = repoName[:slashIdx]
	}
	if repoName == "" {
		return "", "", fmt.Errorf("could not extract repository name from npm registry URL %q", registryUrl)
	}
	return rtBaseUrl, repoName, nil
}

func createTreeDepsParam(params *technologies.BuildInfoBomGeneratorParams) biutils.NpmTreeDepListParam {
	if params == nil {
		return biutils.NpmTreeDepListParam{
			Args: addIgnoreScriptsFlag([]string{}),
		}
	}
	installCommandArgs := params.InstallCommandArgs
	if params.NpmLegacyPeerDeps {
		installCommandArgs = appendUniqueFlag(installCommandArgs, LegacyPeerDepsFlag)
	}
	npmTreeDepParam := biutils.NpmTreeDepListParam{
		Args:                 addIgnoreScriptsFlag(params.Args),
		InstallCommandArgs:   installCommandArgs,
		IgnoreNodeModules:    params.NpmIgnoreNodeModules,
		OverwritePackageLock: params.NpmOverwritePackageLock,
	}
	return npmTreeDepParam
}

// Add the --ignore-scripts to prevent execution of npm scripts during npm install.
func addIgnoreScriptsFlag(npmArgs []string) []string {
	return appendUniqueFlag(npmArgs, IgnoreScriptsFlag)
}

// appendUniqueFlag appends flag to npmArgs unless it is already present.
func appendUniqueFlag(npmArgs []string, flag string) []string {
	if slices.Contains(npmArgs, flag) {
		return npmArgs
	}
	return append(npmArgs, flag)
}

// Parse the dependencies into an Xray dependency tree format
func parseNpmDependenciesList(dependencies []buildinfo.Dependency, packageInfo *biutils.PackageInfo) (*xrayUtils.GraphNode, []string) {
	treeMap := make(map[string]xray.DepTreeNode)
	for _, dependency := range dependencies {
		dependencyId := techutils.Npm.GetXrayPackageTypeId() + dependency.Id
		for _, requestedByNode := range dependency.RequestedBy {
			parent := techutils.Npm.GetXrayPackageTypeId() + requestedByNode[0]
			depTreeNode, ok := treeMap[parent]
			if ok {
				depTreeNode.Children = appendUniqueChild(depTreeNode.Children, dependencyId)
			} else {
				depTreeNode.Children = []string{dependencyId}
			}
			treeMap[parent] = depTreeNode
		}
	}
	graph, nodeMapTypes := xray.BuildXrayDependencyTree(treeMap, techutils.Npm.GetXrayPackageTypeId()+packageInfo.BuildInfoModuleId())
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
