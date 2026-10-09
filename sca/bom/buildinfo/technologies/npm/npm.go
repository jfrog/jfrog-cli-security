package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	biutils "github.com/jfrog/build-info-go/build/utils"
	buildinfo "github.com/jfrog/build-info-go/entities"
	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/npm"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

const (
	IgnoreScriptsFlag     = "--ignore-scripts"
	LegacyPeerDepsFlag    = "--legacy-peer-deps"
	disableWorkspacesFlag = "--workspaces=false"
	npmConfigRegistryEnv  = "npm_config_registry"
	npmConfigEnvPrefix    = "npm_config_"
	// npmScopedRegistrySuffix marks an npm config key that overrides the registry for one scope
	// (e.g. "@myorg:registry"); it always wins over the plain "registry" key for that scope.
	npmScopedRegistrySuffix = ":registry"
	artifactoryApiNpmPath   = "/api/npm/"
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
	if params.IsCurationCmd && isAnonymousServer(params.ServerDetails) {
		return setAnonymousNpmRegistry(params.ServerDetails, params.DependenciesRepository)
	}
	clearResolutionServerFunc, err = npm.SetArtifactoryAsResolutionServer(params.ServerDetails, params.DependenciesRepository)
	return
}

func isAnonymousServer(server *config.ServerDetails) bool {
	return server != nil && server.User == "" && server.Password == "" && server.AccessToken == ""
}

// setAnonymousNpmRegistry points npm at the repo with no credentials (the usual setup fails anonymously:
// /api/npm/auth returns 400), also overriding any existing scoped registry so it isn't bypassed.
func setAnonymousNpmRegistry(server *config.ServerDetails, repo string) (restore func() error, err error) {
	registry := strings.TrimSuffix(server.ArtifactoryUrl, "/") + artifactoryApiNpmPath + repo
	envKeys, err := anonymousNpmRegistryEnvKeys()
	if err != nil {
		return nil, err
	}
	type previousEnv struct {
		value  string
		exists bool
	}
	previous := make(map[string]previousEnv, len(envKeys))
	for _, key := range envKeys {
		value, exists := os.LookupEnv(key)
		previous[key] = previousEnv{value, exists}
	}
	restore = func() error {
		var restoreErr error
		for _, key := range envKeys {
			prev := previous[key]
			if prev.exists {
				restoreErr = errors.Join(restoreErr, os.Setenv(key, prev.value))
			} else {
				restoreErr = errors.Join(restoreErr, os.Unsetenv(key))
			}
		}
		return errorutils.CheckError(restoreErr)
	}
	for _, key := range envKeys {
		if err = os.Setenv(key, registry); err != nil {
			return nil, errors.Join(errorutils.CheckError(err), restore())
		}
	}
	log.Info(fmt.Sprintf("Resolving dependencies anonymously from '%s' from repo '%s'", server.Url, repo))
	return
}

// anonymousNpmRegistryEnvKeys returns the env vars to set so the default registry and any scoped
// ("@scope:registry") entries all resolve through the anonymous curation repo.
func anonymousNpmRegistryEnvKeys() ([]string, error) {
	envKeys := []string{npmConfigRegistryEnv}
	scopedKeys, err := listScopedRegistryKeys()
	if err != nil {
		return nil, err
	}
	for _, key := range scopedKeys {
		envKeys = append(envKeys, npmConfigEnvPrefix+key)
	}
	return envKeys, nil
}

// listScopedRegistryKeys returns the "@scope:registry" keys currently configured for npm (e.g. from .npmrc).
func listScopedRegistryKeys() ([]string, error) {
	_, npmExecPath, err := biutils.GetNpmVersionAndExecPath(log.Logger)
	if err != nil {
		return nil, err
	}
	data, _, err := biutils.RunNpmCmd(npmExecPath, "", []string{"config", "list", "--json"}, log.Logger)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	var npmConfig map[string]any
	if err = json.Unmarshal(data, &npmConfig); err != nil {
		return nil, errorutils.CheckError(fmt.Errorf("failed to parse npm config: %w", err))
	}
	var keys []string
	for key := range npmConfig {
		if strings.HasPrefix(key, "@") && strings.HasSuffix(key, npmScopedRegistrySuffix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// GetNativeNpmRegistryConfig reads the npm registry URL from the native npm configuration
// (respecting .npmrc, Volta, and other environment settings) and parses it as an
// Artifactory npm repository URL to extract the RT base URL, repo name, and auth token.
func GetNativeNpmRegistryConfig() (*NpmrcRegistryConfig, error) {
	npmVersion, npmExecPath, err := biutils.GetNpmVersionAndExecPath(log.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to locate npm executable: %w", err)
	}
	disableWorkspaces := npmVersion.AtLeast("7.0.0")

	registryData, _, err := biutils.RunNpmCmd(npmExecPath, "", npmConfigGetArgs("registry", disableWorkspaces), log.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to read npm registry from native config: %w", err)
	}
	registryUrl := strings.TrimSpace(string(registryData))

	rtBaseUrl, repoName, err := ParseArtifactoryNpmRegistryUrl(registryUrl)
	if err != nil {
		return nil, err
	}

	authKey, err := BuildNpmAuthTokenKey(registryUrl)
	if err != nil {
		return nil, err
	}
	tokenData, _, _ := biutils.RunNpmCmd(npmExecPath, "", npmConfigGetArgs(authKey, disableWorkspaces), log.Logger)
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

// GetNpmConfigValue runs 'npm config get <key>' from workingDir, respecting the same
// .npmrc/env resolution a real npm command from that directory would see.
func GetNpmConfigValue(workingDir, key string) (string, error) {
	npmVersion, npmExecPath, err := biutils.GetNpmVersionAndExecPath(log.Logger)
	if err != nil {
		return "", fmt.Errorf("failed to locate npm executable: %w", err)
	}
	disableWorkspaces := npmVersion.AtLeast("7.0.0")
	data, _, err := biutils.RunNpmCmd(npmExecPath, workingDir, npmConfigGetArgs(key, disableWorkspaces), log.Logger)
	if err != nil {
		return "", fmt.Errorf("failed to run 'npm config get %s': %w", key, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func npmConfigGetArgs(key string, disableWorkspaces bool) []string {
	args := []string{"config", "get", key}
	if disableWorkspaces {
		// npm 7+ can reject `npm config get` inside workspace packages unless workspaces are disabled.
		args = append(args, disableWorkspacesFlag)
	}
	return args
}

// BuildNpmAuthTokenKey returns the npm config key used to look up the auth token for a
// given registry URL — the registry URL with its scheme stripped and ":_authToken" appended,
// e.g. https://myrt.jfrog.io/artifactory/api/npm/my-repo/ → //myrt.jfrog.io/artifactory/api/npm/my-repo/:_authToken
//
// Returns a typed error (without slicing) when the registry value is malformed and lacks
// the "://" separator, so callers see an actionable message instead of a runtime panic.
// The original URL is preserved verbatim (including any trailing slash) so the lookup
// matches exactly what npm stored in .npmrc.
// Exported so that other package-manager clients (e.g. pnpm) can reuse the same logic.
func BuildNpmAuthTokenKey(registryUrl string) (string, error) {
	_, schemeRelative, ok := strings.Cut(registryUrl, "://")
	if !ok {
		return "", fmt.Errorf("npm registry %q is malformed: expected a scheme-prefixed URL (e.g. https://...)", registryUrl)
	}
	if schemeRelative == "" {
		return "", fmt.Errorf("npm registry %q is malformed: missing host", registryUrl)
	}
	return "//" + schemeRelative + npmAuthTokenSuffix, nil
}

// ParseArtifactoryNpmRegistryUrl extracts the Artifactory base URL and repository name from
// a registry URL containing "/api/npm/<repo>/".
// Supports both standard URLs (https://<host>/artifactory/api/npm/<repo>/) and
// reverse-proxy URLs where the "/artifactory" context root is stripped
// (e.g. https://npm.company.com/api/npm/<repo>/).
// Exported so that other package-manager clients (e.g. pnpm) can reuse the same
// Artifactory URL parsing without duplicating logic.
func ParseArtifactoryNpmRegistryUrl(registryUrl string) (rtBaseUrl, repoName string, err error) {
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
	if params.NpmForceLogsMax != "" {
		// Appended last so this flag can't be shadowed by an earlier one.
		installCommandArgs = append(installCommandArgs, "--logs-max", params.NpmForceLogsMax)
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
