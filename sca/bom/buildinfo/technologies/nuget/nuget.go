package nuget

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"golang.org/x/exp/maps"

	bidotnet "github.com/jfrog/build-info-go/build/utils/dotnet"
	"github.com/jfrog/build-info-go/build/utils/dotnet/solution"
	"github.com/jfrog/build-info-go/entities"
	biutils "github.com/jfrog/build-info-go/utils"

	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/dotnet"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
)

const (
	nugetPackageTypeIdentifier         = "nuget://"
	csprojFileSuffix                   = ".csproj"
	packageReferenceSyntax             = "PackageReference Include"
	packagesConfigFileName             = "packages.config"
	installCommandName                 = "restore"
	dotnetToolType                     = "dotnet"
	nugetToolType                      = "nuget"
	globalPackagesNotFoundErrorMessage = "could not find global packages path at:"
	artifactoryApiNugetPath            = "/api/nuget/"
	nugetV3PathSegment                 = "v3/"
	nugetV3IndexJsonSuffix             = "/index.json"
)

// Generates a temporary duplicate of the project to execute the 'install' command without impacting the original directory and establishing the JFrog configuration file for Artifactory resolution
// Additionally, re-loads the project's Solution so the dependencies sources will be identified
func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	if p := params.SolutionFilePath; p != "" {
		if info, statErr := os.Stat(filepath.Join(wd, filepath.Base(p))); statErr != nil || info.IsDir() {
			err = fmt.Errorf("--solution-path %q: no solution file named %q in %s "+
				"(the flag is resolved relative to the scanned directory)", p, filepath.Base(p), wd)
			return
		}
	}
	sol, err := solution.Load(wd, solutionFileName(params.SolutionFilePath), params.ExclusionPattern, log.Logger)
	if err != nil && !strings.Contains(err.Error(), globalPackagesNotFoundErrorMessage) {
		// In older NuGet projects that utilize NuGet Cli and package.config, if the project is not installed, the solution.Load function raises an error because it cannot find global package paths.
		// This issue is resolved by executing the 'nuget restore' command followed by running solution.Load again. Therefore, in this scenario, we need to proceed with this process.
		return
	}

	installRequired, err := isInstallRequired(params, sol, params.SkipAutoInstall, wd)
	if err != nil {
		return
	}

	var buildInfo *entities.BuildInfo
	if installRequired {
		buildInfo, err = restoreInTempDirAndGetBuildInfo(params, wd, params.ExclusionPattern)
	} else {
		buildInfo, err = sol.BuildInfo("", log.Logger)
	}

	if err != nil {
		return
	}
	dependencyTree, uniqueDeps = parseNugetDependencyTree(buildInfo)
	return
}

func restoreInTempDirAndGetBuildInfo(params technologies.BuildInfoBomGeneratorParams, wd string, exclusionPattern string) (buildInfo *entities.BuildInfo, err error) {
	var tmpWd string
	tmpWd, err = fileutils.CreateTempDir()
	if err != nil {
		err = fmt.Errorf("failed to create a temporary dir: %w", err)
		return
	}
	defer func() {
		err = errors.Join(err, fileutils.RemoveTempDir(tmpWd))
	}()

	// Exclude Visual Studio inner directory since it is not necessary for the scan process and may cause race condition.
	err = biutils.CopyDir(wd, tmpWd, true, []string{technologies.DotVsRepoSuffix})
	if err != nil {
		err = fmt.Errorf("failed copying project to temp dir: %w", err)
		return
	}

	log.Info("Dependencies sources were not detected nor 'install' command provided. Running 'restore' command")
	sol, err := runDotnetRestoreAndLoadSolution(params, tmpWd, exclusionPattern, params.InsecureTls)
	if err != nil {
		return
	}
	return sol.BuildInfo("", log.Logger)
}

// Verifies whether the execution of an 'install' command is necessary, either because the project isn't installed or because the user has specified an 'install' command
func isInstallRequired(params technologies.BuildInfoBomGeneratorParams, sol solution.Solution, skipAutoInstall bool, curWd string) (bool, error) {
	// If the user has specified an 'install' command, we proceed with executing the 'restore' command even if the project is already installed
	// Additionally, if dependency sources were not identified during the construction of the Solution struct, the project will necessitate an 'install'
	solDependencySourcesExists := len(sol.GetDependenciesSources()) > 0
	solProjectsExists := len(sol.GetProjects()) > 0
	installRequired := !solDependencySourcesExists || !solProjectsExists || params.IsCurationCmd

	if len(params.InstallCommandArgs) > 0 {
		return true, nil
	} else if installRequired && skipAutoInstall {
		return false, &biutils.ErrProjectNotInstalled{UninstalledDir: curWd}
	}
	return installRequired, nil
}

func runDotnetRestoreAndLoadSolution(params technologies.BuildInfoBomGeneratorParams, tmpWd, exclusionPattern string, allowInsecureConnections bool) (sol solution.Solution, err error) {
	toolName := params.InstallCommandName
	if toolName == "" {
		// Determine if the project is a NuGet or .NET project
		toolName, err = getProjectToolName(tmpWd)
		if err != nil {
			err = fmt.Errorf("failed while checking for the project's tool type: %s", err.Error())
			return
		}
	}

	toolType := bidotnet.ConvertNameToToolType(toolName)

	var installCommandArgs []string
	depsRepo := params.DependenciesRepository
	if depsRepo != "" {
		serverDetails := params.ServerDetails
		if params.IsCurationCmd {
			copied := *serverDetails
			copied.ArtifactoryUrl += "api/curation/audit"
			serverDetails = &copied
		}

		log.Info(fmt.Sprintf("Resolving dependencies from '%s' from repo '%s'", serverDetails.Url, depsRepo))

		var configFile *os.File
		configFile, err = dotnet.InitNewConfig(tmpWd, depsRepo, serverDetails, false, allowInsecureConnections)
		if err != nil {
			err = fmt.Errorf("failed while attempting to generate a configuration file for setting up Artifactory as a resolution server")
			return
		}
		installCommandArgs = append(installCommandArgs, toolType.GetTypeFlagPrefix()+"configfile", configFile.Name())
	}

	err = runDotnetRestore(tmpWd, params, toolType, installCommandArgs)
	if err != nil {
		return
	}
	sol, err = solution.Load(tmpWd, solutionFileName(params.SolutionFilePath), exclusionPattern, log.Logger)
	return
}

// solutionFileName returns the base file name of the solution file explicitly provided via the
// SolutionFilePath param (e.g. the '--solution-path' flag), or an empty string if none was
// provided. An empty string tells solution.Load to auto-discover '.sln'/'.slnx' files under the
// given directory, which is ambiguous when more than one solution file is present.
func solutionFileName(solutionFilePath string) string {
	if solutionFilePath == "" {
		return ""
	}
	return filepath.Base(solutionFilePath)
}

// Detects if the project is utilizing either .NET CLI or NuGet CLI, prioritizing .NET CLI.
// Note: For multi-module projects, only one of these tools can be identified and will be uniformly applied across all modules.
func getProjectToolName(wd string) (toolName string, err error) {
	projectConfigFilesPaths, err := getProjectConfigurationFilesPaths(wd)
	if err != nil {
		err = fmt.Errorf("failed while retrieving list of files in '%s': %s", wd, err.Error())
		return
	}

	var packagesConfigFiles []string
	for _, configFilePath := range projectConfigFilesPaths {
		if strings.HasSuffix(configFilePath, csprojFileSuffix) {
			var fileData []byte
			fileData, err = os.ReadFile(configFilePath)
			if err != nil {
				err = fmt.Errorf("failed to read file '%s': %s", configFilePath, err.Error())
				return
			}

			// If the .csproj file contains the <PackageReference> syntax, it signifies the usage of .NET CLI as the tool type
			if strings.Contains(string(fileData), packageReferenceSyntax) {
				toolName = dotnetToolType
				return
			}
		} else {
			packagesConfigFiles = append(packagesConfigFiles, configFilePath)
		}
	}

	// If the <PackageReference> syntax isn't found in any .csproj file but a packages.config file is present, it indicates that the tool type being used is the NuGet CLI
	if len(packagesConfigFiles) > 0 {
		toolName = nugetToolType
		return
	}

	err = errorutils.CheckErrorf("the project's tool type (.NET/NuGet CLI) couldn't be detected. Please execute the 'restore' command.\nNote: Certain entry points allow providing an 'install' command instead of manually executing it")
	return
}

// Returns a slice of absolute paths for the project's configuration files, strictly limited to .csproj files and packages.config files.
func getProjectConfigurationFilesPaths(wd string) (projectConfigFilesPaths []string, err error) {
	err = filepath.WalkDir(wd, func(path string, d fs.DirEntry, innerErr error) error {
		if innerErr != nil {
			return fmt.Errorf("error has occurred when trying to access or traverse the files system: %s", err.Error())
		}

		if strings.HasSuffix(path, csprojFileSuffix) || strings.HasSuffix(path, packagesConfigFileName) {
			var absFilePath string
			absFilePath, innerErr = filepath.Abs(path)
			if innerErr != nil {
				return fmt.Errorf("couldn't retrieve file's absolute path for './%s':%s", path, innerErr.Error())
			}
			projectConfigFilesPaths = append(projectConfigFilesPaths, absFilePath)
		}
		return nil
	})
	return
}

func getEnvVariablesForCurationAudit() ([]string, error) {
	curationCache, err := utils.GetCurationNugetCacheFolder()
	if err != nil {
		return nil, err
	}

	// Create Curation cache folders to avoid polluting the default cache
	if err := os.MkdirAll(filepath.Join(curationCache, "packages"), os.ModePerm); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(curationCache, "cache"), os.ModePerm); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(curationCache, "scratch"), os.ModePerm); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(curationCache, "cache"), os.ModePerm); err != nil {
		return nil, err
	}

	// Configure NuGet to use the Curation cache folders
	if err := os.Setenv("NUGET_PACKAGES", filepath.Join(curationCache, "packages")); err != nil {
		return nil, err
	}
	if err := os.Setenv("NUGET_SCRATCH", filepath.Join(curationCache, "scratch")); err != nil {
		return nil, err
	}
	if err := os.Setenv("NUGET_PLUGINS_CACHE", filepath.Join(curationCache, "plugins")); err != nil {
		return nil, err
	}
	if err := os.Setenv("NUGET_HTTP_CACHE", filepath.Join(curationCache, "cache")); err != nil {
		return nil, err
	}
	return os.Environ(), nil
}

func runDotnetRestore(wd string, params technologies.BuildInfoBomGeneratorParams, toolType bidotnet.ToolchainType, commandExtraArgs []string) (err error) {
	var completeCommandArgs []string
	if len(params.InstallCommandArgs) > 0 {
		// If the user has specified an 'install' command, we execute the command that has been provided.
		completeCommandArgs = append(completeCommandArgs, params.InstallCommandName)
		completeCommandArgs = append(completeCommandArgs, params.InstallCommandArgs...)
	} else {
		completeCommandArgs = append(completeCommandArgs, toolType.String(), installCommandName)
	}

	// Check for solution file path from JF CA arguments for specific solution when we have more than one solution file
	if slnFile := solutionFileName(params.SolutionFilePath); slnFile != "" {
		completeCommandArgs = append(completeCommandArgs, slnFile)
		log.Info(fmt.Sprintf("Using solution file: %s", slnFile))
	}

	// We include the flag that allows resolution from an Artifactory server, if it exists.
	executable, args, err := validateInputCommand(append(completeCommandArgs, commandExtraArgs...))
	if err != nil {
		return err
	}
	// #nosec G702 -- executable restricted to dotnet/nuget via validateInputCommand; args are project paths and known flags
	command := exec.Command(executable, args...)
	command.Dir = wd
	if params.IsCurationCmd {
		command.Env, err = getEnvVariablesForCurationAudit()
		if err != nil {
			return err
		}

		// Specify a custom output directory to force NuGet to rebuild all the dependencies
		if toolType.String() == nugetToolType {
			command.Args = append(command.Args, "-OutputDirectory", "cur_output")
		}
	}
	log.Info(command.String())
	output, err := command.CombinedOutput()
	if err != nil {
		err = translateRestoreError(output, err, wd)
	}
	return
}

// Validates the executable is either dotnet or nuget to prevent command injection (G702)
func validateInputCommand(completeCommandArgs []string) (string, []string, error) {
	executable := completeCommandArgs[0]
	if base := filepath.Base(executable); base != dotnetToolType && base != nugetToolType {
		return "", nil, errorutils.CheckErrorf("invalid install command executable: %q (allowed: %s, %s)", executable, dotnetToolType, nugetToolType)
	}
	return executable, completeCommandArgs[1:], nil
}

// NuGetRegistrySourceConfig holds Artifactory connection details parsed from a native
// NuGet/.NET CLI configured package source.
type NuGetRegistrySourceConfig struct {
	SourceName     string
	ArtifactoryUrl string
	RepoName       string
}

type nugetSource struct {
	name string
	url  string
}

// sourceHeaderRegex matches a single "Registered Sources" entry header line, shared by both
// 'dotnet nuget list source' and 'nuget sources List' (detailed format), e.g.:
//
//  1. MyArtifactory [Enabled]
var sourceHeaderRegex = regexp.MustCompile(`^\d+\.\s*(.+?)\s*\[(Enabled|Disabled)\]$`)

// GetNativeNuGetRegistryConfig resolves NuGet's Artifactory source natively:
//  1. Detect the project's tool (.NET CLI or legacy NuGet CLI).
//  2. List that tool's configured sources ('dotnet nuget list source' / 'nuget sources List').
//  3. Pick the source whose host matches the 'jf c' configured Artifactory server.
//
// Returns a clear error when no configured source matches.
func GetNativeNuGetRegistryConfig(serverDetails *config.ServerDetails) (*NuGetRegistrySourceConfig, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	toolName, err := getProjectToolName(wd)
	if err != nil {
		return nil, fmt.Errorf("failed while checking for the project's tool type: %w", err)
	}

	sources, err := listNativeNuGetSources(toolName)
	if err != nil {
		return nil, err
	}

	return selectMatchingNuGetSource(sources, serverDetails.GetArtifactoryUrl(), toolName)
}

// listNativeNuGetSources runs the tool-appropriate list-sources command and parses its output.
func listNativeNuGetSources(toolName string) ([]nugetSource, error) {
	var cmd *exec.Cmd
	switch toolName {
	case dotnetToolType:
		cmd = exec.Command(dotnetToolType, "nuget", "list", "source")
	case nugetToolType:
		cmd = exec.Command(nugetToolType, "sources", "List")
	default:
		return nil, errorutils.CheckErrorf("unsupported tool type %q for native NuGet source resolution", toolName)
	}
	// #nosec G204 -- executable and args are hardcoded above, restricted to dotnet/nuget.
	output, err := cmd.CombinedOutput()
	if err != nil {
		if trimmedOutput := strings.TrimSpace(string(output)); trimmedOutput != "" {
			return nil, fmt.Errorf("failed running '%s' to list the configured NuGet sources: %s", cmd.String(), trimmedOutput)
		}
		return nil, fmt.Errorf("failed running '%s' to list the configured NuGet sources: %w", cmd.String(), err)
	}
	return parseNuGetSourcesOutput(string(output)), nil
}

// parseNuGetSourcesOutput parses the "Registered Sources" detailed-format output shared by
// 'dotnet nuget list source' and 'nuget sources List', returning only the enabled sources.
func parseNuGetSourcesOutput(output string) []nugetSource {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}

	var sources []nugetSource
	for i := 0; i < len(lines); i++ {
		match := sourceHeaderRegex.FindStringSubmatch(lines[i])
		if match == nil || match[2] != "Enabled" {
			continue
		}
		if i+1 >= len(lines) || sourceHeaderRegex.MatchString(lines[i+1]) {
			// No URL line follows this source header - skip rather than misreading the next header as a URL.
			continue
		}
		sources = append(sources, nugetSource{name: match[1], url: lines[i+1]})
	}
	return sources
}

// selectMatchingNuGetSource returns the configured source whose host matches the configured
// Artifactory server's host, parsed into its Artifactory base URL and repository name.
// Returns a clear error when no configured source matches.
func selectMatchingNuGetSource(sources []nugetSource, artifactoryUrl, toolName string) (*NuGetRegistrySourceConfig, error) {
	artifactoryHost, err := schemeAndHostOf(artifactoryUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the configured Artifactory URL %q: %w", artifactoryUrl, err)
	}

	var matched []nugetSource
	for _, source := range sources {
		sourceHost, hostErr := schemeAndHostOf(source.url)
		if hostErr != nil || !strings.EqualFold(sourceHost, artifactoryHost) {
			continue
		}
		matched = append(matched, source)
	}
	if len(matched) > 1 {
		names := make([]string, len(matched))
		for i, source := range matched {
			names[i] = source.name
		}
		log.Warn(fmt.Sprintf("Multiple configured NuGet sources match the Artifactory host %q: %s. Using %q; remove or rename the unused sources to avoid ambiguity.",
			artifactoryHost, strings.Join(names, ", "), matched[0].name))
	}
	if len(matched) > 0 {
		rtBaseUrl, repoName, parseErr := parseArtifactoryNugetSourceUrl(matched[0].url)
		if parseErr != nil {
			return nil, fmt.Errorf("NuGet source %q (%s) matches the configured Artifactory host %q but is not a recognizable Artifactory NuGet repository URL: %w", matched[0].name, matched[0].url, artifactoryHost, parseErr)
		}
		return &NuGetRegistrySourceConfig{SourceName: matched[0].name, ArtifactoryUrl: rtBaseUrl, RepoName: repoName}, nil
	}

	return nil, errorutils.CheckErrorf(
		"could not find a NuGet source configured. Add one via Artifactory's %s 'Set me up' instructions "+
			"(run '%s' to view your currently configured sources)",
		setMeUpClientName(toolName), listSourcesCommandString(toolName))
}

// setMeUpClientName returns the name of the 'Set me up' client tab matching toolName, so the
// error points the user at the same tab they'd need to follow ('.NET' vs 'NuGet').
func setMeUpClientName(toolName string) string {
	if toolName == nugetToolType {
		return "NuGet"
	}
	return ".NET"
}

func listSourcesCommandString(toolName string) string {
	if toolName == nugetToolType {
		return "nuget sources List"
	}
	return "dotnet nuget list source"
}

// parseArtifactoryNugetSourceUrl extracts the Artifactory base URL and repository name from a
// NuGet source URL containing "/api/nuget/<repo>" (V2) or "/api/nuget/v3/<repo>/index.json" (V3).
// Supports both standard URLs (https://<host>/artifactory/api/nuget/...) and reverse-proxy URLs
// where the "/artifactory" context root is stripped (e.g. https://nuget.company.com/api/nuget/...).
func parseArtifactoryNugetSourceUrl(sourceUrl string) (rtBaseUrl, repoName string, err error) {
	apiIdx := strings.Index(sourceUrl, artifactoryApiNugetPath)
	if apiIdx == -1 {
		return "", "", fmt.Errorf("NuGet source %q does not appear to be an Artifactory NuGet registry (expected %q in URL)", sourceUrl, artifactoryApiNugetPath)
	}
	rtBaseUrl = sourceUrl[:apiIdx] + "/"
	afterApiNuget := sourceUrl[apiIdx+len(artifactoryApiNugetPath):]
	afterApiNuget = strings.TrimPrefix(afterApiNuget, nugetV3PathSegment)
	afterApiNuget = strings.TrimSuffix(afterApiNuget, "/")
	// The repository name is always the first path segment, whether followed by nothing (V2),
	// or by "/index.json" (V3) or extra path segments.
	repoName, _, _ = strings.Cut(afterApiNuget, "/")
	if repoName == "" || repoName == strings.TrimPrefix(nugetV3IndexJsonSuffix, "/") {
		return "", "", fmt.Errorf("could not extract repository name from NuGet source URL %q", sourceUrl)
	}
	return rtBaseUrl, repoName, nil
}

// schemeAndHostOf returns "scheme://host[:port]" of the given URL.
func schemeAndHostOf(rawUrl string) (string, error) {
	parsed, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("no host found in URL %q", rawUrl)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func parseNugetDependencyTree(buildInfo *entities.BuildInfo) (nodes []*xrayUtils.GraphNode, allUniqueDeps []string) {
	uniqueDepsSet := datastructures.MakeSet[string]()
	for _, module := range buildInfo.Modules {
		treeMap := make(map[string]xray.DepTreeNode)
		for _, dependency := range module.Dependencies {
			dependencyId := nugetPackageTypeIdentifier + dependency.Id
			parent := nugetPackageTypeIdentifier + dependency.RequestedBy[0][0]
			depTreeNode, ok := treeMap[parent]
			if ok {
				depTreeNode.Children = append(depTreeNode.Children, dependencyId)
			} else {
				depTreeNode.Children = []string{dependencyId}
			}
			treeMap[parent] = depTreeNode
		}
		dependencyTree, uniqueDeps := xray.BuildXrayDependencyTree(treeMap, nugetPackageTypeIdentifier+module.Id)
		nodes = append(nodes, dependencyTree)
		for _, uniqueDep := range maps.Keys(uniqueDeps) {
			uniqueDepsSet.Add(uniqueDep)
		}
	}
	allUniqueDeps = uniqueDepsSet.ToSlice()
	return
}
