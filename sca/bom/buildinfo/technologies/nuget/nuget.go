package nuget

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
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
)

// Generates a temporary duplicate of the project to execute the 'install' command without impacting the original directory and establishing the JFrog configuration file for Artifactory resolution
// Additionally, re-loads the project's Solution so the dependencies sources will be identified
func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTree []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	sol, err := solution.Load(wd, "", params.ExclusionPattern, log.Logger)
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
	// Set up an Artifactory server as a resolution server if needed
	depsRepo := params.DependenciesRepository
	if depsRepo != "" {
		// var serverDetails *config.ServerDetails
		// serverDetails, err = params.ServerDetails()

		// Use the pass-through URL if the project is being restored as part of Curation Audit
		if params.IsCurationCmd {
			params.ServerDetails.ArtifactoryUrl += "api/curation/audit"
		}
		if err != nil {
			err = fmt.Errorf("failed to get server details: %s", err.Error())
			return
		}

		log.Info(fmt.Sprintf("Resolving dependencies from '%s' from repo '%s'", params.ServerDetails.Url, depsRepo))

		var configFile *os.File
		configFile, err = dotnet.InitNewConfig(tmpWd, depsRepo, params.ServerDetails, false, allowInsecureConnections)
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
	sol, err = solution.Load(tmpWd, "", exclusionPattern, log.Logger)
	return
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

	// We include the flag that allows resolution from an Artifactory server, if it exists.
	completeCommandArgs = append(completeCommandArgs, commandExtraArgs...)
	command := exec.Command(completeCommandArgs[0], completeCommandArgs[1:]...)
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
		err = errorutils.CheckErrorf("'dotnet restore' command failed: %s - %s", err.Error(), output)
	}
	return
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
