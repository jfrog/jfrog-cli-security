package yarn

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	biutils "github.com/jfrog/build-info-go/utils"

	"golang.org/x/exp/maps"

	"github.com/jfrog/build-info-go/build"
	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/yarn"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/ioutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	// Do not execute any scripts defined in the project package.json and its dependencies.
	v1IgnoreScriptsFlag = "--ignore-scripts"
	// Run yarn install without printing installation log.
	v1SilentFlag = "--silent"
	// Disable interactive prompts, like when there’s an invalid version of a dependency.
	v1NonInteractiveFlag = "--non-interactive"
	// Ignores any build scripts
	v2SkipBuildFlag = "--skip-builds"
	// Skips linking and fetch only packages that are missing from yarn.lock file
	v3UpdateLockfileFlag = "--mode=update-lockfile"
	// Ignores any build scripts
	v3SkipBuildFlag     = "--mode=skip-build"
	yarnV2Version       = "2.0.0"
	yarnV3Version       = "3.0.0"
	yarnV4Version       = "4.0.0"
	nodeModulesRepoName = "node_modules"
)

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	executablePath, err := bibuildutils.GetYarnExecutable()
	if errorutils.CheckError(err) != nil {
		return
	}

	// Curation issues per-package HEAD requests to Artifactory, which only
	// return meaningful curation JSON for packages Artifactory has resolved.
	// The jfrog-cli yarn integration only resolves through Artifactory for
	// Yarn V2/V3, so V1 and V4 would silently bypass Artifactory and produce
	// unreliable curation results. Reject those versions up front.
	//
	// Additionally, yarn (unlike npm with --package-lock-only) has no way to
	// generate a fresh lockfile without fetching the package tarballs (even
	// --mode=update-lockfile fetches packages that are missing from the
	// lockfile). When the configured registry is a curation-enabled repository,
	// blocked packages cause those fetches to fail with HTTP 403, so curation
	// cannot generate yarn.lock on the user's behalf. Require a pre-existing
	// yarn.lock for curation and let the user produce it themselves against a
	// non-curation registry.
	if params.IsCurationCmd {
		if err = verifyYarnVersionSupportedForCuration(executablePath, currentDir); err != nil {
			return
		}
		if err = verifyYarnLockExistsForCuration(currentDir); err != nil {
			return
		}
	}

	packageInfo, err := bibuildutils.ReadPackageInfoFromPackageJsonIfExists(currentDir, nil)
	if errorutils.CheckError(err) != nil {
		return
	}

	installRequired, err := isInstallRequired(currentDir, params.InstallCommandArgs, params.SkipAutoInstall)
	if err != nil {
		return
	}

	if installRequired {
		err = configureYarnResolutionServerAndRunInstall(params, currentDir, executablePath)
		if err != nil {
			err = fmt.Errorf("failed to configure an Artifactory resolution server or running and install command: %s", err.Error())
			return
		}
	}

	// Calculate Yarn dependencies
	dependenciesMap, root, err := bibuildutils.GetYarnDependencies(executablePath, currentDir, packageInfo, log.Logger, params.AllowPartialResults)
	if err != nil {
		return
	}
	// build-info-go's buildYarnV2DependencyMap finds the root workspace by
	// matching dependency entries that start with packageInfo.FullName()+"@".
	// When package.json has no "name" (or no "version"), Yarn V2+ falls back
	// to a synthesized workspace identifier such as "root-workspace-XXXXXXXX",
	// which never matches that prefix — so root comes back nil and a naive
	// deref would panic. Recover by scanning the dependency map for the root
	// workspace entry that yarn V2+ always emits as "<name>@workspace:.".
	if root == nil {
		root = findYarnWorkspaceRoot(dependenciesMap)
	}
	if root == nil {
		err = errorutils.CheckErrorf("could not identify the root workspace from yarn dependency output")
		return
	}
	// Parse the dependencies into Xray dependency tree format
	rootXrayId, err := getXrayDependencyId(root)
	if err != nil {
		return
	}
	dependencyTree, uniqueDeps, err := parseYarnDependenciesMap(dependenciesMap, rootXrayId)
	if err != nil {
		return
	}
	dependencyTrees = []*xrayUtils.GraphNode{dependencyTree}
	return
}

// verifyYarnVersionSupportedForCuration rejects Yarn versions that the
// jfrog-cli yarn integration cannot route through Artifactory (V1 and V4),
// since 'jf curation-audit' depends on Artifactory having resolved every
// package to return meaningful curation HEAD responses.
func verifyYarnVersionSupportedForCuration(yarnExecPath, curWd string) error {
	versionStr, err := bibuildutils.GetVersion(yarnExecPath, curWd)
	if err != nil {
		return err
	}
	yarnVersion := version.NewVersion(versionStr)
	if yarnVersion.Compare(yarnV2Version) > 0 || yarnVersion.Compare(yarnV4Version) <= 0 {
		return errorutils.CheckErrorf("'jf curation-audit' is not supported for Yarn V1 or Yarn V4 (detected: %s). Curation requires Artifactory-resolved installs, which the JFrog CLI Yarn integration only supports for Yarn V2 and V3.", versionStr)
	}
	return nil
}

// verifyYarnLockExistsForCuration enforces that 'jf curation-audit' is run
// against a project that already has a yarn.lock. Yarn cannot generate one
// through a curation-enabled repository because every fresh Fetch is subject
// to the curation policy, and any blocked package returns HTTP 403 (YN0035).
// Asking the user to pre-generate yarn.lock against a non-curation registry
// keeps the curation phase to pure HEAD checks against the resolved tree.
func verifyYarnLockExistsForCuration(curWd string) error {
	yarnLockPath := filepath.Join(curWd, yarn.YarnLockFileName)
	exists, err := fileutils.IsFileExists(yarnLockPath, false)
	if err != nil {
		return fmt.Errorf("failed to check the existence of '%s' file: %s", yarnLockPath, err.Error())
	}
	if !exists {
		return errorutils.CheckErrorf("'jf curation-audit' requires an existing '%s'. Yarn cannot generate a fresh lockfile through a curation-enabled repository (curation blocks the package downloads required to compute integrity hashes). Please run 'yarn install' against a non-curation registry to produce '%s', then re-run 'jf ca'.", yarn.YarnLockFileName, yarn.YarnLockFileName)
	}
	return nil
}

// Sets up Artifactory server configurations for dependency resolution, if such were provided by the user.
// Executes the user's 'install' command or a default 'install' command if none was specified.
func configureYarnResolutionServerAndRunInstall(params technologies.BuildInfoBomGeneratorParams, curWd, yarnExecPath string) (err error) {
	depsRepo := params.DependenciesRepository
	if depsRepo == "" {
		// Run install without configuring an Artifactory server
		return runYarnInstallAccordingToVersion(curWd, yarnExecPath, params.InstallCommandArgs)
	}

	executableYarnVersion, err := bibuildutils.GetVersion(yarnExecPath, curWd)
	if err != nil {
		return
	}
	// Resolving through Artifactory is only supported for Yarn V2 and V3.
	yarnVersion := version.NewVersion(executableYarnVersion)
	if yarnVersion.Compare(yarnV2Version) > 0 || yarnVersion.Compare(yarnV4Version) <= 0 {
		err = errors.New("resolving Yarn dependencies from Artifactory is currently not supported for Yarn V1 and Yarn V4. The current Yarn version is: " + executableYarnVersion)
		return
	}

	// If an Artifactory resolution repository was provided we first configure to resolve from it and only then run the 'install' command
	restoreYarnrcFunc, err := ioutils.BackupFile(filepath.Join(curWd, yarn.YarnrcFileName), yarn.YarnrcBackupFileName)
	if err != nil {
		return
	}

	registry, repoAuthIdent, npmAuthToken, err := yarn.GetYarnAuthDetails(params.ServerDetails, depsRepo)
	if err != nil {
		err = errors.Join(err, restoreYarnrcFunc())
		return
	}

	backupEnvMap, err := yarn.ModifyYarnConfigurations(yarnExecPath, registry, repoAuthIdent, npmAuthToken)
	if err != nil {
		if len(backupEnvMap) > 0 {
			err = errors.Join(err, yarn.RestoreConfigurationsFromBackup(backupEnvMap, restoreYarnrcFunc))
		} else {
			err = errors.Join(err, restoreYarnrcFunc())
		}
		return
	}
	defer func() {
		err = errors.Join(err, yarn.RestoreConfigurationsFromBackup(backupEnvMap, restoreYarnrcFunc))
	}()

	log.Info(fmt.Sprintf("Resolving dependencies from '%s' from repo '%s'", params.ServerDetails.Url, depsRepo))
	return runYarnInstallAccordingToVersion(curWd, yarnExecPath, params.InstallCommandArgs)
}

// We verify the project's installation status by examining the presence of the yarn.lock file and the presence of an installation command provided by the user.
// If install command was provided - we install
// If yarn.lock is missing, we should install unless the user has explicitly disabled auto-install. In this case we return an error
// Notice!: If alterations are made manually in the package.json file, it necessitates a manual update to the yarn.lock file as well.
func isInstallRequired(currentDir string, installCommandArgs []string, skipAutoInstall bool) (installRequired bool, err error) {
	yarnLockExits, err := fileutils.IsFileExists(filepath.Join(currentDir, yarn.YarnLockFileName), false)
	if err != nil {
		err = fmt.Errorf("failed to check the existence of '%s' file: %s", filepath.Join(currentDir, yarn.YarnLockFileName), err.Error())
		return
	}

	if len(installCommandArgs) > 0 {
		return true, nil
	} else if !yarnLockExits && skipAutoInstall {
		return false, &biutils.ErrProjectNotInstalled{UninstalledDir: currentDir}
	}
	return !yarnLockExits, nil
}

// Executes the user-defined 'install' command; if absent, defaults to running an 'install' command with specific flags suited to the current yarn version.
func runYarnInstallAccordingToVersion(curWd, yarnExecPath string, installCommandArgs []string) (err error) {
	// If the installCommandArgs in the params is not empty, it signifies that the user has provided it, and 'install' is already included as one of the arguments
	installCommandProvidedFromUser := len(installCommandArgs) != 0

	// Upon receiving a user-provided 'install' command, we execute the command exactly as provided
	if installCommandProvidedFromUser {
		return build.RunYarnCommand(yarnExecPath, curWd, installCommandArgs...)
	}

	installCommandArgs = []string{"install"}
	executableVersionStr, err := bibuildutils.GetVersion(yarnExecPath, curWd)
	if err != nil {
		return
	}

	yarnVersion := version.NewVersion(executableVersionStr)
	isYarnV1 := yarnVersion.Compare(yarnV2Version) > 0

	if isYarnV1 {
		// When executing 'yarn install...', the node_modules directory is automatically generated.
		// If it did not exist prior to the 'install' command, we aim to remove it.
		nodeModulesFullPath := filepath.Join(curWd, nodeModulesRepoName)
		var nodeModulesDirExists bool
		nodeModulesDirExists, err = fileutils.IsDirExists(nodeModulesFullPath, false)
		if err != nil {
			err = fmt.Errorf("failed while checking for existence of node_modules directory: %s", err.Error())
			return
		}
		if !nodeModulesDirExists {
			defer func() {
				err = errors.Join(err, fileutils.RemoveTempDir(nodeModulesFullPath))
			}()
		}

		installCommandArgs = append(installCommandArgs, v1IgnoreScriptsFlag, v1SilentFlag, v1NonInteractiveFlag)
	} else {
		if yarnVersion.Compare(yarnV3Version) > 0 {
			// V2
			installCommandArgs = append(installCommandArgs, v2SkipBuildFlag)
		} else {
			// V3 (curation rejects V1 and V4 earlier and requires a pre-existing
			// yarn.lock, so this branch only ever runs from 'jf audit')
			installCommandArgs = append(installCommandArgs, v3UpdateLockfileFlag, v3SkipBuildFlag)
		}
	}
	log.Info(fmt.Sprintf("Running 'yarn %s' command.", strings.Join(installCommandArgs, " ")))
	err = build.RunYarnCommand(yarnExecPath, curWd, installCommandArgs...)
	return
}

// Parse the dependencies into a Xray dependency tree format
func parseYarnDependenciesMap(dependencies map[string]*bibuildutils.YarnDependency, rootXrayId string) (*xrayUtils.GraphNode, []string, error) {
	treeMap := make(map[string]xray.DepTreeNode)
	for _, dependency := range dependencies {
		xrayDepId, err := getXrayDependencyId(dependency)
		if err != nil {
			return nil, nil, err
		}
		var subDeps []string
		for _, subDepPtr := range dependency.Details.Dependencies {
			subDep := dependencies[bibuildutils.GetYarnDependencyKeyFromLocator(subDepPtr.Locator)]
			subDepXrayId, err := getXrayDependencyId(subDep)
			if err != nil {
				return nil, nil, err
			}
			subDeps = append(subDeps, subDepXrayId)
		}
		if len(subDeps) > 0 {
			treeMap[xrayDepId] = xray.DepTreeNode{Children: subDeps}
		}
	}
	graph, uniqDeps := xray.BuildXrayDependencyTree(treeMap, rootXrayId)
	return graph, maps.Keys(uniqDeps), nil
}

func getXrayDependencyId(yarnDependency *bibuildutils.YarnDependency) (string, error) {
	dependencyName, err := yarnDependency.Name()
	if err != nil {
		return "", err
	}
	return techutils.Npm.GetXrayPackageTypeId() + dependencyName + ":" + yarnDependency.Details.Version, nil
}

// findYarnWorkspaceRoot recovers the project's root workspace entry when
// build-info-go could not identify it from package.json's name+version. Yarn
// V2+ always emits the project root with a Value suffixed by "@workspace:."
// (the dot meaning "the project itself"), regardless of whether package.json
// declares a name. This lets 'jf audit' / 'jf ca' work on bare package.json
// files the same way npm does, instead of forcing users to add a name/version.
func findYarnWorkspaceRoot(dependenciesMap map[string]*bibuildutils.YarnDependency) *bibuildutils.YarnDependency {
	const rootWorkspaceSuffix = "@workspace:."
	for _, dep := range dependenciesMap {
		if dep != nil && strings.HasSuffix(dep.Value, rootWorkspaceSuffix) {
			return dep
		}
	}
	return nil
}
