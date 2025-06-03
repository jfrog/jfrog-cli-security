package pnpm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/io"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/npm"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/maps"

	biutils "github.com/jfrog/build-info-go/utils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

type pnpmLsDependency struct {
	From         string                      `json:"from"`
	Version      string                      `json:"version"`
	Dependencies map[string]pnpmLsDependency `json:"dependencies,omitempty"`
}

type pnpmLsProject struct {
	Name            string                      `json:"name"`
	Version         string                      `json:"version"`
	Dependencies    map[string]pnpmLsDependency `json:"dependencies,omitempty"`
	DevDependencies map[string]pnpmLsDependency `json:"devDependencies,omitempty"`
}

func BuildDependencyTree(params utils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	// Prepare
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	pnpmExecPath, err := getPnpmExecPath()
	if err != nil {
		return
	}
	// Build
	var dirForDependenciesCalculation string
	if dirForDependenciesCalculation, err = installProjectIfNeeded(pnpmExecPath, currentDir); errorutils.CheckError(err) != nil {
		return
	}

	if dirForDependenciesCalculation == "" {
		// If we didn't execute 'install' dirForDependenciesCalculation contains an empty value and the dependencies calculation should be performed on the original cloned dir
		dirForDependenciesCalculation = currentDir
	} else {
		// If tempDirForDependenciesCalculation contains a non-empty value, it means we created a temporary directory during the execution of 'install' command, and it needs to removed at the end
		defer func() {
			err = errors.Join(err, biutils.RemoveTempDir(dirForDependenciesCalculation))
		}()
	}
	return calculateDependencies(pnpmExecPath, dirForDependenciesCalculation, params)
}

func getPnpmExecPath() (pnpmExecPath string, err error) {
	if pnpmExecPath, err = exec.LookPath("pnpm"); errorutils.CheckError(err) != nil {
		return
	}
	if pnpmExecPath == "" {
		err = errors.New("could not find the 'pnpm' executable in the system PATH")
		return
	}
	log.Debug("Using Pnpm executable:", pnpmExecPath)
	// Validate pnpm version command
	version, err := getPnpmCmd(pnpmExecPath, "", "--version").RunWithOutput()
	if errorutils.CheckError(err) != nil {
		return
	}
	log.Debug("Pnpm version:", string(version))
	return
}

func getPnpmCmd(pnpmExecPath, workingDir, cmd string, args ...string) *io.Command {
	command := io.NewCommand(pnpmExecPath, cmd, args)
	command.Dir = workingDir
	return command
}

// Installation is necessary when either the "pnpm-lock.yaml" lock file or the "node_modules/.pnpm" directory does not exist.
// If install is needed, we duplicate the project to a temporary directory and conduct the 'install' operation on the duplicate, to ensure that the original clone does not retain the node_modules directory if it didn't exist previously.
// Upon 'install' the path to the duplicate directory will be returned.
func installProjectIfNeeded(pnpmExecPath, workingDir string) (dirForDependenciesCalculation string, err error) {
	lockFileExists, err := fileutils.IsFileExists(filepath.Join(workingDir, "pnpm-lock.yaml"), false)
	if err != nil {
		return
	}
	pnpmDirExists, err := fileutils.IsDirExists(filepath.Join(workingDir, "node_modules", ".pnpm"), false)
	if err != nil || (lockFileExists && pnpmDirExists) {
		return
	}
	// Install is needed and will be performed on a copy of the cloned dir
	log.Debug("Installing Pnpm project:", workingDir)
	dirForDependenciesCalculation, err = fileutils.CreateTempDir()
	if err != nil {
		err = fmt.Errorf("failed to create a temporary dir: %w", err)
		return
	}
	defer func() {
		// If an error occurs for any reason, we proceed to delete the temporary directory.
		if err != nil {
			err = errors.Join(err, fileutils.RemoveTempDir(dirForDependenciesCalculation))
		}
	}()

	// Exclude Visual Studio inner directory since it is not necessary for the scan process and may cause race condition.
	err = biutils.CopyDir(workingDir, dirForDependenciesCalculation, true, []string{sca.DotVsRepoSuffix})
	if err != nil {
		err = fmt.Errorf("failed copying project to temp dir: %w", err)
		return
	}
	output, err := getPnpmCmd(pnpmExecPath, dirForDependenciesCalculation, "install", npm.IgnoreScriptsFlag).GetCmd().CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to install project: %w\n%s", err, string(output))
	}
	return
}

// Run 'pnpm ls ...' command (project must be installed) and parse the returned result to create a dependencies trees for the projects.
func calculateDependencies(executablePath, workingDir string, params utils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	lsArgs := append([]string{"--depth", params.MaxTreeDepth(), "--json", "--long"}, params.Args()...)
	log.Debug("Running Pnpm ls command with args:", lsArgs)
	npmLsCmdContent, err := getPnpmCmd(executablePath, workingDir, "ls", lsArgs...).RunWithOutput()
	if err != nil {
		return
	}
	log.Debug("Pnpm ls command output:\n", string(npmLsCmdContent))
	output := &[]pnpmLsProject{}
	if err = json.Unmarshal(npmLsCmdContent, output); err != nil {
		return
	}
	dependencyTrees, uniqueDeps = parsePnpmLSContent(*output)
	return
}

func parsePnpmLSContent(projectInfo []pnpmLsProject) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string) {
	uniqueDepsSet := datastructures.MakeSet[string]()
	for _, project := range projectInfo {
		// Parse the dependencies into Xray dependency tree format
		dependencyTree, uniqueProjectDeps := xray.BuildXrayDependencyTree(createProjectDependenciesTree(project), getDependencyId(project.Name, project.Version))
		// Add results
		dependencyTrees = append(dependencyTrees, dependencyTree)
		uniqueDepsSet.AddElements(maps.Keys(uniqueProjectDeps)...)
	}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

func createProjectDependenciesTree(project pnpmLsProject) map[string]xray.DepTreeNode {
	treeMap := make(map[string]xray.DepTreeNode)
	directDependencies := []string{}
	// Handle production-dependencies
	for depName, dependency := range project.Dependencies {
		directDependency := getDependencyId(depName, dependency.Version)
		directDependencies = append(directDependencies, directDependency)
		appendTransitiveDependencies(directDependency, dependency.Dependencies, &treeMap)
	}
	// Handle dev-dependencies
	for depName, dependency := range project.DevDependencies {
		directDependency := getDependencyId(depName, dependency.Version)
		directDependencies = append(directDependencies, directDependency)
		appendTransitiveDependencies(directDependency, dependency.Dependencies, &treeMap)
	}
	if len(directDependencies) > 0 {
		treeMap[getDependencyId(project.Name, project.Version)] = xray.DepTreeNode{Children: directDependencies}
	}
	return treeMap
}

// Return npm://<name>:<version> of a dependency
func getDependencyId(depName, version string) string {
	return techutils.Npm.GetPackageTypeId() + depName + ":" + version
}

func appendTransitiveDependencies(parent string, dependencies map[string]pnpmLsDependency, result *map[string]xray.DepTreeNode) {
	for depName, dependency := range dependencies {
		dependencyId := getDependencyId(depName, dependency.Version)
		if node, ok := (*result)[parent]; ok {
			node.Children = append(node.Children, dependencyId)
			(*result)[parent] = node
		} else {
			(*result)[parent] = xray.DepTreeNode{Children: []string{dependencyId}}
		}
		appendTransitiveDependencies(dependencyId, dependency.Dependencies, result)
	}
}
