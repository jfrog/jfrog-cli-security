package pnpm

import (
	"encoding/json"
	"errors"
	"fmt"
	biutils "github.com/jfrog/build-info-go/utils"
	"os/exec"
	"path/filepath"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/io"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/npm"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	coreXray "github.com/jfrog/jfrog-cli-core/v2/utils/xray"
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
	var tempDirForDependenciesCalculation string
	if tempDirForDependenciesCalculation, err = installProjectIfNeeded(pnpmExecPath, currentDir); errorutils.CheckError(err) != nil {
		return
	}

	var dirToCalcDependenciesOn string
	if tempDirForDependenciesCalculation == "" {
		dirToCalcDependenciesOn = currentDir
	} else {
		dirToCalcDependenciesOn = tempDirForDependenciesCalculation
		defer func() {
			err = errors.Join(err, biutils.RemoveTempDir(tempDirForDependenciesCalculation))
		}()
	}
	return calculateDependencies(pnpmExecPath, dirToCalcDependenciesOn, params)
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

// Install is required when "pnpm-lock.yaml" lock file or "node_modules/.pnpm" directory not exists.
// If "node_modules/.pnpm" doesn't exist we copy the project to a temporary dir and perform the 'install' on the copy, because we don't want to have node_modules in the original cloned
// Directory if it wasn't exist before
func installProjectIfNeeded(pnpmExecPath, workingDir string) (tempDirForDependenciesCalculation string, err error) {
	lockFileExists, err := fileutils.IsFileExists(filepath.Join(workingDir, "pnpm-lock.yaml"), false)
	if err != nil {
		return
	}
	pnpmDirExists, err := fileutils.IsDirExists(filepath.Join(workingDir, "node_modules", ".pnpm"), false)
	if err != nil || (lockFileExists && pnpmDirExists) {
		return
	}
	// Install is needed
	log.Debug("Installing Pnpm project:", workingDir)
	workingDirToRunInstallOn := workingDir

	// If node_modules/.pnpm doesn't exist we clone the project to a temporary dir so the original project will not be effected by the newly added files of the 'install' command
	if !pnpmDirExists {
		tempDirForDependenciesCalculation, err = fileutils.CreateTempDir()
		if err != nil {
			err = fmt.Errorf("failed to create a temporary dir: %w", err)
			return
		}
		defer func() {
			// If we have an error for any reason we delete the temp dir
			if err != nil {
				err = errors.Join(err, fileutils.RemoveTempDir(tempDirForDependenciesCalculation))
			}
		}()

		err = biutils.CopyDir(workingDir, tempDirForDependenciesCalculation, true, nil)
		if err != nil {
			err = fmt.Errorf("failed copying project to temp dir: %w", err)
			return
		}
		workingDirToRunInstallOn = tempDirForDependenciesCalculation
	}

	err = getPnpmCmd(pnpmExecPath, workingDirToRunInstallOn, "install", npm.IgnoreScriptsFlag).GetCmd().Run()
	return
}

// Run 'pnpm ls ...' command (project must be installed) and parse the returned result to create a dependencies trees for the projects.
func calculateDependencies(executablePath, workingDir string, params utils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	lsArgs := append([]string{"--depth", "Infinity", "--json", "--long"}, params.Args()...)
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
		dependencyTree, uniqueProjectDeps := coreXray.BuildXrayDependencyTree(createProjectDependenciesTree(project), getDependencyId(project.Name, project.Version))
		// Add results
		dependencyTrees = append(dependencyTrees, dependencyTree)
		uniqueDepsSet.AddElements(maps.Keys(uniqueProjectDeps)...)
	}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

func createProjectDependenciesTree(project pnpmLsProject) map[string]coreXray.DepTreeNode {
	treeMap := make(map[string]coreXray.DepTreeNode)
	directDependencies := []string{}
	// Handle production-dependencies
	for depName, dependency := range project.Dependencies {
		directDependency := getDependencyId(depName, dependency.Version)
		directDependencies = append(directDependencies, directDependency)
		appendTransitiveDependencies(directDependency, dependency.Dependencies, treeMap)
	}
	// Handle dev-dependencies
	for depName, dependency := range project.DevDependencies {
		directDependency := getDependencyId(depName, dependency.Version)
		directDependencies = append(directDependencies, directDependency)
		appendTransitiveDependencies(directDependency, dependency.Dependencies, treeMap)
	}
	if len(directDependencies) > 0 {
		treeMap[getDependencyId(project.Name, project.Version)] = coreXray.DepTreeNode{Children: directDependencies}
	}
	return treeMap
}

// Return npm://<name>:<version> of a dependency
func getDependencyId(depName, version string) string {
	return utils.NpmPackageTypeIdentifier + depName + ":" + version
}

func appendTransitiveDependencies(parent string, dependencies map[string]pnpmLsDependency, result map[string]coreXray.DepTreeNode) {
	for depName, dependency := range dependencies {
		dependencyId := getDependencyId(depName, dependency.Version)
		if node, ok := result[parent]; ok {
			node.Children = appendUniqueChild(node.Children, dependencyId)
		} else {
			result[parent] = coreXray.DepTreeNode{Children: []string{dependencyId}}
		}
		appendTransitiveDependencies(dependencyId, dependency.Dependencies, result)
	}
}

func appendUniqueChild(children []string, candidateDependency string) []string {
	if slices.Contains(children, candidateDependency) {
		return children
	}
	return append(children, candidateDependency)
}
