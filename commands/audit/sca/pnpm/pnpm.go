package pnpm

import (
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/io"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"golang.org/x/exp/maps"

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
	if err = installProjectIfNeeded(pnpmExecPath, currentDir); errorutils.CheckError(err) != nil {
		return
	}
	return calculateDependencies(pnpmExecPath, currentDir, params)
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
	if workingDir != "" {
		command.Dir = workingDir
	}
	return command
}

// Install is required when "pnpm-lock.yaml" lock file or "node_modules/.pnpm" directory not exists.
func installProjectIfNeeded(pnpmExecPath, workingDir string) (err error) {
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
	return getPnpmCmd(pnpmExecPath, workingDir, "install").GetCmd().Run()
}

// Run 'pnpm ls ...' command (project must be installed) and parse the returned result to create a dependencies map of.
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
	for _, existingChild := range children {
		if existingChild == candidateDependency {
			return children
		}
	}
	return append(children, candidateDependency)
}
