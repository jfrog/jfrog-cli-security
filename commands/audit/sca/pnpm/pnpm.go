package pnpm

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	coreXray "github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

type pnpmLsProject struct {
	Name         string                      `json:"name"`
	Version      string                      `json:"version"`
	Dependencies map[string]pnpmLsDependency `json:"dependencies,omitempty"`
}

type pnpmLsDependency struct {
	From         string                      `json:"from"`
	Version      string                      `json:"version"`
	Dependencies map[string]pnpmLsDependency `json:"dependencies,omitempty"`
	// binary location
	Resolved string `json:"resolved"`
}

func BuildDependencyTree(params utils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	pnpmExecPath, err := getPnpmExecPath()
	if err != nil {
		return
	}
	// Run 'pnpm ls...' command and parse the returned result to create a dependencies map.
	projectInfo, err := calculateDependencies(pnpmExecPath, currentDir)
	if err != nil {
		return
	}
	dependencyTrees, uniqueDeps = parsePnpmDependenciesList(projectInfo)
	return
}

func getPnpmExecPath() (string, error) {
	pnpmExecPath, err := exec.LookPath("pnpm")
	if err != nil {
		return "", err
	}
	if pnpmExecPath == "" {
		return "", errors.New("could not find the 'pnpm' executable in the system PATH")
	}
	log.Debug("Using pnpm executable:", pnpmExecPath)
	// Validate pnpm version
	_, _, err = sca.RunCmdAndGetOutput(pnpmExecPath, "", "--version")
	if err != nil {
		return "", err
	}
	return pnpmExecPath, nil
}

// Run 'pnpm ls ...' command and parse the returned result to create a dependencies map of.
func calculateDependencies(executablePath, workingDir string) ([]pnpmLsProject, error) {
	npmLsCmdContent, errData, err := sca.RunCmdAndGetOutput(executablePath, workingDir, "ls", "--depth", "Infinity", "--json", "--long")
	if err != nil {
		return nil, err
	} else if len(errData) > 0 {
		log.Warn("Encountered some issues while running 'pnpm ls' command:\n" + strings.TrimSpace(string(errData)))
	}
	output := &[]pnpmLsProject{}
	if err := json.Unmarshal(npmLsCmdContent, output); err != nil {
		return nil, err
	}
	return *output, nil
}

func parsePnpmDependenciesList(projectInfo []pnpmLsProject) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string) {
	uniqueDepsSet := datastructures.MakeSet[string]()
	for _, project := range projectInfo {
		treeMap := createProjectDependenciesTree(project)
		// Parse the dependencies into Xray dependency tree format
		dependencyTree, uniqueProjectDeps := coreXray.BuildXrayDependencyTree(treeMap, getDependencyId(project.Name, project.Version))
		dependencyTrees = append(dependencyTrees, dependencyTree)
		// Add the dependencies to the unique dependencies set
		uniqueDepsSet.AddElements(uniqueProjectDeps...)
	}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

func createProjectDependenciesTree(project pnpmLsProject) map[string][]string {
	treeMap := make(map[string][]string)
	// Create a map of the project's dependencies
	directDependencies := []string{}
	projectId := getDependencyId(project.Name, project.Version)
	for depName, dependency := range project.Dependencies {
		directDependency := getDependencyId(depName, dependency.Version)
		directDependencies = append(directDependencies, directDependency)
		appendTransitiveDependencies(directDependency, dependency.Dependencies, treeMap)
	}
	if len(directDependencies) > 0 {
		treeMap[projectId] = directDependencies
	}
	return treeMap
}

// Return npm://<name>:<version> of a dependency
func getDependencyId(depName, version string) string {
	return utils.NpmPackageTypeIdentifier + depName + ":" + version
}

func appendTransitiveDependencies(parent string, dependencies map[string]pnpmLsDependency, result map[string][]string) {
	for depName, dependency := range dependencies {
		dependencyId := getDependencyId(depName, dependency.Version)
		if children, ok := result[parent]; ok {
			result[parent] = appendUniqueChild(children, dependencyId)
		} else {
			result[parent] = []string{dependencyId}
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
