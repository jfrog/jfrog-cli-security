package pnpm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/io"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/npm"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/maps"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const lockfileOnlyFlag = "--lockfile-only"

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

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	pnpmExecPath, err := getPnpmExecPath()
	if err != nil {
		return
	}

	if err = ensureLockfile(pnpmExecPath, currentDir); err != nil {
		return
	}

	projects, err := parsePnpmLockFile(currentDir)
	if err != nil {
		return
	}
	// Apply scope filter (dev-only / prod-only) to the raw project list if requested.
	if len(params.Args) > 0 {
		projects = filterProjectsByScope(projects, params.Args)
	}
	dependencyTrees, uniqueDeps = parsePnpmLSContent(projects)
	return
}

// filterProjectsByScope removes dev or prod dependencies from each project
// based on the --dev or --prod flags passed via params.Args (set by SetNpmScope).
func filterProjectsByScope(projects []pnpmLsProject, args []string) []pnpmLsProject {
	devOnly, prodOnly := false, false
	for _, arg := range args {
		switch arg {
		case "--dev":
			devOnly = true
		case "--prod":
			prodOnly = true
		}
	}
	if !devOnly && !prodOnly {
		return projects
	}
	for i := range projects {
		if devOnly {
			projects[i].Dependencies = nil
		}
		if prodOnly {
			projects[i].DevDependencies = nil
		}
	}
	return projects
}

// GetNativePnpmRegistryConfig reads the Artifactory registry URL and auth token
// from the project's .npmrc via the pnpm CLI. pnpm reads .npmrc with the same
// hierarchy and semantics as npm, so this mirrors GetNativeNpmRegistryConfig
// without requiring an npm binary on pnpm-only machines.
func GetNativePnpmRegistryConfig() (*npm.NpmrcRegistryConfig, error) {
	pnpmExecPath, err := getPnpmExecPath()
	if err != nil {
		return nil, fmt.Errorf("failed to locate pnpm executable: %w", err)
	}

	registryData, err := getPnpmCmd(pnpmExecPath, "", "config", "get", "registry").RunWithOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to read registry from pnpm config: %w", err)
	}
	registryUrl := strings.TrimSpace(string(registryData))

	rtBaseUrl, repoName, err := npm.ParseArtifactoryNpmRegistryUrl(registryUrl)
	if err != nil {
		return nil, err
	}

	authKey, err := npm.BuildNpmAuthTokenKey(registryUrl)
	if err != nil {
		return nil, err
	}

	tokenData, tokenErr := getPnpmCmd(pnpmExecPath, "", "config", "get", authKey).RunWithOutput()
	authToken := ""
	if tokenErr == nil {
		authToken = strings.TrimSpace(string(tokenData))
		if authToken == "undefined" || authToken == "null" {
			authToken = ""
		}
	}

	return &npm.NpmrcRegistryConfig{
		ArtifactoryUrl: rtBaseUrl,
		RepoName:       repoName,
		AuthToken:      authToken,
	}, nil
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

// ensureLockfile guarantees that pnpm-lock.yaml exists in workingDir.
// If it is already present, nothing is done — the existing lockfile is used as-is.
// If it is absent, `pnpm install --lockfile-only --ignore-scripts` is run in a
// temporary copy of workingDir so the original directory is not mutated.
//
// This mirrors the npm path (--package-lock-only) and yarn V3 path (--mode=update-lockfile):
// no tarballs are downloaded, only resolution metadata is written.
func ensureLockfile(pnpmExecPath, workingDir string) error {
	lockExists, err := fileutils.IsFileExists(filepath.Join(workingDir, "pnpm-lock.yaml"), false)
	if err != nil {
		return err
	}
	if lockExists {
		return nil
	}

	log.Debug("pnpm-lock.yaml not found — running 'pnpm install --lockfile-only' in a temporary directory")
	tmpDir, err := fileutils.CreateTempDir()
	if err != nil {
		return fmt.Errorf("failed to create a temporary dir: %w", err)
	}
	defer func() {
		err = errors.Join(err, fileutils.RemoveTempDir(tmpDir))
	}()

	if copyErr := copyProjectToDir(workingDir, tmpDir); copyErr != nil {
		return copyErr
	}

	out, runErr := getPnpmCmd(pnpmExecPath, tmpDir, "install", lockfileOnlyFlag, npm.IgnoreScriptsFlag).GetCmd().CombinedOutput()
	if runErr != nil {
		return fmt.Errorf("'pnpm install --lockfile-only' failed: %w\n%s", runErr, string(out))
	}

	// Copy the generated lockfile back so parsePnpmLockFile can read it from workingDir.
	generatedLock, readErr := fileutils.ReadFile(filepath.Join(tmpDir, "pnpm-lock.yaml"))
	if readErr != nil {
		return fmt.Errorf("lockfile not produced after 'pnpm install --lockfile-only': %w", readErr)
	}
	return os.WriteFile(filepath.Join(workingDir, "pnpm-lock.yaml"), generatedLock, 0644)
}

func copyProjectToDir(src, dst string) error {
	if err := biutils.CopyDir(src, dst, true, []string{technologies.DotVsRepoSuffix}); err != nil {
		return fmt.Errorf("failed copying project to temp dir: %w", err)
	}
	return nil
}

func parsePnpmLSContent(projectInfo []pnpmLsProject) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string) {
	uniqueDepsSet := datastructures.MakeSet[string]()
	for _, project := range projectInfo {
		dependencyTree, uniqueProjectDeps := xray.BuildXrayDependencyTree(createProjectDependenciesTree(project), getDependencyId(project.Name, project.Version))
		dependencyTrees = append(dependencyTrees, dependencyTree)
		uniqueDepsSet.AddElements(maps.Keys(uniqueProjectDeps)...)
	}
	uniqueDeps = uniqueDepsSet.ToSlice()
	return
}

func createProjectDependenciesTree(project pnpmLsProject) map[string]xray.DepTreeNode {
	treeMap := make(map[string]xray.DepTreeNode)
	var directDependencies []string
	for depName, dependency := range project.Dependencies {
		directDependency := getDependencyId(depName, dependency.Version)
		directDependencies = append(directDependencies, directDependency)
		appendTransitiveDependencies(directDependency, dependency.Dependencies, &treeMap)
	}
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

func getDependencyId(depName, version string) string {
	return techutils.Npm.GetXrayPackageTypeId() + depName + ":" + version
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
