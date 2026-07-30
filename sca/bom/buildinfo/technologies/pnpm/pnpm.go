package pnpm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

const (
	lockfileOnlyFlag = "--lockfile-only"
	// Suppresses .pnpmfile.cjs hooks during lockfile generation — hooks run arbitrary JS.
	ignorePnpmfileFlag = "--ignore-pnpmfile"
)

type pnpmLsDependency struct {
	From         string                      `json:"from"`
	Version      string                      `json:"version"`
	Dependencies map[string]pnpmLsDependency `json:"dependencies,omitempty"`
	// Local marks a node that is a local workspace member (not a published package).
	// Such nodes stay in the tree for attribution but are excluded from the curation
	// HEAD-check, mirroring how the root project node is skipped.
	Local bool `json:"-"`
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
	pnpmExecPath, pnpmVersion, err := getPnpmExecPath()
	if err != nil {
		return
	}
	if params.IsCurationCmd {
		return buildDependencyTreeFromLockfile(pnpmExecPath, pnpmVersion, currentDir, params)
	}
	return buildDependencyTreeFromPnpmLs(pnpmExecPath, currentDir, params)
}

// buildDependencyTreeFromLockfile is the curation-audit path: parses pnpm-lock.yaml
// directly without running pnpm ls or downloading tarballs.
func buildDependencyTreeFromLockfile(pnpmExecPath, pnpmVersion, currentDir string, params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	if err = validateSupportedPnpmVersion(pnpmVersion); err != nil {
		return
	}
	if params.MaxTreeDepth != "" && params.MaxTreeDepth != "Infinity" {
		log.Warn("The --max-tree-depth flag is not supported for pnpm curation audit (lockfile-based resolution always produces the full tree). The flag will be ignored.")
	}
	// In a workspace, the lockfile lives at the root and records every member under its
	// own importer. Resolve from the root, then scope to the importer matching currentDir:
	// "." (the root) audits the whole workspace; a member audits only that member.
	workspaceRoot, importer := resolveWorkspaceRoot(currentDir)
	lockfileDir, cleanup, err := resolveLockfileDir(pnpmExecPath, workspaceRoot)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, cleanup())
	}()
	projects, err := parsePnpmLockFile(lockfileDir, importer)
	if err != nil {
		return
	}
	if len(params.Args) > 0 {
		projects = filterProjectsByScope(projects, params.Args)
	}
	dependencyTrees, uniqueDeps = parsePnpmLSContent(projects)
	return
}

// buildDependencyTreeFromPnpmLs is the audit/scan path: installs into a temp dir
// if needed, then calls `pnpm ls --json` to obtain the full dependency tree.
func buildDependencyTreeFromPnpmLs(pnpmExecPath, currentDir string, params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	var dirForDependenciesCalculation string
	if dirForDependenciesCalculation, err = installProjectIfNeeded(pnpmExecPath, currentDir); errorutils.CheckError(err) != nil {
		return
	}
	if dirForDependenciesCalculation == "" {
		// Lockfile and node_modules already present — run ls in the original dir.
		dirForDependenciesCalculation = currentDir
	} else {
		defer func() {
			err = errors.Join(err, biutils.RemoveTempDir(dirForDependenciesCalculation))
		}()
	}
	return calculateDependencies(pnpmExecPath, dirForDependenciesCalculation, params)
}

// installProjectIfNeeded runs `pnpm install --ignore-scripts` in a temp copy of the
// project when pnpm-lock.yaml or node_modules/.pnpm is missing.
// Returns the temp dir path, or "" if no install was needed.
func installProjectIfNeeded(pnpmExecPath, workingDir string) (dirForDependenciesCalculation string, err error) {
	lockFileExists, err := fileutils.IsFileExists(filepath.Join(workingDir, "pnpm-lock.yaml"), false)
	if err != nil {
		return
	}
	pnpmDirExists, err := fileutils.IsDirExists(filepath.Join(workingDir, "node_modules", ".pnpm"), false)
	if err != nil || (lockFileExists && pnpmDirExists) {
		return
	}
	log.Debug("Installing Pnpm project:", workingDir)
	dirForDependenciesCalculation, err = fileutils.CreateTempDir()
	if err != nil {
		err = fmt.Errorf("failed to create a temporary dir: %w", err)
		return
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, fileutils.RemoveTempDir(dirForDependenciesCalculation))
		}
	}()
	// Exclude Visual Studio inner directory — not needed for scanning and may cause race conditions.
	err = biutils.CopyDir(workingDir, dirForDependenciesCalculation, true, []string{technologies.DotVsRepoSuffix})
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

// calculateDependencies runs `pnpm ls --json` in workingDir (which must already be
// installed) and converts the output into an Xray dependency tree.
func calculateDependencies(executablePath, workingDir string, params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	lsArgs := append([]string{"--depth", params.MaxTreeDepth, "--json", "--long"}, params.Args...)
	log.Debug("Running Pnpm ls command with args:", lsArgs)
	npmLsCmdContent, err := getPnpmCmd(executablePath, workingDir, "ls", lsArgs...).RunWithOutput()
	if err != nil {
		return
	}
	log.Verbose("Pnpm ls command output:\n", string(npmLsCmdContent))
	output := &[]pnpmLsProject{}
	if err = json.Unmarshal(npmLsCmdContent, output); err != nil {
		return
	}
	dependencyTrees, uniqueDeps = parsePnpmLSContent(*output)
	return
}

// filterProjectsByScope returns a shallow copy of projects with dev or prod
// dependencies cleared based on the --dev or --prod flags passed via params.Args
// (set by SetNpmScope). It does not mutate the caller's slice, so the original
// pre-filter state stays intact.
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
	result := make([]pnpmLsProject, len(projects))
	copy(result, projects)
	for i := range result {
		if devOnly {
			result[i].Dependencies = nil
		}
		if prodOnly {
			result[i].DevDependencies = nil
		}
	}
	return result
}

// GetNativePnpmRegistryConfig reads the Artifactory registry URL and auth token
// from the project's .npmrc via the pnpm CLI. pnpm reads .npmrc with the same
// hierarchy and semantics as npm, so this mirrors GetNativeNpmRegistryConfig
// without requiring an npm binary on pnpm-only machines.
func GetNativePnpmRegistryConfig() (*npm.NpmrcRegistryConfig, error) {
	pnpmExecPath, _, err := getPnpmExecPath()
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

const supportedPnpmMajorVersion = 10

// getPnpmExecPath locates the pnpm executable and returns it together with its version,
// so callers needing the version (e.g. the curation version check) need not re-spawn it.
func getPnpmExecPath() (pnpmExecPath, pnpmVersion string, err error) {
	if pnpmExecPath, err = exec.LookPath("pnpm"); errorutils.CheckError(err) != nil {
		return
	}
	if pnpmExecPath == "" {
		err = errors.New("could not find the 'pnpm' executable in the system PATH")
		return
	}
	log.Debug("Using Pnpm executable:", pnpmExecPath)
	versionOut, versionErr := getPnpmCmd(pnpmExecPath, "", "--version").RunWithOutput()
	if errorutils.CheckError(versionErr) != nil {
		err = versionErr
		return
	}
	pnpmVersion = strings.TrimSpace(string(versionOut))
	log.Debug("Pnpm version:", pnpmVersion)
	return
}

// validateSupportedPnpmVersion returns an error unless the installed pnpm major
// version is exactly supportedPnpmMajorVersion. Curation supports only that major,
// so both older and newer majors are rejected.
func validateSupportedPnpmVersion(versionStr string) error {
	// Version string may include extra lines (warnings on incompatible Node); take first token.
	firstLine := strings.SplitN(versionStr, "\n", 2)[0]
	parts := strings.SplitN(strings.TrimSpace(firstLine), ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("could not parse pnpm version %q: %w", versionStr, err)
	}
	if major != supportedPnpmMajorVersion {
		return fmt.Errorf("resolving pnpm dependencies from Artifactory is currently not supported for pnpm versions other than %d.x. The current pnpm version is: %s", supportedPnpmMajorVersion, versionStr)
	}
	return nil
}

// wrapLockfileRegenError checks the pnpm output for ERR_PNPM_NO_MATCHING_VERSION
// (raised when CVS removes a blocked version from the packument) and returns a
// curation-flavoured message. Any other failure is returned with the raw output.
func wrapLockfileRegenError(out []byte, runErr error) error {
	output := string(out)
	if !strings.Contains(output, "ERR_PNPM_NO_MATCHING_VERSION") {
		return fmt.Errorf("'pnpm install --lockfile-only' failed: %w\n%s", runErr, output)
	}
	pkgs := parsePnpmCvsFailedPackages(output)
	return errors.New(formatPnpmCvsBlockedMessage(pkgs))
}

// pnpmNoMatchPrefix is the literal that precedes the failed "<name>@<version>"
// reference in pnpm's ERR_PNPM_NO_MATCHING_VERSION output line, e.g.
// "No matching version found for @scope/pkg@^1.0.0 while fetching it from ...".
const pnpmNoMatchPrefix = "No matching version found for "

// parsePnpmCvsFailedPackages extracts every name@version pair that pnpm
// reported as unresolvable so only the actual blockers are listed.
// It uses splitPnpmRef (last-'@' split) so scoped names like "@scope/pkg@1.0.0"
// are parsed correctly — a leading '@' would defeat a naive name regex.
func parsePnpmCvsFailedPackages(output string) []string {
	seen := map[string]bool{}
	var pkgs []string
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, pnpmNoMatchPrefix)
		if idx < 0 {
			continue
		}
		// The package reference is the first whitespace-delimited token after the
		// prefix; pnpm appends trailing text such as "while fetching it from ...".
		fields := strings.Fields(line[idx+len(pnpmNoMatchPrefix):])
		if len(fields) == 0 {
			continue
		}
		name, version := splitPnpmRef(fields[0])
		if version == "" {
			continue
		}
		key := version
		if name != "" {
			key = name + "@" + version
		}
		if !seen[key] {
			seen[key] = true
			pkgs = append(pkgs, key)
		}
	}
	return pkgs
}

func formatPnpmCvsBlockedMessage(pkgs []string) string {
	var b strings.Builder
	b.WriteString("Curation audit failed: one or more pinned package versions were unavailable during dependency resolution, so the corresponding curation policy violations could not be evaluated.")
	if len(pkgs) > 0 {
		b.WriteString("\n\nAffected package(s):\n")
		for _, p := range pkgs {
			fmt.Fprintf(&b, " - %s\n", p)
		}
	}
	return b.String()
}

func getPnpmCmd(pnpmExecPath, workingDir, cmd string, args ...string) *io.Command {
	command := io.NewCommand(pnpmExecPath, cmd, args)
	command.Dir = workingDir
	return command
}

// resolveLockfileDir returns the directory whose pnpm-lock.yaml should be parsed, plus a
// cleanup the caller must always invoke. An up-to-date lockfile returns workingDir and a
// no-op; a missing/stale one is regenerated in a temp copy (returned for cleanup) so the
// user's project is never modified and read-only checkouts still work.
// resolveWorkspaceRoot walks up from workingDir to find the pnpm workspace root — the
// nearest ancestor (workingDir included) containing pnpm-lock.yaml or pnpm-workspace.yaml.
// It returns that root and the importer path of workingDir relative to it ("." when
// workingDir is the root). When no marker is found, workingDir is treated as a standalone
// project (root=workingDir, importer="."). This mirrors promotePnpmWorkspaceMember so
// detection and lockfile resolution agree on what the workspace root is.
func resolveWorkspaceRoot(workingDir string) (rootDir, importer string) {
	dir := workingDir
	for {
		for _, marker := range []string{"pnpm-lock.yaml", "pnpm-workspace.yaml"} {
			if exists, _ := fileutils.IsFileExists(filepath.Join(dir, marker), false); exists {
				rel, err := filepath.Rel(dir, workingDir)
				if err != nil {
					rel = "."
				}
				return dir, filepath.ToSlash(rel)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return workingDir, "."
		}
		dir = parent
	}
}

func resolveLockfileDir(pnpmExecPath, workingDir string) (lockfileDir string, cleanup func() error, err error) {
	noop := func() error { return nil }
	lockPath := filepath.Join(workingDir, "pnpm-lock.yaml")
	lockExists, err := fileutils.IsFileExists(lockPath, false)
	if err != nil {
		return "", noop, err
	}
	if lockExists && !lockfileNeedsRefresh(pnpmExecPath, workingDir, lockPath) {
		return workingDir, noop, nil
	}
	if !lockExists {
		log.Debug(fmt.Sprintf("pnpm-lock.yaml not found — generating it in a temporary directory via '%s install %s %s'", pnpmExecPath, lockfileOnlyFlag, npm.IgnoreScriptsFlag))
	}

	tmpDir, err := fileutils.CreateTempDir()
	if err != nil {
		return "", noop, fmt.Errorf("failed to create a temporary dir: %w", err)
	}
	cleanup = func() error { return fileutils.RemoveTempDir(tmpDir) }
	// On failure, remove the temp dir now and downgrade cleanup so the caller won't re-remove.
	defer func() {
		if err != nil {
			err = errors.Join(err, cleanup())
			cleanup = noop
		}
	}()

	if err = copyProjectToDir(workingDir, tmpDir); err != nil {
		return "", cleanup, err
	}

	out, runErr := getPnpmCmd(pnpmExecPath, tmpDir, "install", lockfileOnlyFlag, npm.IgnoreScriptsFlag, ignorePnpmfileFlag).GetCmd().CombinedOutput()
	if runErr != nil {
		log.Debug("pnpm install --lockfile-only failed:\n" + string(out))
		err = wrapLockfileRegenError(out, runErr)
		return "", cleanup, err
	}

	lockProduced, err := fileutils.IsFileExists(filepath.Join(tmpDir, "pnpm-lock.yaml"), false)
	if err != nil {
		return "", cleanup, err
	}
	if !lockProduced {
		err = errors.New("lockfile not produced after 'pnpm install --lockfile-only'")
		return "", cleanup, err
	}
	return tmpDir, cleanup, nil
}

// lockfileNeedsRefresh reports whether pnpm-lock.yaml is stale versus package.json,
// by mtime or by drift in the recorded dependency specifiers.
func lockfileNeedsRefresh(pnpmExecPath, workingDir, lockPath string) bool {
	pkgStat, pkgErr := os.Stat(filepath.Join(workingDir, "package.json"))
	lockStat, lockErr := os.Stat(lockPath)
	mtimeStale := pkgErr == nil && lockErr == nil && pkgStat.ModTime().After(lockStat.ModTime())
	switch {
	case mtimeStale:
		log.Debug(fmt.Sprintf("package.json is newer than pnpm-lock.yaml — regenerating the lockfile in a temporary directory via '%s install %s %s'", pnpmExecPath, lockfileOnlyFlag, npm.IgnoreScriptsFlag))
		return true
	case lockfileSpecifiersDrift(workingDir, lockPath):
		log.Debug(fmt.Sprintf("pnpm-lock.yaml specifiers do not match package.json — regenerating the lockfile in a temporary directory via '%s install %s %s'", pnpmExecPath, lockfileOnlyFlag, npm.IgnoreScriptsFlag))
		return true
	default:
		return false
	}
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
		// Local workspace members are project roots, not published packages: keep them
		// in the tree for attribution but drop them from the HEAD-check set so we don't
		// query Artifactory for a package that doesn't exist (404).
		for name, dependency := range project.Dependencies {
			if dependency.Local {
				_ = uniqueDepsSet.Remove(getDependencyId(name, dependency.Version))
			}
		}
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
