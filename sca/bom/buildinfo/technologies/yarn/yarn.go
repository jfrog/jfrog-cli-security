package yarn

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	biutils "github.com/jfrog/build-info-go/utils"
	"gopkg.in/yaml.v3"

	"github.com/jfrog/build-info-go/build"
	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/yarn"
	outFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/ioutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/npm"
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
	v3SkipBuildFlag = "--mode=skip-build"
	// Env vars yarn reads for npm auth, used to inject curation's fallback credential
	// (see injectCurationFallbackAuthEnv) without touching YARN_NPM_REGISTRY_SERVER.
	//#nosec G101
	yarnNpmAuthIdentEnv = "YARN_NPM_AUTH_IDENT"
	//#nosec G101
	yarnNpmAuthTokenEnv  = "YARN_NPM_AUTH_TOKEN"
	yarnNpmAlwaysAuthEnv = "YARN_NPM_ALWAYS_AUTH"
	yarnV2Version        = "2.0.0"
	yarnV3Version   = "3.0.0"
	// YarnV4Version is the lowest version treated as Yarn V4 (native .yarnrc.yml mode).
	YarnV4Version       = "4.0.0"
	nodeModulesRepoName = "node_modules"

	// Command registered by the embedded resolution-only plugin.
	resolveLockfilePluginCommand = "jfrog-yarn-resolve-lockfile"
	// Plugin path inside the curation temp dir (the layout yarn loads from).
	resolveLockfilePluginRelPath = ".yarn/plugins/jfrog-yarn-resolve-lockfile.cjs"
	// Spec recorded in .yarnrc.yml; only the path matters to yarn.
	resolveLockfilePluginSpec = "@yarnpkg/plugin-jfrog-yarn-resolve-lockfile"
)

// Resolution-only Yarn V3/V4 plugin: builds a complete yarn.lock from registry
// metadata without fetching tarballs, so curation's 403s don't abort it.
//
//go:embed resources/jfrog-yarn-resolve-lockfile.cjs
var resolveLockfilePluginJS []byte

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	// When 'jf ca --working-dirs=<X>' targets a yarn workspace member, yarn V2+ cannot run
	// from a non-root. Walk up to the yarn root, drive the audit from there, and remember
	// memberRel to prune the dep map to just the member's subgraph.
	// Gated on IsCurationCmd — generic audit/scan must not walk upward.
	workspaceMemberRel := ""
	if params.IsCurationCmd {
		if rootDir, memberRel := findClaimingYarnWorkspaceRoot(currentDir); rootDir != "" {
			log.Info(fmt.Sprintf(
				"Detected yarn workspace member '%s' under '%s'; re-rooting the audit to the workspace root and filtering results to '%s'.",
				memberRel, rootDir, memberRel))
			currentDir = rootDir
			workspaceMemberRel = memberRel
		}
	}
	executablePath, err := bibuildutils.GetYarnExecutable()
	if errorutils.CheckError(err) != nil {
		return
	}

	// Log the resolved yarn binary version up front so the rest of the audit
	// log can be correlated to a specific yarn release. The integration's code
	// paths differ markedly between V1, V2, V3 and V4 (lockfile-only install
	// mode, Artifactory resolution support, enumeration semantics), and having
	// the version stamped in the log avoids guesswork when triaging reports
	// from different machines or after a 'yarn set version' bump mid-session.
	logYarnExecutableVersion(executablePath, currentDir)

	// Curation issues per-package HEAD requests to Artifactory, which only
	// return meaningful curation JSON for packages Artifactory has resolved.
	// The jfrog-cli yarn integration resolves through Artifactory for Yarn
	// V2/V3/V4; only V1 (classic) silently bypasses it and produces unreliable
	// curation results, so reject V1 up front.
	if params.IsCurationCmd {
		if err = VerifyYarnVersionSupportedForCuration(executablePath, currentDir); err != nil {
			return
		}
	}

	packageInfo, err := bibuildutils.ReadPackageInfoFromPackageJsonIfExists(currentDir, nil)
	if errorutils.CheckError(err) != nil {
		return
	}

	// resolveDir is where we read yarn.lock and run GetYarnDependencies.
	// For curation: a temp copy of the project so the customer's files are
	// never modified. For non-curation: the project directory itself.
	resolveDir := currentDir
	var deferredInstallErr error

	if params.IsCurationCmd {
		var lockfileCleanup func() error
		resolveDir, lockfileCleanup, deferredInstallErr, err = resolveCurationLockfileDir(params, currentDir, executablePath, workspaceMemberRel)
		if err != nil {
			return
		}
		defer func() { err = errors.Join(err, lockfileCleanup()) }()
	} else {
		installRequired, installCheckErr := isInstallRequired(currentDir, params.InstallCommandArgs, params.SkipAutoInstall, params.YarnOverwriteYarnLock)
		if installCheckErr != nil {
			err = installCheckErr
			return
		}
		if installRequired {
			if installErr := configureYarnResolutionServerAndRunInstall(params, currentDir, executablePath); installErr != nil {
				err = fmt.Errorf("failed to configure an Artifactory resolution server or running an install command: %w", installErr)
				return
			}
		}
	}

	// Log the number of yarn.lock entries so debug output shows whether the
	// lockfile is complete or partial (some manifests blocked by curation).
	if params.IsCurationCmd {
		logYarnLockEntryCount(filepath.Join(resolveDir, yarn.YarnLockFileName))
	}

	// Calculate Yarn dependencies
	dependenciesMap, root, err := bibuildutils.GetYarnDependencies(executablePath, resolveDir, packageInfo, log.Logger, params.AllowPartialResults)
	if err != nil {
		// On workspaces projects a prior curation 403 leaves yarn's install
		// state inconsistent; 'yarn info' then emits an opaque parse error.
		// Re-wrap with actionable context via enumerateAfterCurationInstallError.
		if params.IsCurationCmd && deferredInstallErr != nil {
			err = enumerateAfterCurationInstallError(params, resolveDir, workspaceMemberRel, deferredInstallErr, err)
		}
		return
	}
	// Curation-only: 'jf audit'/'jf scan' keep the root GetYarnDependencies resolved.
	if params.IsCurationCmd {
		packageName := ""
		if packageInfo != nil {
			packageName = packageInfo.Name
		}
		root = resolveYarnRoot(dependenciesMap, root, packageName)
	}
	stripWorkspaceUseLocalSuffix(dependenciesMap)
	if root == nil {
		err = errorutils.CheckErrorf("could not identify the root workspace from yarn dependency output")
		return
	}
	// When --working-dirs targets a workspace member, prune dependenciesMap
	// to the subgraph reachable from that member and reset root accordingly.
	// This keeps the dependency tree and the uniqueDeps list
	// faithful to "what does <member> actually depend on".
	if workspaceMemberRel != "" {
		filteredMap, memberRoot, filterErr := filterYarnDepMapToWorkspaceMember(dependenciesMap, workspaceMemberRel)
		if filterErr != nil {
			err = filterErr
			return
		}
		dependenciesMap = filteredMap
		root = memberRoot
		log.Debug(fmt.Sprintf(
			"yarn workspace-member filter: scoped dependency map to '%s' — %d entries reachable from %s",
			workspaceMemberRel, len(dependenciesMap), root.Value))
	} else if params.IsCurationCmd {
		// Workspace members are siblings of the root, not its deps, so their
		// subgraphs would be orphaned and never probed. Attach each as a root
		// child so 'jf ca' audits the whole workspace graph (matching npm/pnpm).
		attachWorkspaceMembersToRoot(dependenciesMap, root)
	}
	// Inject synthetic dep-tree entries for any direct deps that curation
	// blocked during 'yarn install --mode=update-lockfile' (which aborts the
	// lockfile write on a 403, leaving newly-declared deps absent from the
	// resolved map). Fixed versions only; semver ranges are skipped with a
	// warning. Skipped for jf audit/scan — those must use literal yarn.lock.
	if params.IsCurationCmd {
		declared := collectDeclaredDirectDepsForMember(resolveDir, workspaceMemberRel)
		reconcileDeclaredDirectDepsAgainstTree(dependenciesMap, root, declared)
	}
	// Parse the dependencies into Xray dependency tree format
	rootXrayId, err := getXrayDependencyId(root)
	if err != nil {
		return
	}
	dependencyTree, uniqueDeps, err := parseYarnDependenciesMap(dependenciesMap, rootXrayId, params.IsCurationCmd)
	if err != nil {
		return
	}
	dependencyTrees = []*xrayUtils.GraphNode{dependencyTree}
	return
}

// logYarnExecutableVersion logs the yarn binary version at INFO level.
// Version probe errors are demoted to DEBUG so the audit is never blocked.
func logYarnExecutableVersion(yarnExecPath, curWd string) {
	versionStr, err := bibuildutils.GetVersion(yarnExecPath, curWd)
	if err != nil {
		log.Debug(fmt.Sprintf("could not determine yarn version from '%s': %s", yarnExecPath, err.Error()))
		return
	}
	log.Info(fmt.Sprintf("Yarn version: %s", strings.TrimSpace(versionStr)))
}

// logYarnLockEntryCount logs the number of resolved entries in yarn.lock at
// DEBUG level so audit logs show whether the lockfile is complete or partial.
func logYarnLockEntryCount(yarnLockPath string) {
	data, err := os.ReadFile(yarnLockPath)
	if err != nil {
		log.Debug(fmt.Sprintf("yarn curation: could not read '%s' for entry-count diagnostic: %s", yarnLockPath, err.Error()))
		return
	}
	count := bytes.Count(data, []byte("\n  resolution: "))
	log.Debug(fmt.Sprintf("yarn curation: '%s' contains %d resolved package entries; the curation walker will HEAD-check this set", yarnLockPath, count))
}

// VerifyYarnVersionSupportedForCuration rejects Yarn V1 — curation only supports
// V2/V3/V4, which resolve the registry from .yarnrc.yml.
func VerifyYarnVersionSupportedForCuration(yarnExecPath, curWd string) error {
	versionStr, err := bibuildutils.GetVersion(yarnExecPath, curWd)
	if err != nil {
		return err
	}
	yarnVersion := version.NewVersion(versionStr)
	if yarnVersion.Compare(yarnV2Version) > 0 {
		return errorutils.CheckErrorf("'jf curation-audit' is not supported for Yarn V1 (detected: %s). Curation requires Artifactory-resolved installs, which the curation flow supports for Yarn V2, V3, and V4.", versionStr)
	}
	return nil
}

// handleCurationInstallError translates a failed 'yarn install' into the right
// audit outcome. For jf audit, any install error is fatal. For jf ca, a 403
// on blocked tarballs is expected; when yarn.lock was produced we warn and
// continue. Without a lockfile we surface a direct-dep probe table instead.
func handleCurationInstallError(params technologies.BuildInfoBomGeneratorParams, curWd, yarnExecPath, workspaceMemberRel string, installErr error, preInstallLockMtime time.Time) error {
	if !params.IsCurationCmd {
		return fmt.Errorf("failed to configure an Artifactory resolution server or running an install command: %w", installErr)
	}
	yarnLockPath := filepath.Join(curWd, yarn.YarnLockFileName)
	lockExists, statErr := fileutils.IsFileExists(yarnLockPath, false)
	if statErr != nil {
		return errors.Join(installErr, fmt.Errorf("failed to check the existence of '%s' after install: %s", yarnLockPath, statErr.Error()))
	}
	if !lockExists {
		return curationNoLockfileError(params, curWd, yarnExecPath, workspaceMemberRel, installErr)
	}
	log.Warn(fmt.Sprintf("'yarn install' against curation repo '%s' exited with: %s", params.DependenciesRepository, installErr.Error()))
	// When mtime is unchanged yarn rolled back the lockfile write entirely
	// (V3 --mode=update-lockfile on an uncached 403). The reconciliation pass
	// in BuildDependencyTree will surface any newly-declared direct deps.
	postInstallLockMtime := lockfileMtime(yarnLockPath)
	if !preInstallLockMtime.IsZero() && !postInstallLockMtime.IsZero() && !postInstallLockMtime.After(preInstallLockMtime) {
		log.Warn(fmt.Sprintf(
			"'%s' was not updated by this install (yarn rolled the write transaction back, mtime unchanged). Continuing with the existing lockfile contents; any newly-declared direct dependencies missing from it will be reconciled against the curation registry separately.",
			yarn.YarnLockFileName))
	} else {
		log.Warn(fmt.Sprintf(
			"'%s' was produced regardless; continuing with curation analysis. Blocked packages will appear in the report.",
			yarn.YarnLockFileName))
	}
	return nil
}

// lockfileMtime returns yarn.lock's mtime, or zero if the file is missing or
// unreadable. Callers compare against zero to detect "no measurement available".
func lockfileMtime(yarnLockPath string) time.Time {
	info, err := os.Stat(yarnLockPath)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// installErrCarriesCurationBlockSignal reports whether installErr looks like a curation
// block (HTTP 403), as opposed to an unrelated failure (e.g. an auth error). Yarn echoes
// curation's HTTP response verbatim, e.g. "YN0035: ... Response Code: 403 (Forbidden)".
func installErrCarriesCurationBlockSignal(installErr error) bool {
	if installErr == nil {
		return false
	}
	errText := strings.ToLower(installErr.Error())
	return strings.Contains(errText, "403") || strings.Contains(errText, "forbidden")
}

// curationNoLockfileError builds an actionable error for when 'yarn install'
// did not produce yarn.lock. Probes declared direct deps against the curation
// repo and renders blocked ones in a table. Error text is version-specific:
// V2 has no lockfile-only install mode; V3+ reaching here means curation is
// blocking manifests (not just tarballs).
func curationNoLockfileError(params technologies.BuildInfoBomGeneratorParams, curWd, yarnExecPath, workspaceMemberRel string, installErr error) error {
	probed, totalProbed := probeBlockedDirectDeps(params, curWd, workspaceMemberRel)
	// Only blame curation when there's actual evidence of a block: a rejected direct dep
	// from the probe, or a curation-block signal in installErr. Otherwise installErr is
	// unrelated, and blaming curation would misdirect engineers into removing packages
	// curation never evaluated.
	if len(probed) == 0 && !installErrCarriesCurationBlockSignal(installErr) {
		return errorutils.CheckErrorf("'jf curation-audit' against curation repo '%s' could not produce '%s' — 'yarn install' failed for a reason unrelated to a curation block (no HTTP 403/rejected-package evidence found). Check the debug log for the underlying 'yarn install' output. Underlying yarn error: %s", params.DependenciesRepository, yarn.YarnLockFileName, installErr.Error())
	}
	outputRef := string(outFormat.Table)
	if params.OutputFormat == outFormat.Json {
		outputRef = "JSON output"
	}
	tableRendered := false
	tableNote := ""
	if len(probed) > 0 {
		if tableErr := npm.PrintBlockedDirectDepsTable(probed, totalProbed, params.OutputFormat, techutils.Yarn); tableErr != nil {
			log.Debug(fmt.Sprintf("yarn curation probe: failed to render blocked deps table: %s", tableErr.Error()))
		} else {
			tableRendered = true
			tableNote = fmt.Sprintf(" The %d direct dependencies that the curation repo rejected with HTTP 403 are listed in the %s above.", len(probed), outputRef)
			tableNote += " Without a 'yarn.lock' the audit cannot enumerate transitives; only direct blockers are listed. Once enough directs pass curation that Yarn writes a lockfile, transitive blockers are audited automatically."
		}
	}
	// buildSuffix assembles the note + recommendation appended after the
	// "...lockfile was written." sentence. It begins with a leading space.
	// When the probe surfaced blocked directs (table rendered) we point the user
	// at them; otherwise the blocker is a transitive we can't enumerate without a
	// lockfile, so referencing a (non-existent) table would be misleading.
	buildSuffix := func(completionVerb string) string {
		if tableRendered {
			return tableNote + fmt.Sprintf(" Remove or replace the blocked direct dependencies in the %s above and re-run 'jf ca'; once they pass curation, %s completes and the audit enumerates the full graph.", outputRef, completionVerb)
		}
		return " Probing the declared direct dependencies did not surface the blocked package, so it is likely a transitive dependency that cannot be enumerated without a 'yarn.lock'. Check the debug log for the underlying 'yarn install' output to identify the blocked package (or pre-generate 'yarn.lock' against a non-curation registry), then remove/replace it or request a waiver and re-run 'jf ca'."
	}
	yarnVersionStr, versionErr := bibuildutils.GetVersion(yarnExecPath, curWd)
	if versionErr == nil {
		yarnVersion := version.NewVersion(yarnVersionStr)
		isV2 := yarnVersion.Compare(yarnV2Version) <= 0 && yarnVersion.Compare(yarnV3Version) > 0
		if isV2 {
			return errorutils.CheckErrorf("'jf curation-audit' against curation repo '%s' could not produce '%s' with Yarn %s — V2 has no lockfile-only install mode, so any blocked package aborts the install before the lockfile is written.%s Secondary option: upgrade the project to Yarn V3+ ('yarn set version 3.6.4'). V3/V4 resolve the lockfile from registry metadata (via the jfrog-yarn-resolve-lockfile plugin) without downloading tarballs, so 'jf ca' can audit even while curation blocks tarballs. Underlying yarn error: %s", params.DependenciesRepository, yarn.YarnLockFileName, yarnVersionStr, buildSuffix("install"), installErr.Error())
		}
		return errorutils.CheckErrorf("'jf curation-audit' against curation repo '%s' could not produce '%s' with Yarn %s — 'yarn jfrog-yarn-resolve-lockfile' aborted before the lockfile was written (curation is blocking manifests, not just tarballs).%s Underlying yarn error: %s", params.DependenciesRepository, yarn.YarnLockFileName, yarnVersionStr, buildSuffix("resolve"), installErr.Error())
	}
	return errorutils.CheckErrorf("'jf curation-audit' against curation repo '%s' could not produce '%s' — 'yarn install' failed before the lockfile was written (curation is likely blocking manifests, not just tarballs).%s Underlying yarn error: %s", params.DependenciesRepository, yarn.YarnLockFileName, buildSuffix("install"), installErr.Error())
}

// enumerateAfterCurationInstallError handles the workspace-specific case where
// 'yarn install' failed with a curation 403, leaving the install state
// inconsistent. 'yarn info' then fails with an opaque parse error on workspaces
// projects. Since we can't enumerate the full tree, we fall back to a
// direct-dep probe table so the user sees which packages curation blocked.
func enumerateAfterCurationInstallError(params technologies.BuildInfoBomGeneratorParams, curWd, workspaceMemberRel string, installErr, enumerationErr error) error {
	probed, totalProbed := probeBlockedDirectDeps(params, curWd, workspaceMemberRel)
	tablePointer := ""
	if len(probed) > 0 {
		if tableErr := npm.PrintBlockedDirectDepsTable(probed, totalProbed, params.OutputFormat, techutils.Yarn); tableErr != nil {
			log.Debug(fmt.Sprintf("yarn curation probe: failed to render blocked deps table: %s", tableErr.Error()))
		} else {
			if params.OutputFormat == outFormat.Json {
				tablePointer = " (listed in the JSON output above)"
			} else {
				tablePointer = " (listed in the table above)"
			}
		}
	}
	return errorutils.CheckErrorf(
		"'jf curation-audit' against curation repo '%s' audited direct dependencies only%s — transitives could not be enumerated in full because the install was blocked (HTTP 403) and yarn could not read the workspaces project back from the rolled-back lockfile. "+
			"Remove or replace the blocked direct dependencies and re-run 'jf ca'; once they pass curation, yarn writes the full lockfile and transitives are audited automatically. "+
			"Underlying yarn install error: %s. Underlying yarn enumeration error: %s.",
		params.DependenciesRepository, tablePointer, installErr.Error(), enumerationErr.Error())
}

// probeBlockedDirectDeps HEAD/GET-probes each declared direct dependency's npm tarball URL directly, delegating to the shared npm.ProbeBlockedDirectDeps (also used by pnpm's fallback); workspaceMemberRel, when non-empty, scopes it to one workspace member (--working-dirs).
func probeBlockedDirectDeps(params technologies.BuildInfoBomGeneratorParams, curWd, workspaceMemberRel string) ([]npm.BlockedDirectDep, int) {
	declared := collectDeclaredDirectDepsForMember(curWd, workspaceMemberRel)
	if len(declared) == 0 {
		return nil, 0
	}
	return npm.ProbeBlockedDirectDeps(params, declared, "yarn")
}

// collectDeclaredDirectDeps merges the root package.json's direct deps with every workspace member's, so a member-only dependency isn't invisible to the curation probe.
func collectDeclaredDirectDeps(curWd string) map[string]string {
	return npm.CollectDeclaredDirectDeps(curWd, expandYarnWorkspaceDirs(curWd))
}

// collectDeclaredDirectDepsForMember returns direct deps for the whole workspace (memberRel == "") or a single member's package.json; missing/empty member returns an empty map, no fallback.
func collectDeclaredDirectDepsForMember(curWd, memberRel string) map[string]string {
	if memberRel == "" {
		return collectDeclaredDirectDeps(curWd)
	}
	memberDir := filepath.Join(curWd, filepath.FromSlash(memberRel))
	pi, err := bibuildutils.ReadPackageInfoFromPackageJsonIfExists(memberDir, nil)
	if err != nil || pi == nil {
		return map[string]string{}
	}
	return npm.MergeDirectDeps(pi)
}

// expandYarnWorkspaceDirs reads package.json's "workspaces" field (either shape below) and expands it via the shared npm.ExpandWorkspaceDirs.
//
//	"workspaces": ["packages/*", "tools/*"]
//	"workspaces": {"packages": ["packages/*"]}
func expandYarnWorkspaceDirs(curWd string) []string {
	data, err := os.ReadFile(filepath.Join(curWd, "package.json"))
	if err != nil {
		return nil
	}
	var raw struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &raw); err != nil || len(raw.Workspaces) == 0 {
		return nil
	}
	patterns := techutils.DecodeYarnWorkspacesField(raw.Workspaces)
	return npm.ExpandWorkspaceDirs(curWd, patterns, "yarn")
}

// reconcileDeclaredDirectDepsAgainstTree injects synthetic dep-tree entries
// for declared direct deps missing from the resolved map (e.g. because a
// curation 403 aborted yarn's lockfile write). Fixed-semver deps get a
// synthetic entry so the curation walker HEAD-checks them; semver ranges and
// dist-tags are skipped with a warning; non-registry specifiers are ignored.
// Callers must gate on IsCurationCmd — audit/scan use yarn.lock verbatim.
func reconcileDeclaredDirectDepsAgainstTree(
	dependenciesMap map[string]*bibuildutils.YarnDependency,
	root *bibuildutils.YarnDependency,
	declared map[string]string,
) {
	if root == nil || len(declared) == 0 {
		return
	}
	var synthesised, unresolvedRanges []string
	for name, spec := range declared {
		resolvedVer, probeable, isRangeOrTag := npm.ClassifyNpmVersionSpec(spec)
		if probeable {
			locator := name + "@npm:" + resolvedVer
			if _, dup := dependenciesMap[locator]; dup {
				continue
			}
			dependenciesMap[locator] = &bibuildutils.YarnDependency{
				Value:   locator,
				Details: bibuildutils.YarnDepDetails{Version: resolvedVer},
			}
			root.Details.Dependencies = append(root.Details.Dependencies, bibuildutils.YarnDependencyPointer{Locator: locator})
			synthesised = append(synthesised, fmt.Sprintf("%s@%s", name, resolvedVer))
			continue
		}
		if isRangeOrTag {
			unresolvedRanges = append(unresolvedRanges, fmt.Sprintf("%s@%s", name, spec))
		}
	}
	if len(synthesised) > 0 {
		slices.Sort(synthesised)
		log.Debug(fmt.Sprintf(
			"yarn curation reconciliation: %d direct dependency(ies) declared in package.json but missing from yarn.lock — synthesised under root for the curation HEAD-check: %s",
			len(synthesised), strings.Join(synthesised, ", ")))
	}
	if len(unresolvedRanges) > 0 {
		slices.Sort(unresolvedRanges)
		log.Warn(fmt.Sprintf(
			"yarn curation: %d direct dependency(ies) declared with non-fixed version specifiers are missing from yarn.lock and were not HEAD-checked: %s. This usually means yarn rolled back its lockfile write after another direct dependency was blocked. Remove or replace the blocked direct dependencies and re-run 'jf ca' — once install succeeds these will resolve into yarn.lock and be audited too.",
			len(unresolvedRanges), strings.Join(unresolvedRanges, ", ")))
	}
}

// runYarnCommandQuiet runs yarn with stdout and stderr captured internally.
// Failure output goes to Debug only (raw internals, not user-actionable); success output is discarded to keep stdout JSON clean.
func runYarnCommandQuiet(executablePath, srcPath string, args ...string) error {
	command := exec.Command(executablePath, args...)
	command.Dir = srcPath
	var combined bytes.Buffer
	command.Stdout = &combined
	command.Stderr = &combined
	if err := command.Run(); err != nil {
		if msg := strings.TrimSpace(combined.String()); msg != "" {
			log.Debug("yarn install output:\n" + msg)
		}
		return err
	}
	return nil
}

// resolveCurationLockfileDir prepares the directory from which the curation
// audit reads yarn.lock. When install is needed it copies the project to a
// temp dir, configures the curation registry there, and runs
// 'yarn jfrog-yarn-resolve-lockfile' (V3/V4) or 'yarn install' (V2) —
// so the customer's project content is never modified and read-only CI checkouts still work.
//
// Exception: it bumps the original yarn.lock's mtime (touchYarnLock) so the
// next run skips re-resolution — mtime only, not content; failures are ignored.
//
// Returns:
//   - lockfileDir: where to read yarn.lock / run GetYarnDependencies from
//   - cleanup:     must always be called by the caller (no-op when using currentDir)
//   - deferredInstallErr: non-nil when yarn install failed with a curation 403
//     but handleCurationInstallError determined we can continue (lockfile was
//     partially written); the caller should surface it if enumeration also fails
func resolveCurationLockfileDir(
	params technologies.BuildInfoBomGeneratorParams,
	currentDir, yarnExecPath, workspaceMemberRel string,
) (lockfileDir string, cleanup func() error, deferredInstallErr error, err error) {
	noop := func() error { return nil }

	installRequired, err := isInstallRequired(currentDir, params.InstallCommandArgs, params.SkipAutoInstall, params.YarnOverwriteYarnLock)
	if err != nil {
		return "", noop, nil, err
	}
	if !installRequired {
		return currentDir, noop, nil, nil
	}

	tmpDir, err := fileutils.CreateTempDir()
	if err != nil {
		return "", noop, nil, fmt.Errorf("failed to create a temporary dir: %w", err)
	}
	cleanup = func() error { return fileutils.RemoveTempDir(tmpDir) }
	defer func() {
		if err != nil {
			err = errors.Join(err, cleanup())
			cleanup = noop
		}
	}()

	if err = biutils.CopyDir(currentDir, tmpDir, true, []string{technologies.DotVsRepoSuffix}); err != nil {
		return "", cleanup, nil, fmt.Errorf("failed copying project to temp dir: %w", err)
	}

	preInstallLockMtime := lockfileMtime(filepath.Join(tmpDir, yarn.YarnLockFileName))
	installErr := configureYarnResolutionServerAndRunInstall(params, tmpDir, yarnExecPath)
	if installErr != nil {
		if err = handleCurationInstallError(params, tmpDir, yarnExecPath, workspaceMemberRel, installErr, preInstallLockMtime); err != nil {
			return "", cleanup, nil, err
		}
		deferredInstallErr = installErr
	}

	// Bump the original yarn.lock mtime so the next run skips re-resolution, but
	// only when its content already covers all declared deps. The resolved lock
	// lives in tmpDir; touching an incomplete original would mask staleness.
	if !yarnLockMissesDeclaredDeps(currentDir, filepath.Join(currentDir, yarn.YarnLockFileName)) {
		touchYarnLock(currentDir)
	}

	return tmpDir, cleanup, deferredInstallErr, nil
}

// Sets up Artifactory server configurations for dependency resolution, if such were provided by the user.
// Executes the user's 'install' command or a default 'install' command if none was specified.
func configureYarnResolutionServerAndRunInstall(params technologies.BuildInfoBomGeneratorParams, curWd, yarnExecPath string) (err error) {
	depsRepo := params.DependenciesRepository

	// Skip credential injection when no repo was resolved, or for curation (native
	// .yarnrc.yml resolution already has it, for V2/V3/V4 alike). Only non-curation
	// V2/V3 with a repo from --deps-repo or 'jf yarn-config' still needs it below.
	useNativeInstall := depsRepo == "" || params.IsCurationCmd
	if !useNativeInstall {
		executableYarnVersion, versionErr := bibuildutils.GetVersion(yarnExecPath, curWd)
		if versionErr != nil {
			return versionErr
		}
		useNativeInstall = version.NewVersion(executableYarnVersion).Compare(YarnV4Version) <= 0
	}
	if useNativeInstall {
		if params.IsCurationCmd && depsRepo != "" {
			// If .yarnrc.yml has no token, curation may have resolved a fallback credential
			// into params.ServerDetails. Inject it into the subprocess env, since the native
			// install path above skips the GetYarnAuthDetails+ModifyYarnConfigurations
			// injection below (which also sets YARN_NPM_REGISTRY_SERVER, unwanted here).
			restoreAuthEnv, authErr := injectCurationFallbackAuthEnv(params.ServerDetails, depsRepo)
			if authErr != nil {
				return authErr
			}
			defer func() {
				err = errors.Join(err, restoreAuthEnv())
			}()
		}
		err = runYarnInstallAccordingToVersion(curWd, yarnExecPath, params.InstallCommandArgs, params.IsCurationCmd)
		return
	}

	// V2/V3 (non-curation): inject Artifactory credentials via GetYarnAuthDetails + ModifyYarnConfigurations.
	// V1 is rejected earlier by VerifyYarnVersionSupportedForCuration (curation) or is unsupported
	// by the jfrog-cli-artifactory yarn integration (non-curation).
	restoreYarnrcFunc, err := ioutils.BackupFile(filepath.Join(curWd, yarn.YarnrcFileName), yarn.YarnrcBackupFileName)
	if err != nil {
		return err
	}

	registry, repoAuthIdent, npmAuthToken, err := yarn.GetYarnAuthDetails(params.ServerDetails, depsRepo)
	if err != nil {
		return errors.Join(err, restoreYarnrcFunc())
	}

	// api/curation/audit's redirect is broken (missing /api/npm/ segment, breaks yarn's JSON.parse);
	// the direct-dep probe + post-resolution HEAD-walker enforce curation instead.
	log.Debug(fmt.Sprintf("Yarn npmRegistryServer set to: %s", registry))

	backupEnvMap, err := yarn.ModifyYarnConfigurations(yarnExecPath, registry, repoAuthIdent, npmAuthToken)
	if err != nil {
		if len(backupEnvMap) > 0 {
			return errors.Join(err, yarn.RestoreConfigurationsFromBackup(backupEnvMap, restoreYarnrcFunc))
		}
		return errors.Join(err, restoreYarnrcFunc())
	}
	defer func() {
		err = errors.Join(err, yarn.RestoreConfigurationsFromBackup(backupEnvMap, restoreYarnrcFunc))
	}()

	log.Info(fmt.Sprintf("Resolving dependencies from '%s' from repo '%s'", params.ServerDetails.Url, depsRepo))
	err = runYarnInstallAccordingToVersion(curWd, yarnExecPath, params.InstallCommandArgs, params.IsCurationCmd)
	return err
}

// injectCurationFallbackAuthEnv sets YARN_NPM_AUTH_IDENT/YARN_NPM_AUTH_TOKEN/YARN_NPM_ALWAYS_AUTH
// from serverDetails for the yarn subprocess, without setting YARN_NPM_REGISTRY_SERVER — the
// registry must keep coming from .yarnrc.yml. No-op (returns a no-op restore) when serverDetails
// has no usable credentials, so the anonymous case is unchanged.
func injectCurationFallbackAuthEnv(serverDetails *config.ServerDetails, depsRepo string) (restore func() error, err error) {
	noOpRestore := func() error { return nil }
	if serverDetails == nil || (serverDetails.AccessToken == "" && serverDetails.User == "") {
		return noOpRestore, nil
	}
	_, npmAuthIdent, npmAuthToken, err := yarn.GetYarnAuthDetails(serverDetails, depsRepo)
	if err != nil {
		return noOpRestore, err
	}
	if npmAuthIdent == "" && npmAuthToken == "" {
		return noOpRestore, nil
	}

	envUpdates := map[string]string{
		yarnNpmAuthIdentEnv:  npmAuthIdent,
		yarnNpmAuthTokenEnv:  npmAuthToken,
		yarnNpmAlwaysAuthEnv: "true",
	}
	backup := make(map[string]*string, len(envUpdates))
	for key, value := range envUpdates {
		if oldVal, existed := os.LookupEnv(key); existed {
			backup[key] = &oldVal
		} else {
			backup[key] = nil
		}
		if setErr := os.Setenv(key, value); setErr != nil {
			return noOpRestore, setErr
		}
	}
	return func() error {
		var restoreErrs []error
		for key, oldVal := range backup {
			if oldVal == nil {
				restoreErrs = append(restoreErrs, os.Unsetenv(key))
				continue
			}
			restoreErrs = append(restoreErrs, os.Setenv(key, *oldVal))
		}
		return errors.Join(restoreErrs...)
	}, nil
}

// isInstallRequired reports whether 'yarn install' must run before enumerating
// the dependency tree. Install is needed when the user supplied an explicit
// install command, yarn.lock is missing, or overwriteYarnLock is set and the
// lockfile is older than package.json. skipAutoInstall converts a missing
// lockfile into a typed ErrProjectNotInstalled instead of running install.
func isInstallRequired(currentDir string, installCommandArgs []string, skipAutoInstall, overwriteYarnLock bool) (installRequired bool, err error) {
	yarnLockPath := filepath.Join(currentDir, yarn.YarnLockFileName)
	yarnLockExits, err := fileutils.IsFileExists(yarnLockPath, false)
	if err != nil {
		err = fmt.Errorf("failed to check the existence of '%s' file: %s", yarnLockPath, err.Error())
		return
	}

	if len(installCommandArgs) > 0 {
		return true, nil
	}
	stale := overwriteYarnLock && yarnLockExits && isYarnLockStale(currentDir)
	if stale {
		log.Debug(fmt.Sprintf("'%s' is older than '%s'; refreshing the lockfile so the audit reflects the current declared dependencies", yarn.YarnLockFileName, "package.json"))
	}
	if !yarnLockExits || stale {
		if skipAutoInstall {
			return false, &biutils.ErrProjectNotInstalled{UninstalledDir: currentDir}
		}
		return true, nil
	}
	return false, nil
}

// isYarnLockStale reports whether yarn.lock needs regeneration.
// If package.json is newer by mtime it does a specifier-coverage check: if
// every declared direct dep already has an entry in yarn.lock the lockfile is
// still fresh (handles yarn V4 stamping packageManager in package.json after
// writing yarn.lock, which would otherwise always trigger re-resolution).
func isYarnLockStale(curWd string) bool {
	pkgJsonStat, err := os.Stat(filepath.Join(curWd, "package.json"))
	if err != nil {
		return false
	}
	lockPath := filepath.Join(curWd, yarn.YarnLockFileName)
	lockStat, err := os.Stat(lockPath)
	if err != nil {
		return false
	}
	if !pkgJsonStat.ModTime().After(lockStat.ModTime()) {
		return false
	}
	return yarnLockMissesDeclaredDeps(curWd, lockPath)
}

// yarnLockMissesDeclaredDeps returns true if any direct dep declared in
// package.json has no entry in yarn.lock (Berry quoted format: "dep@...).
// Covers all four dependency sections (matching mergeDirectDeps) so adding a
// peer/optional dep also triggers re-resolution.
func yarnLockMissesDeclaredDeps(curWd, lockPath string) bool {
	pkgData, err := os.ReadFile(filepath.Join(curWd, "package.json"))
	if err != nil {
		return true
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err = json.Unmarshal(pkgData, &pkg); err != nil {
		return true
	}
	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return true
	}
	lockContent := string(lockData)
	for _, section := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
		for dep := range section {
			if !strings.Contains(lockContent, `"`+dep+`@`) {
				return true
			}
		}
	}
	return false
}

// touchYarnLock bumps yarn.lock mtime to now so isYarnLockStale won't re-trigger.
func touchYarnLock(curWd string) {
	lockPath := filepath.Join(curWd, yarn.YarnLockFileName)
	now := time.Now()
	_ = os.Chtimes(lockPath, now, now)
}

// runYarnInstallAccordingToVersion runs 'yarn install' (or the user-supplied
// install command). Curation runs suppress yarn's own output; other commands
// preserve it.
func runYarnInstallAccordingToVersion(curWd, yarnExecPath string, installCommandArgs []string, isCurationCmd bool) (err error) {
	runYarn := func(path, wd string, args ...string) error {
		if isCurationCmd {
			return runYarnCommandQuiet(path, wd, args...)
		}
		return build.RunYarnCommand(path, wd, args...)
	}

	// If the installCommandArgs in the params is not empty, it signifies that the user has provided it, and 'install' is already included as one of the arguments
	installCommandProvidedFromUser := len(installCommandArgs) != 0

	// Upon receiving a user-provided 'install' command, we execute the command exactly as provided
	if installCommandProvidedFromUser {
		return runYarn(yarnExecPath, curWd, installCommandArgs...)
	}

	installCommandArgs = []string{"install"}
	executableVersionStr, err := bibuildutils.GetVersion(yarnExecPath, curWd)
	if err != nil {
		return err
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
			return fmt.Errorf("failed while checking for existence of node_modules directory: %w", err)
		}
		if !nodeModulesDirExists {
			defer func() {
				err = errors.Join(err, fileutils.RemoveTempDir(nodeModulesFullPath))
			}()
		}

		installCommandArgs = append(installCommandArgs, v1IgnoreScriptsFlag, v1SilentFlag, v1NonInteractiveFlag)
	} else {
		if yarnVersion.Compare(yarnV3Version) > 0 {
			// V2 has no lockfile-only mode, so install fetches tarballs; a
			// curation 403 aborts it before yarn.lock is written (handled by
			// handleCurationInstallError).
			installCommandArgs = append(installCommandArgs, v2SkipBuildFlag)
		} else {
			// V3+ curation: resolve the full graph from metadata without
			// fetching tarballs, so blocked (uncached) packages don't abort the
			// lockfile. --mode=update-lockfile can't be used: it still fetches
			// uncached tarballs to compute checksums.
			if isCurationCmd {
				return runYarnResolveOnlyLockfile(yarnExecPath, curWd)
			}
			installCommandArgs = append(installCommandArgs, v3UpdateLockfileFlag, v3SkipBuildFlag)
		}
	}
	log.Info(fmt.Sprintf("Running 'yarn %s' command.", strings.Join(installCommandArgs, " ")))
	return runYarn(yarnExecPath, curWd, installCommandArgs...)
}

// runYarnResolveOnlyLockfile installs the embedded plugin and runs it to write
// a complete yarn.lock from registry metadata (no tarball fetch). Output is
// captured quietly; on failure it's surfaced via handleCurationInstallError.
func runYarnResolveOnlyLockfile(yarnExecPath, curWd string) error {
	if err := installResolveLockfilePlugin(curWd); err != nil {
		return fmt.Errorf("failed to install the resolution-only yarn plugin: %w", err)
	}
	log.Info("Running 'yarn jfrog-yarn-resolve-lockfile' command (resolving the dependency graph from registry metadata without downloading tarballs).")
	return runYarnCommandQuiet(yarnExecPath, curWd, resolveLockfilePluginCommand)
}

// installResolveLockfilePlugin writes the embedded plugin into curWd/.yarn/plugins/
// and registers it in curWd/.yarnrc.yml (preserving existing config). Idempotent.
func installResolveLockfilePlugin(curWd string) error {
	pluginPath := filepath.Join(curWd, filepath.FromSlash(resolveLockfilePluginRelPath))
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0700); err != nil {
		return fmt.Errorf("creating yarn plugins dir: %w", err)
	}
	if err := os.WriteFile(pluginPath, resolveLockfilePluginJS, 0600); err != nil {
		return fmt.Errorf("writing yarn plugin file: %w", err)
	}
	return registerYarnPluginInYarnrc(curWd)
}

// registerYarnPluginInYarnrc adds a {path, spec} entry to the "plugins" list of
// curWd/.yarnrc.yml, creating the file if absent and preserving every other
// setting. If an entry with the same path already exists it is left untouched.
func registerYarnPluginInYarnrc(curWd string) error {
	yarnrcPath := filepath.Join(curWd, yarn.YarnrcFileName)
	rc := map[string]interface{}{}
	if data, err := os.ReadFile(yarnrcPath); err == nil {
		if unmarshalErr := yaml.Unmarshal(data, &rc); unmarshalErr != nil {
			log.Debug(fmt.Sprintf("yarn curation: could not parse existing %s (%v); recreating it for the resolution-only plugin", yarn.YarnrcFileName, unmarshalErr))
			rc = map[string]interface{}{}
		}
	}
	if rc == nil {
		rc = map[string]interface{}{}
	}

	// Normalize the existing "plugins" value into a slice we can append to.
	var plugins []interface{}
	if existing, ok := rc["plugins"].([]interface{}); ok {
		plugins = existing
	}
	for _, p := range plugins {
		if entry, ok := p.(map[string]interface{}); ok {
			if path, _ := entry["path"].(string); path == resolveLockfilePluginRelPath {
				return nil // already registered
			}
		}
	}
	plugins = append(plugins, map[string]interface{}{
		"path": resolveLockfilePluginRelPath,
		"spec": resolveLockfilePluginSpec,
	})
	rc["plugins"] = plugins

	updated, err := yaml.Marshal(rc)
	if err != nil {
		return fmt.Errorf("marshalling %s: %w", yarn.YarnrcFileName, err)
	}
	return os.WriteFile(yarnrcPath, updated, 0600)
}

// stripWorkspaceUseLocalSuffix drops Yarn's "-use.local" version marker
// from workspace entries so they display as declared (e.g. 0.0.0).
func stripWorkspaceUseLocalSuffix(dependencies map[string]*bibuildutils.YarnDependency) {
	for _, dep := range dependencies {
		if dep != nil && strings.Contains(dep.Value, "@workspace:") {
			dep.Details.Version = strings.TrimSuffix(dep.Details.Version, "-use.local")
		}
	}
}

func parseYarnDependenciesMap(dependencies map[string]*bibuildutils.YarnDependency, rootXrayId string, isCurationCmd bool) (*xrayUtils.GraphNode, []string, error) {
	treeMap := make(map[string]xray.DepTreeNode)
	workspaceMemberIds := make(map[string]bool)
	for _, dependency := range dependencies {
		xrayDepId, err := getXrayDependencyId(dependency)
		if err != nil {
			return nil, nil, err
		}
		// Workspace members are local, not registry artifacts; skip them in the
		// curation HEAD-check flat list (root exempt). Curation-only.
		if isCurationCmd && strings.Contains(dependency.Value, "@workspace:") && xrayDepId != rootXrayId {
			workspaceMemberIds[xrayDepId] = true
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
	if !isCurationCmd {
		return graph, slices.Collect(maps.Keys(uniqDeps)), nil
	}
	// Workspace members stay in the graph (deps attribute to them) but are
	// dropped from the flat list to avoid false positives on public packages.
	uniqueDepsList := make([]string, 0, len(uniqDeps))
	for id := range uniqDeps {
		if workspaceMemberIds[id] {
			continue
		}
		uniqueDepsList = append(uniqueDepsList, id)
	}
	return graph, uniqueDepsList, nil
}

func getXrayDependencyId(yarnDependency *bibuildutils.YarnDependency) (string, error) {
	dependencyName, err := yarnDependency.Name()
	if err != nil {
		return "", err
	}
	return techutils.Npm.GetXrayPackageTypeId() + dependencyName + ":" + yarnDependency.Details.Version, nil
}

// findYarnWorkspaceRoot returns the dep whose Value ends in "@workspace:.",
// which Yarn V2+ always emits for the project root regardless of whether
// package.json declares a name field.
func findYarnWorkspaceRoot(dependenciesMap map[string]*bibuildutils.YarnDependency) *bibuildutils.YarnDependency {
	const rootWorkspaceSuffix = "@workspace:."
	for _, dep := range dependenciesMap {
		if dep != nil && strings.HasSuffix(dep.Value, rootWorkspaceSuffix) {
			return dep
		}
	}
	return nil
}

// resolveYarnRoot picks the dependency-tree root for 'jf ca' (curation-only;
// see the IsCurationCmd guard in BuildDependencyTree). Trusts heuristicRoot
// unless it's nil or packageName is empty, then falls back to the
// "<name>@workspace:." locator.
func resolveYarnRoot(dependenciesMap map[string]*bibuildutils.YarnDependency, heuristicRoot *bibuildutils.YarnDependency, packageName string) *bibuildutils.YarnDependency {
	if heuristicRoot != nil && packageName != "" {
		return heuristicRoot
	}
	if workspaceRoot := findYarnWorkspaceRoot(dependenciesMap); workspaceRoot != nil {
		return workspaceRoot
	}
	return heuristicRoot
}

// findClaimingYarnWorkspaceRoot walks upward from targetDir to find the nearest
// ancestor that is a Yarn workspace root whose "workspaces" field expands to
// targetDir. Used by 'jf ca --working-dirs=<X>' so the audit runs from the
// workspace root rather than the member directory. Requires: a package.json
// with a "workspaces" field, a glob that matches targetDir, and a Yarn
// indicator file (yarn.lock / .yarnrc.yml / .yarnrc / .yarn/).
func findClaimingYarnWorkspaceRoot(targetDir string) (rootDir, memberRel string) {
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return "", ""
	}
	// Start from the parent — a directory that is itself the target is just
	// a regular workspace root and needs no re-routing.
	cur := filepath.Dir(absTarget)
	for {
		pkgPath := filepath.Join(cur, "package.json")
		if _, statErr := os.Stat(pkgPath); statErr == nil {
			data, readErr := os.ReadFile(pkgPath)
			if readErr != nil {
				return "", ""
			}
			var raw struct {
				Workspaces json.RawMessage `json:"workspaces"`
			}
			if jsonErr := json.Unmarshal(data, &raw); jsonErr == nil && len(raw.Workspaces) > 0 {
				if !techutils.DirectoryHasYarnIndicator(cur) {
					// Workspace-aware but not yarn — likely npm workspaces.
					// Stop here; do not walk further up.
					return "", ""
				}
				for _, wsDir := range expandYarnWorkspaceDirs(cur) {
					absWS, absErr := filepath.Abs(wsDir)
					if absErr != nil {
						continue
					}
					if absWS == absTarget {
						rel, relErr := filepath.Rel(cur, absTarget)
						if relErr != nil {
							return "", ""
						}
						return cur, filepath.ToSlash(rel)
					}
				}
				// Workspace-aware yarn root, but it does not claim
				// targetDir. Stop walking — yarn's resolver wouldn't
				// look further up either.
				return "", ""
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", ""
		}
		cur = parent
	}
}

// attachWorkspaceMembersToRoot makes every workspace member a direct child of
// the root node so the tree walk reaches each member's subgraph. Yarn only links
// a member under the root when the root explicitly depends on it; otherwise
// members are siblings whose deps would be orphaned. Root curation audits only;
// already-linked members are deduped.
func attachWorkspaceMembersToRoot(dependenciesMap map[string]*bibuildutils.YarnDependency, root *bibuildutils.YarnDependency) {
	const workspaceMarker = "@workspace:"
	const rootWorkspaceSuffix = "@workspace:."
	if root == nil {
		return
	}
	linked := map[string]struct{}{}
	for _, ptr := range root.Details.Dependencies {
		linked[bibuildutils.GetYarnDependencyKeyFromLocator(ptr.Locator)] = struct{}{}
	}
	// Iterate in sorted key order so the appended root.Details.Dependencies (which
	// feeds the tree walk) is deterministic across runs, not in map-random order.
	var attached []string
	for _, key := range slices.Sorted(maps.Keys(dependenciesMap)) {
		dep := dependenciesMap[key]
		if dep == nil || dep == root {
			continue
		}
		// Only member workspaces; skip non-workspace packages and the root itself.
		if !strings.Contains(dep.Value, workspaceMarker) || strings.HasSuffix(dep.Value, rootWorkspaceSuffix) {
			continue
		}
		depKey := bibuildutils.GetYarnDependencyKeyFromLocator(dep.Value)
		if _, already := linked[depKey]; already {
			continue
		}
		root.Details.Dependencies = append(root.Details.Dependencies, bibuildutils.YarnDependencyPointer{Locator: dep.Value})
		linked[depKey] = struct{}{}
		attached = append(attached, dep.Value)
	}
	if len(attached) > 0 {
		log.Debug(fmt.Sprintf(
			"yarn curation: attached %d workspace member(s) to the root so their dependencies are audited: %s",
			len(attached), strings.Join(attached, ", ")))
	}
}

// filterYarnDepMapToWorkspaceMember returns the subgraph of dependenciesMap
// reachable from the workspace entry whose Value ends in "@workspace:<memberRelPath>",
// along with that entry as memberRoot. Returns an error when no matching entry
// is found — the scope must not silently widen back to the whole workspace.
func filterYarnDepMapToWorkspaceMember(
	dependenciesMap map[string]*bibuildutils.YarnDependency,
	memberRelPath string,
) (filtered map[string]*bibuildutils.YarnDependency, memberRoot *bibuildutils.YarnDependency, err error) {
	memberSuffix := "@workspace:" + filepath.ToSlash(memberRelPath)
	for _, dep := range dependenciesMap {
		if dep != nil && strings.HasSuffix(dep.Value, memberSuffix) {
			memberRoot = dep
			break
		}
	}
	if memberRoot == nil {
		return nil, nil, errorutils.CheckErrorf(
			"could not scope yarn audit to workspace member '%s': yarn's dependency output contained no entry with suffix %q. "+
				"Verify the member is declared under the root package.json's 'workspaces' field, and that the project has a complete yarn.lock — if curation blocked the most recent install, remove or replace the blocked direct dependencies the audit surfaced and re-run.",
			memberRelPath, memberSuffix)
	}
	filtered = map[string]*bibuildutils.YarnDependency{}
	queue := []*bibuildutils.YarnDependency{memberRoot}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		key := bibuildutils.GetYarnDependencyKeyFromLocator(node.Value)
		if _, seen := filtered[key]; seen {
			continue
		}
		filtered[key] = node
		for _, childPtr := range node.Details.Dependencies {
			childKey := bibuildutils.GetYarnDependencyKeyFromLocator(childPtr.Locator)
			child, ok := dependenciesMap[childKey]
			if !ok || child == nil {
				continue
			}
			queue = append(queue, child)
		}
	}
	return filtered, memberRoot, nil
}

// GetNativeYarnRegistryConfig reads the Artifactory registry URL and auth
// token from the project's .yarnrc.yml via the Yarn CLI. Yarn V2, V3, and V4
// all use the same Berry .yarnrc.yml format, so curation-audit resolves the
// registry natively for every version — no jf yarn-config step is required.
// The URL must contain /api/npm/<repo>/ so that ParseArtifactoryNpmRegistryUrl
// can extract the Artifactory base URL and repository name.
func GetNativeYarnRegistryConfig(yarnExecPath, workingDir string) (*npm.NpmrcRegistryConfig, error) {
	registryURL, err := runYarnConfigGet(yarnExecPath, workingDir, "npmRegistryServer")
	if err != nil {
		return nil, fmt.Errorf("failed to read npmRegistryServer from .yarnrc.yml: %w", err)
	}
	if registryURL == "" || registryURL == "undefined" {
		return nil, fmt.Errorf("npmRegistryServer is not set in .yarnrc.yml; configure it to point to your Artifactory npm repository (e.g. https://<host>/artifactory/api/npm/<repo>/)")
	}

	rtBaseURL, repoName, err := npm.ParseArtifactoryNpmRegistryUrl(registryURL)
	if err != nil {
		return nil, err
	}

	// Auth token lookup: parse .yarnrc.yml files directly rather than using
	// 'yarn config get' with a composite key, which is unreliable across versions.
	// Check order: project .yarnrc.yml → global ~/.yarnrc.yml.
	// For each file, try the registry-scoped entry first, then the global npmAuthToken.
	authToken := readNpmAuthTokenFromYarnrcFiles(registryURL, workingDir)

	return &npm.NpmrcRegistryConfig{
		ArtifactoryUrl: rtBaseURL,
		RepoName:       repoName,
		AuthToken:      authToken,
	}, nil
}

// runYarnConfigGet runs 'yarn config get <key>' in workingDir and returns the
// trimmed output. An empty or "undefined" response means the key is not set.
func runYarnConfigGet(yarnExecPath, workingDir, key string) (string, error) {
	cmd := exec.Command(yarnExecPath, "config", "get", key)
	cmd.Dir = workingDir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("yarn config get %s: %w", key, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// yarnrcFile is the subset of .yarnrc.yml fields we need for curation.
type yarnrcFile struct {
	NpmAuthToken  string                         `yaml:"npmAuthToken"`
	NpmRegistries map[string]yarnrcRegistryEntry `yaml:"npmRegistries"`
}

type yarnrcRegistryEntry struct {
	NpmAuthToken string `yaml:"npmAuthToken"`
}

// readNpmAuthTokenFromYarnrcFiles returns the npm auth token for registryURL by
// parsing .yarnrc.yml files directly. It checks the project-level file first,
// then the global ~/.yarnrc.yml. For each file it tries the registry-scoped
// npmRegistries["<url>"].npmAuthToken entry before falling back to the top-level
// npmAuthToken field.
func readNpmAuthTokenFromYarnrcFiles(registryURL, workingDir string) string {
	candidates := []string{filepath.Join(workingDir, ".yarnrc.yml")}
	if homeDir, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(homeDir, ".yarnrc.yml"))
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var rc yarnrcFile
		if err := yaml.Unmarshal(data, &rc); err != nil {
			log.Debug(fmt.Sprintf("yarn: could not parse %s: %s", path, err))
			continue
		}
		// Scoped registry entry takes priority (trailing-slash tolerant).
		if entry, ok := lookupNpmRegistryEntry(rc.NpmRegistries, registryURL); ok && entry.NpmAuthToken != "" {
			log.Debug(fmt.Sprintf("yarn: using auth token from scoped npmRegistries entry in %s", path))
			return entry.NpmAuthToken
		}
		// Fall back to top-level npmAuthToken in the same file.
		if rc.NpmAuthToken != "" {
			log.Debug(fmt.Sprintf("yarn: using top-level npmAuthToken from %s", path))
			return rc.NpmAuthToken
		}
	}
	return ""
}

// lookupNpmRegistryEntry resolves a npmRegistries entry for registryURL,
// tolerating a trailing-slash mismatch between the query and the stored key.
func lookupNpmRegistryEntry(registries map[string]yarnrcRegistryEntry, registryURL string) (yarnrcRegistryEntry, bool) {
	if entry, ok := registries[registryURL]; ok {
		return entry, true
	}
	withSlash := strings.TrimSuffix(registryURL, "/") + "/"
	if entry, ok := registries[withSlash]; ok {
		return entry, true
	}
	withoutSlash := strings.TrimSuffix(registryURL, "/")
	if entry, ok := registries[withoutSlash]; ok {
		return entry, true
	}
	return yarnrcRegistryEntry{}, false
}
