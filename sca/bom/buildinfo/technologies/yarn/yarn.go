package yarn

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	biutils "github.com/jfrog/build-info-go/utils"
	"gopkg.in/yaml.v3"

	"github.com/jfrog/build-info-go/build"
	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-artifactory/artifactory/commands/yarn"
	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	outFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/ioutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/npm"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
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
	// The jfrog-cli yarn integration only resolves through Artifactory for
	// Yarn V2/V3, so V1 and V4 would silently bypass Artifactory and produce
	// unreliable curation results. Reject those versions up front.
	if params.IsCurationCmd {
		if err = verifyYarnVersionSupportedForCuration(executablePath, currentDir); err != nil {
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
	// Yarn V2+ always emits the project root as "<name>@workspace:.". Prefer
	// that over build-info-go's heuristic, which can misidentify the root
	// when package.json has no name field.
	if workspaceRoot := findYarnWorkspaceRoot(dependenciesMap); workspaceRoot != nil {
		root = workspaceRoot
	}
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
	dependencyTree, uniqueDeps, err := parseYarnDependenciesMap(dependenciesMap, rootXrayId)
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

// verifyYarnVersionSupportedForCuration returns an error for Yarn V1,
// which cannot be routed through Artifactory for curation.
// V2/V3 use configured-registry mode (jf yarn-config); V4 uses native mode (.yarnrc.yml).
func verifyYarnVersionSupportedForCuration(yarnExecPath, curWd string) error {
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

// curationNoLockfileError builds an actionable error for when 'yarn install'
// did not produce yarn.lock. Probes declared direct deps against the curation
// repo and renders blocked ones in a table. Error text is version-specific:
// V2 has no lockfile-only install mode; V3+ reaching here means curation is
// blocking manifests (not just tarballs).
func curationNoLockfileError(params technologies.BuildInfoBomGeneratorParams, curWd, yarnExecPath, workspaceMemberRel string, installErr error) error {
	probed, totalProbed := probeBlockedDirectDeps(params, curWd, workspaceMemberRel)
	outputRef := string(outFormat.Table)
	if params.OutputFormat == outFormat.Json {
		outputRef = "JSON output"
	}
	tableRendered := false
	tableNote := ""
	if len(probed) > 0 {
		if tableErr := printBlockedDirectDepsTable(probed, totalProbed, params.OutputFormat); tableErr != nil {
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
		return " Probing the declared direct dependencies did not surface the blocked package, so it is likely a transitive dependency that cannot be enumerated without a 'yarn.lock'. Identify the blocked package from the 'yarn install' output above (or pre-generate 'yarn.lock' against a non-curation registry), then remove/replace it or request a waiver and re-run 'jf ca'."
	}
	yarnVersionStr, versionErr := bibuildutils.GetVersion(yarnExecPath, curWd)
	if versionErr == nil {
		yarnVersion := version.NewVersion(yarnVersionStr)
		isV2 := yarnVersion.Compare(yarnV2Version) <= 0 && yarnVersion.Compare(yarnV3Version) > 0
		if isV2 {
			return errorutils.CheckErrorf("'jf curation-audit' against curation repo '%s' could not produce '%s' with Yarn %s — V2 has no lockfile-only install mode, so any blocked package aborts the install before the lockfile is written.%s Secondary option: upgrade the project to Yarn V3 ('yarn set version 3.6.4'). V3's '--mode=update-lockfile' writes the lockfile during resolve, so 'jf ca' can audit even while curation blocks tarballs. Underlying yarn error: %s", params.DependenciesRepository, yarn.YarnLockFileName, yarnVersionStr, buildSuffix("install"), installErr.Error())
		}
		return errorutils.CheckErrorf("'jf curation-audit' against curation repo '%s' could not produce '%s' with Yarn %s — 'yarn install --mode=update-lockfile' aborted before the lockfile was written (curation is blocking manifests, not just tarballs).%s Underlying yarn error: %s", params.DependenciesRepository, yarn.YarnLockFileName, yarnVersionStr, buildSuffix("resolve"), installErr.Error())
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
		if tableErr := printBlockedDirectDepsTable(probed, totalProbed, params.OutputFormat); tableErr != nil {
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

// blockedDirectDep captures the diagnostic info we recovered for a single
// direct package.json dependency rejected by the curation repo with 403.
// Multiple curation policies can violate the same package, so policies is a
// slice — each entry produces one row in the rendered table.
type blockedDirectDep struct {
	name            string
	declaredVersion string
	probedVersion   string
	reason          string // "blocked_policy" | "not_found" | "unknown_403"
	policies        []probedPolicy
}

// probedPolicy is one (policy, condition, explanation, recommendation)
// quartet extracted from a curation 403 response message. Mirrors curation's
// Policy type, but duplicated here to avoid an import cycle (the yarn package
// cannot import commands/curation because curation transitively imports yarn
// through the buildinfo dependency-tree builders).
type probedPolicy struct {
	policy         string
	condition      string
	explanation    string
	recommendation string
}

// blockedDepJSONRow mirrors commands/curation.PackageStatus JSON tags so that
// --format=json output from the V2 no-lockfile probe path uses the same schema
// as normal curation audit output. Duplicated here (not imported) to avoid the
// commands/curation ↔ yarn import cycle. Keep these tags in sync with
// PackageStatus when that struct changes.
type blockedDepJSONRow struct {
	Action         string                 `json:"action"`
	ParentName     string                 `json:"direct_dependency_package_name"`
	ParentVersion  string                 `json:"direct_dependency_package_version"`
	PackageName    string                 `json:"blocked_package_name"`
	PackageVersion string                 `json:"blocked_package_version"`
	BlockingReason string                 `json:"blocking_reason"`
	DepRelation    string                 `json:"dependency_relation"`
	PkgType        string                 `json:"type"`
	WaiverAllowed  bool                   `json:"waiver_allowed"`
	Policy         []blockedDepPolicyJSON `json:"policies,omitempty"`
}

// blockedDepPolicyJSON mirrors commands/curation.Policy JSON tags.
type blockedDepPolicyJSON struct {
	Policy         string `json:"policy"`
	Condition      string `json:"condition"`
	Explanation    string `json:"explanation"`
	Recommendation string `json:"recommendation"`
}

// probeBlockedDirectDeps walks the direct dependencies declared in package.json
// (deps + devDeps + optionalDeps + peerDeps) and probes each one's npm tarball
// URL against the curation-enabled Artifactory repository. Returns the deps
// that responded with HTTP 403, parsed for policy details when the body is a
// recognizable JFrog Curation error. All errors are logged at debug level and
// swallowed — this is a best-effort diagnostic invoked from an existing fatal
// error path; partial information is better than no information.
//
// probeBlockedDirectDeps HEAD-checks each declared direct dependency against
// the curation registry. workspaceMemberRel, when non-empty, scopes the probe
// to a single workspace member's package.json (used with --working-dirs).
func probeBlockedDirectDeps(params technologies.BuildInfoBomGeneratorParams, curWd, workspaceMemberRel string) ([]blockedDirectDep, int) {
	if params.ServerDetails == nil || params.DependenciesRepository == "" {
		return nil, 0
	}
	declared := collectDeclaredDirectDepsForMember(curWd, workspaceMemberRel)
	if len(declared) == 0 {
		return nil, 0
	}
	rtManager, err := rtUtils.CreateServiceManager(params.ServerDetails, 2, 0, false)
	if err != nil {
		log.Debug(fmt.Sprintf("yarn curation probe: failed to create Artifactory service manager: %s", err.Error()))
		return nil, 0
	}
	rtAuth, err := params.ServerDetails.CreateArtAuthConfig()
	if err != nil {
		log.Debug(fmt.Sprintf("yarn curation probe: failed to create Artifactory auth config: %s", err.Error()))
		return nil, 0
	}
	artiURL := strings.TrimSuffix(rtAuth.GetUrl(), "/")
	repo := params.DependenciesRepository

	names := slices.Sorted(maps.Keys(declared))

	httpDetails := rtAuth.CreateHttpClientDetails()
	if httpDetails.Headers == nil {
		httpDetails.Headers = map[string]string{}
	}
	// Mirror the curation walker: this header asks Artifactory to include the
	// curation policy details in the 403 response body so we can show them.
	httpDetails.Headers["X-Artifactory-Curation-Request-Waiver"] = "syn"

	parallelRequests := params.ParallelRequests
	if parallelRequests == 0 {
		parallelRequests = 3
	}
	var (
		mu          sync.Mutex
		blocked     []blockedDirectDep
		totalProbed int
	)
	errorsQueue := clientutils.NewErrorsQueue(1)
	runner := parallel.NewBounedRunner(parallelRequests, false)
	go func() {
		defer runner.Done()
		for _, name := range names {
			name := name
			probedVersion, ok := normalizeNpmVersion(declared[name])
			if !ok {
				continue
			}
			task := func(_ int) error {
				url := buildNpmTarballURL(artiURL, repo, name, probedVersion)
				headResp, _, headErr := rtManager.Client().SendHead(url, &httpDetails)
				if headResp == nil {
					if headErr != nil {
						log.Debug(fmt.Sprintf("yarn curation probe: HEAD %s failed without response: %s", url, headErr.Error()))
					}
					return nil
				}
				mu.Lock()
				totalProbed++
				mu.Unlock()
				if headResp.StatusCode != http.StatusForbidden {
					return nil
				}
				getResp, body, _, getErr := rtManager.Client().SendGet(url, true, &httpDetails)
				if getResp == nil || getResp.StatusCode != http.StatusForbidden {
					log.Debug(fmt.Sprintf("yarn curation probe: GET %s after HEAD 403 did not return 403: err=%v", url, getErr))
					return nil
				}
				dep := blockedDirectDep{
					name:            name,
					declaredVersion: declared[name],
					probedVersion:   probedVersion,
				}
				parseProbe403Body(body, &dep)
				if len(dep.policies) == 0 {
					log.Debug(fmt.Sprintf("yarn curation probe: could not extract policy details for %s:%s — reason=%q, raw 403 body=%s",
						name, probedVersion, dep.reason, string(body)))
				}
				mu.Lock()
				blocked = append(blocked, dep)
				mu.Unlock()
				return nil
			}
			if _, err := runner.AddTaskWithError(task, errorsQueue.AddError); err != nil {
				errorsQueue.AddError(err)
			}
		}
	}()
	runner.Run()
	if err := errorsQueue.GetError(); err != nil {
		log.Debug(fmt.Sprintf("yarn curation probe: parallel runner error: %s", err.Error()))
	}
	// Distinguish "probe ran and found no blockers" from "probe never reached
	// Artifactory" — both leave the table empty, so without this Warn a support
	// engineer reading default-level logs cannot tell the two apart.
	if len(declared) > 0 && totalProbed == 0 {
		log.Warn(fmt.Sprintf(
			"yarn curation probe: attempted to check %d direct dependencies but received no HTTP responses from Artifactory; the blocked-package table will be empty. Re-run with 'JFROG_CLI_LOG_LEVEL=DEBUG' to see the underlying HEAD failures.",
			len(declared)))
	}
	return blocked, totalProbed
}

// collectDeclaredDirectDeps returns direct deps from the root package.json only.
// Child workspace members are excluded; use --working-dirs to audit them.
func collectDeclaredDirectDeps(curWd string) map[string]string {
	declared := map[string]string{}
	if rootPI, err := bibuildutils.ReadPackageInfoFromPackageJsonIfExists(curWd, nil); err == nil && rootPI != nil {
		for n, v := range mergeDirectDeps(rootPI) {
			declared[n] = v
		}
	}
	return declared
}

// collectDeclaredDirectDepsForMember returns direct deps for the whole
// workspace (memberRel == "") or for a single member's package.json.
// Missing/empty member package.json returns an empty map — no fallback.
func collectDeclaredDirectDepsForMember(curWd, memberRel string) map[string]string {
	if memberRel == "" {
		return collectDeclaredDirectDeps(curWd)
	}
	memberDir := filepath.Join(curWd, filepath.FromSlash(memberRel))
	declared := map[string]string{}
	pi, err := bibuildutils.ReadPackageInfoFromPackageJsonIfExists(memberDir, nil)
	if err != nil || pi == nil {
		return declared
	}
	for n, v := range mergeDirectDeps(pi) {
		declared[n] = v
	}
	return declared
}

// expandYarnWorkspaceDirs reads the "workspaces" field from the root
// package.json and returns the absolute paths of every directory that
// matches at least one workspace pattern. Yarn V2+ accepts two shapes:
//
//	"workspaces": ["packages/*", "tools/*"]
//	"workspaces": {"packages": ["packages/*"]}
//
// Both are handled. Patterns are resolved relative to curWd via
// filepath.Glob. Returned entries are deduplicated; non-directory matches
// (a stray file matching a glob) are filtered out. Any I/O or parse error
// is downgraded to a debug log and the function returns whatever it has so
// far — this is invoked from error paths and must never itself fail the
// audit.
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
	if len(patterns) == 0 {
		return nil
	}
	// The "workspaces" patterns come from package.json (untrusted, stored input),
	// so a crafted manifest could use '../' segments to escape the project. Resolve
	// the root once and reject any match that lands outside it before touching the
	// filesystem, preventing stored path traversal.
	rootAbs, rootErr := filepath.Abs(curWd)
	if rootErr != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var dirs []string
	for _, pattern := range patterns {
		matches, globErr := filepath.Glob(filepath.Join(curWd, pattern))
		if globErr != nil {
			log.Debug(fmt.Sprintf("yarn curation probe: failed to expand workspace pattern '%s': %s", pattern, globErr.Error()))
			continue
		}
		for _, m := range matches {
			absMatch, absErr := filepath.Abs(m)
			if absErr != nil {
				continue
			}
			rel, relErr := filepath.Rel(rootAbs, absMatch)
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				log.Debug(fmt.Sprintf("yarn curation probe: ignoring workspace match outside project root: %s", m))
				continue
			}
			info, statErr := os.Stat(absMatch)
			if statErr != nil || !info.IsDir() {
				continue
			}
			if _, dup := seen[absMatch]; dup {
				continue
			}
			seen[absMatch] = struct{}{}
			dirs = append(dirs, absMatch)
		}
	}
	return dirs
}

// mergeDirectDeps flattens the four package.json dependency sections into one
// map. Sections later in the chain don't override earlier ones; duplicates are
// rare in practice and the first declared spec is usually authoritative.
func mergeDirectDeps(pi *bibuildutils.PackageInfo) map[string]string {
	out := map[string]string{}
	for n, v := range pi.Dependencies {
		out[n] = v
	}
	for n, v := range pi.DevDependencies {
		if _, exists := out[n]; !exists {
			out[n] = v
		}
	}
	for n, v := range pi.OptionalDependencies {
		if _, exists := out[n]; !exists {
			out[n] = v
		}
	}
	for n, v := range pi.PeerDependencies {
		if _, exists := out[n]; !exists {
			out[n] = v
		}
	}
	return out
}

// normalizeNpmVersion strips common semver-range operator prefixes from a
// package.json version specifier and returns a bare, fetchable version string.
// Returns ok=false for specifiers we cannot probe meaningfully (file:, link:,
// workspace:, git+/http(s)/npm: aliases, dist-tags like "latest", wildcard
// ranges like "1.x" / "*", and OR-ranges).
func normalizeNpmVersion(spec string) (string, bool) {
	v, probeable, _ := classifyNpmVersionSpec(spec)
	if !probeable {
		return "", false
	}
	return v, true
}

// classifyNpmVersionSpec inspects a package.json version specifier and tells
// the caller what kind of value it sees. It returns:
//
//   - probeable=true when the spec resolves to a single concrete semver after
//     stripping the standard range operators (^, ~, =, >, >=, <, <=). The
//     returned version is the bare semver and can be used to construct a
//     tarball URL; rangeOrTag is irrelevant.
//   - probeable=false, rangeOrTag=true when the spec is a semver range
//     (e.g. "1.x", "*", "1 || 2") or a dist-tag (e.g. "latest", "next") that
//     needs npm-side resolution we cannot perform. The reconciliation pass
//     uses this to emit a warning that names the dep and the recovery flow.
//   - probeable=false, rangeOrTag=false when the spec uses a non-registry
//     protocol (file:, link:, workspace:, patch:, portal:, git+, git:,
//     http(s):, npm:). These are out of scope for the curation HEAD-check
//     entirely and the reconciliation pass silently skips them.
//
// Kept separate from normalizeNpmVersion so the existing probe path
// (curationNoLockfileError) retains its quiet "silently skip everything
// we can't fetch" behaviour while the reconciliation pass can react
// differently to ranges vs. non-registry protocols.
func classifyNpmVersionSpec(spec string) (resolvedVer string, probeable, rangeOrTag bool) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return "", false, false
	}
	lc := strings.ToLower(s)
	for _, p := range []string{"file:", "link:", "workspace:", "patch:", "portal:", "git+", "git:", "http://", "https://", "npm:"} {
		if strings.HasPrefix(lc, p) {
			return "", false, false
		}
	}
	for len(s) > 0 {
		switch s[0] {
		case '^', '~', '=':
			s = s[1:]
			continue
		case '>', '<':
			s = s[1:]
			if len(s) > 0 && s[0] == '=' {
				s = s[1:]
			}
			continue
		}
		break
	}
	s = strings.TrimSpace(s)
	if npmConcreteVersionRegex.MatchString(s) {
		return s, true, false
	}
	return "", false, true
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
	resolvedNames := map[string]struct{}{}
	for _, dep := range dependenciesMap {
		if dep == nil {
			continue
		}
		name, nameErr := dep.Name()
		if nameErr != nil || name == "" {
			continue
		}
		resolvedNames[name] = struct{}{}
	}
	var synthesised, unresolvedRanges []string
	for name, spec := range declared {
		if _, present := resolvedNames[name]; present {
			continue
		}
		resolvedVer, probeable, isRangeOrTag := classifyNpmVersionSpec(spec)
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

// buildNpmTarballURL constructs the Artifactory npm tarball download URL for a
// given (name, version), handling scoped package names like @scope/name. This
// must match the format used by the curation walker in commands/curation so
// the 403 responses we parse here match those the walker would parse.
func buildNpmTarballURL(artiURL, repo, name, ver string) string {
	if scope, base := splitNpmScope(name); scope != "" {
		return fmt.Sprintf("%s/api/npm/%s/%s/%s/-/%s-%s.tgz", artiURL, repo, scope, base, base, ver)
	}
	return fmt.Sprintf("%s/api/npm/%s/%s/-/%s-%s.tgz", artiURL, repo, name, name, ver)
}

func splitNpmScope(name string) (scope, base string) {
	if !strings.HasPrefix(name, "@") {
		return "", name
	}
	idx := strings.Index(name, "/")
	if idx < 0 {
		return "", name
	}
	return name[:idx], name[idx+1:]
}

var probeCurationPolicyRegex = regexp.MustCompile(`\{[^{}]*\}`)

// npmConcreteVersionRegex matches a single concrete semver (no ranges, no
// wildcards, no dist-tags). MAJOR.MINOR.PATCH with optional prerelease and/or
// build-metadata suffix. Rejects "1.x", "1.0.x", "1.0", "latest", etc.
var npmConcreteVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-]+)*$`)

// parseProbe403Body fills `dep` with policy details extracted from a curation
// 403 response body. The body format is the same one parsed by curation's
// extractPoliciesFromMsg: a JSON envelope { errors: [{ status, message }] }
// where message is "Package %s:%s download was blocked by JFrog Packages
// Curation service due to the following policies violated {p,c,e,r},{...}.".
// Falls back gracefully when the body is not a recognizable curation message.
// All quartets are captured — a single package can violate multiple policies
// and we render one table row per (package, policy) pair to match the layout
// the curation walker produces on the V3 success path.
func parseProbe403Body(body []byte, dep *blockedDirectDep) {
	dep.reason = "unknown_403"
	if len(body) == 0 {
		return
	}
	var resp struct {
		Errors []struct {
			Status  int    `json:"status"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Errors) == 0 {
		return
	}
	msg := resp.Errors[0].Message
	lower := strings.ToLower(msg)
	if !strings.Contains(lower, "jfrog packages curation") {
		return
	}
	if strings.Contains(lower, "not being found") {
		dep.reason = "not_found"
		return
	}
	dep.reason = "blocked_policy"
	for _, match := range probeCurationPolicyRegex.FindAllString(msg, -1) {
		raw := strings.TrimSuffix(strings.TrimPrefix(match, "{"), "}")
		parts := strings.Split(raw, ",")
		if len(parts) < 2 {
			continue
		}
		p := probedPolicy{
			policy:    strings.TrimSpace(parts[0]),
			condition: strings.TrimSpace(parts[1]),
		}
		if len(parts) >= 4 {
			// curation's extractPoliciesFromMsg also normalises ": " → ":\n"
			// and " | " → "\n" in explanation/recommendation for readability;
			// mirror that here so the V2 table matches the V3 layout byte-for-byte.
			p.explanation = makeLegibleProbePolicyDetail(strings.TrimSpace(parts[2]))
			p.recommendation = makeLegibleProbePolicyDetail(strings.TrimSpace(parts[3]))
		}
		dep.policies = append(dep.policies, p)
	}
}

// makeLegibleProbePolicyDetail mirrors curation.makeLegiblePolicyDetails: the
// first ": " becomes ":\n" (so the header sits on its own line) and every
// " | " becomes a newline (so multi-CVE explanations stack). Duplicated here
// rather than imported to avoid the curation → yarn cycle.
func makeLegibleProbePolicyDetail(s string) string {
	return strings.ReplaceAll(strings.Replace(s, ": ", ":\n", 1), " | ", "\n")
}

// yarnV2BlockedDepTableRow mirrors commands/curation.PackageStatusTable so the
// V2 fallback renders the SAME tabular layout developers already see for V3 +
// other ecosystems' `jf ca` reports. The column tags drive coreutils.PrintTable
// (go-pretty under the hood); auto-merge collapses adjacent rows that share a
// column value, so multiple policy violations on one package render as one
// visually-merged package block.
type yarnV2BlockedDepTableRow struct {
	ID             string `col-name:"ID" auto-merge:"true"`
	ParentName     string `col-name:"Direct\nDependency\nPackage\nName" auto-merge:"true"`
	ParentVersion  string `col-name:"Direct\nDependency\nPackage\nVersion" auto-merge:"true"`
	PackageName    string `col-name:"Blocked\nPackage\nName" auto-merge:"true"`
	PackageVersion string `col-name:"Blocked\nPackage\nVersion" auto-merge:"true"`
	PkgType        string `col-name:"Package\nType" auto-merge:"true"`
	Policy         string `col-name:"Violated\nPolicy\nName"`
	Condition      string `col-name:"Violated Condition\nName"`
	Explanation    string `col-name:"Explanation"`
	Recommendation string `col-name:"Recommendation"`
}

// convertBlockedDepsToJSON converts the probe results to a slice of
// blockedDepJSONRow — the JSON schema that matches commands/curation.PackageStatus
// so that --format=json output from the V2 no-lockfile path is consistent with
// the normal curation audit JSON output.
func convertBlockedDepsToJSON(blocked []blockedDirectDep) []blockedDepJSONRow {
	rows := make([]blockedDepJSONRow, 0, len(blocked))
	for _, dep := range blocked {
		row := blockedDepJSONRow{
			Action:         "blocked",
			ParentName:     dep.name,
			ParentVersion:  dep.probedVersion,
			PackageName:    dep.name,
			PackageVersion: dep.probedVersion,
			DepRelation:    "direct",
			PkgType:        string(techutils.Yarn),
		}
		if len(dep.policies) == 0 {
			if dep.reason == "not_found" {
				row.BlockingReason = "Package not found in curation repository"
			} else {
				// mirrors curation.BlockingReasonUnknown — import cycle prevents direct use
				row.BlockingReason = "Blocked by curation (response could not be parsed)"
			}
		} else {
			row.BlockingReason = "Policy violations"
			for _, p := range dep.policies {
				row.Policy = append(row.Policy, blockedDepPolicyJSON{
					Policy:         p.policy,
					Condition:      p.condition,
					Explanation:    p.explanation,
					Recommendation: p.recommendation,
				})
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// buildBlockedDirectDepsTableRows turns the probe results into the row slice
// that coreutils.PrintTable renders. The "Direct Dependency" and "Blocked
// Package" columns are intentionally the same name/version because we only
// probe direct deps — in a V2 fallback report, the direct dep IS the blocked
// package. Keeping the column shape identical to the V3 success path means
// downstream tooling and visual muscle memory don't change.
//
// For deps with multiple violated policies, one row is emitted per policy and
// auto-merge stitches the package columns visually. The classic alternating-
// space trick (mirroring commands/curation.convertToPackageStatusTable) keeps
// adjacent packages from accidentally merging when they happen to share a
// column value.
func buildBlockedDirectDepsTableRows(blocked []blockedDirectDep) []yarnV2BlockedDepTableRow {
	if len(blocked) == 0 {
		return nil
	}
	rows := make([]yarnV2BlockedDepTableRow, 0, len(blocked))
	for index, dep := range blocked {
		uniqLineSep := ""
		if index%2 == 0 {
			uniqLineSep = " "
		}
		baseRow := yarnV2BlockedDepTableRow{
			ID:             fmt.Sprintf("%d%s", index+1, uniqLineSep),
			ParentName:     dep.name + uniqLineSep,
			ParentVersion:  dep.probedVersion + uniqLineSep,
			PackageName:    dep.name + uniqLineSep,
			PackageVersion: dep.probedVersion + uniqLineSep,
			PkgType:        string(techutils.Yarn) + uniqLineSep,
		}
		if len(dep.policies) == 0 {
			row := baseRow
			switch dep.reason {
			case "not_found":
				row.Explanation = "Package not found in curation repository"
			default:
				// mirrors curation.BlockingReasonUnknown — import cycle prevents direct use
				row.Explanation = "Blocked by curation (response could not be parsed)"
			}
			rows = append(rows, row)
			continue
		}
		for _, p := range dep.policies {
			row := baseRow
			row.Policy = p.policy
			row.Condition = p.condition
			row.Explanation = p.explanation
			row.Recommendation = p.recommendation
			rows = append(rows, row)
		}
	}
	return rows
}

// printBlockedDirectDepsTable renders the probe results as the same kind of
// table users see after a successful V3 `jf ca` run, then returns. Called for
// its side effect before the V2 install-error is surfaced; the error message
// referenced afterwards points the user back at this table.
//
// coreutils.PrintTable writes the table to STDOUT via a bufio writer and
// flushes on return; everything else in 'jf ca' — log.Output title, [Warn]
// from temp-dir cleanup, [Error] surfaced by the caller — writes to STDERR.
// Both streams land on the same TTY but there's no ordering guarantee
// between a freshly-flushed stdout buffer and a stderr line emitted in the
// same instant, so the table's bottom border can visually collide with the
// next stderr line if we don't leave a blank separator. The trailing
// fmt.Fprintln below writes a blank line to STDOUT (same stream as the
// table), guaranteeing a visible gap between the closing border and
// whatever the caller prints next.
func printBlockedDirectDepsTable(blocked []blockedDirectDep, totalProbed int, format outFormat.OutputFormat) error {
	if len(blocked) == 0 {
		return nil
	}
	if format == outFormat.Json {
		jsonRows := convertBlockedDepsToJSON(blocked)
		jsonBytes, err := json.MarshalIndent(jsonRows, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, string(jsonBytes))
		// Flush stdout so the complete JSON (including the closing ']') is
		// visible before the progress-spinner can tick and overwrite the last
		// line via a carriage-return escape sequence.
		_ = os.Stdout.Sync()
		return err
	}
	rows := buildBlockedDirectDepsTableRows(blocked)
	if len(rows) == 0 {
		return nil
	}
	log.Output(fmt.Sprintf("Probed %d direct dependencies; %d rejected by curation with HTTP 403", totalProbed, len(blocked)))
	err := coreutils.PrintTable(rows, "Curation", "Found 0 blocked packages", true)
	_, _ = fmt.Fprintln(os.Stdout)
	return err
}

// runYarnCommandQuiet runs yarn with stdout and stderr captured internally.
// On failure the captured output is emitted as a Debug log and appended to the
// returned error so the caller (handleCurationInstallError / curationNoLockfileError)
// can surface it to the user. On success the output is discarded so machine-readable
// JSON written to the process's own stdout stays unpolluted.
func runYarnCommandQuiet(executablePath, srcPath string, args ...string) error {
	command := exec.Command(executablePath, args...)
	command.Dir = srcPath
	var combined bytes.Buffer
	command.Stdout = &combined
	command.Stderr = &combined
	if err := command.Run(); err != nil {
		if msg := strings.TrimSpace(combined.String()); msg != "" {
			log.Debug("yarn install output:\n" + msg)
			return fmt.Errorf("%w\n%s", err, msg)
		}
		return err
	}
	return nil
}

// resolveCurationLockfileDir prepares the directory from which the curation
// audit reads yarn.lock. When install is needed it copies the project to a
// temp dir, configures the curation registry there, and runs
// 'yarn install --mode=update-lockfile' — so the customer's project is never
// modified and read-only CI checkouts still work.
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

	// Mark yarn.lock as fresh so the next run skips re-resolution.
	touchYarnLock(currentDir)

	return tmpDir, cleanup, deferredInstallErr, nil
}

// Sets up Artifactory server configurations for dependency resolution, if such were provided by the user.
// Executes the user's 'install' command or a default 'install' command if none was specified.
func configureYarnResolutionServerAndRunInstall(params technologies.BuildInfoBomGeneratorParams, curWd, yarnExecPath string) (err error) {
	depsRepo := params.DependenciesRepository
	if depsRepo == "" {
		// Run install without configuring an Artifactory server
		return runYarnInstallAccordingToVersion(curWd, yarnExecPath, params.InstallCommandArgs, params.IsCurationCmd)
	}

	executableYarnVersion, err := bibuildutils.GetVersion(yarnExecPath, curWd)
	if err != nil {
		return err
	}
	yarnVersion := version.NewVersion(executableYarnVersion)

	// Yarn V4 uses native mode: credentials are already stored in .yarnrc.yml (copied into curWd
	// by resolveCurationLockfileDir). For curation we rewrite the registry URL to the audit
	// endpoint and set a global npmAuthToken — no credential injection via ModifyYarnConfigurations.
	if yarnVersion.Compare(yarnV4Version) <= 0 {
		if params.IsCurationCmd {
			artiURL := strings.TrimSuffix(params.ServerDetails.ArtifactoryUrl, "/")
			registry := fmt.Sprintf("%s/api/npm/%s/", artiURL, depsRepo)
			curationRegistry := yarnCurationRegistry(registry)
			log.Debug(fmt.Sprintf("Yarn V4 native mode: rewriting npmRegistryServer to curation endpoint %s", curationRegistry))
			if err = setYarnConfigNpmRegistryServer(yarnExecPath, curWd, curationRegistry); err != nil {
				return err
			}
			// The original auth token in .yarnrc.yml is scoped to api/npm/<repo>/. After
			// rewriting the URL to api/curation/audit/<repo>/, Yarn can no longer match the
			// scoped token. Setting a global npmAuthToken ensures the curation endpoint is
			// authenticated with the same credential.
			if params.ServerDetails != nil && params.ServerDetails.AccessToken != "" {
				if setErr := runYarnConfigSet(yarnExecPath, curWd, "npmAuthToken", params.ServerDetails.AccessToken); setErr != nil {
					log.Warn(fmt.Sprintf("yarn V4: could not set global npmAuthToken for curation endpoint: %v", setErr))
				}
			}
		}
		return runYarnInstallAccordingToVersion(curWd, yarnExecPath, params.InstallCommandArgs, params.IsCurationCmd)
	}

	// V2/V3: inject Artifactory credentials via GetYarnAuthDetails + ModifyYarnConfigurations.
	// V1 is rejected earlier by verifyYarnVersionSupportedForCuration (curation) or is unsupported
	// by the jfrog-cli-artifactory yarn integration (non-curation).
	restoreYarnrcFunc, err := ioutils.BackupFile(filepath.Join(curWd, yarn.YarnrcFileName), yarn.YarnrcBackupFileName)
	if err != nil {
		return err
	}

	registry, repoAuthIdent, npmAuthToken, err := yarn.GetYarnAuthDetails(params.ServerDetails, depsRepo)
	if err != nil {
		return errors.Join(err, restoreYarnrcFunc())
	}

	// For curation, route installs through the api/curation/audit endpoint.
	if params.IsCurationCmd {
		registry = yarnCurationRegistry(registry)
	}
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

// isYarnLockStale reports whether package.json is newer than yarn.lock.
func isYarnLockStale(curWd string) bool {
	pkgJsonStat, err := os.Stat(filepath.Join(curWd, "package.json"))
	if err != nil {
		return false
	}
	lockStat, err := os.Stat(filepath.Join(curWd, yarn.YarnLockFileName))
	if err != nil {
		return false
	}
	return pkgJsonStat.ModTime().After(lockStat.ModTime())
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
	return registerYarnPluginInYarnrc(curWd, resolveLockfilePluginRelPath, resolveLockfilePluginSpec)
}

// registerYarnPluginInYarnrc adds a {path, spec} entry to the "plugins" list of
// curWd/.yarnrc.yml, creating the file if absent and preserving every other
// setting. If an entry with the same path already exists it is left untouched.
func registerYarnPluginInYarnrc(curWd, pluginRelPath, pluginSpec string) error {
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
			if path, _ := entry["path"].(string); path == pluginRelPath {
				return nil // already registered
			}
		}
	}
	plugins = append(plugins, map[string]interface{}{
		"path": pluginRelPath,
		"spec": pluginSpec,
	})
	rc["plugins"] = plugins

	updated, err := yaml.Marshal(rc)
	if err != nil {
		return fmt.Errorf("marshalling %s: %w", yarn.YarnrcFileName, err)
	}
	return os.WriteFile(yarnrcPath, updated, 0600)
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
	return graph, slices.Collect(maps.Keys(uniqDeps)), nil
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
	var attached []string
	for _, dep := range dependenciesMap {
		if dep == nil || dep == root {
			continue
		}
		// Only member workspaces; skip non-workspace packages and the root itself.
		if !strings.Contains(dep.Value, workspaceMarker) || strings.HasSuffix(dep.Value, rootWorkspaceSuffix) {
			continue
		}
		key := bibuildutils.GetYarnDependencyKeyFromLocator(dep.Value)
		if _, already := linked[key]; already {
			continue
		}
		root.Details.Dependencies = append(root.Details.Dependencies, bibuildutils.YarnDependencyPointer{Locator: dep.Value})
		linked[key] = struct{}{}
		attached = append(attached, dep.Value)
	}
	if len(attached) > 0 {
		slices.Sort(attached)
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

// yarnCurationRegistry rewrites a standard Artifactory npm registry URL to
// the curation audit endpoint, matching what Maven, Gradle, NuGet, and Python
// do for their own native tools.
//
//	https://<host>/artifactory/api/npm/<repo>
//	  → https://<host>/artifactory/api/curation/audit/<repo>
func yarnCurationRegistry(registry string) string {
	return strings.Replace(registry, "/api/npm/", "/api/curation/audit/", 1)
}

// GetNativeYarnV4RegistryConfig reads the Artifactory registry URL and auth
// token from the project's .yarnrc.yml via the Yarn CLI. Yarn V4 uses native
// mode — credentials are already stored in .yarnrc.yml, no jf yarn-config step
// is required. The URL must contain /api/npm/<repo>/ so that ParseArtifactoryNpmRegistryUrl
// can extract the Artifactory base URL and repository name.
func GetNativeYarnV4RegistryConfig(yarnExecPath, workingDir string) (*npm.NpmrcRegistryConfig, error) {
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

// runYarnConfigSet runs 'yarn config set <key> <value>' in workingDir.
func runYarnConfigSet(yarnExecPath, workingDir, key, value string) error {
	cmd := exec.Command(yarnExecPath, "config", "set", key, value)
	cmd.Dir = workingDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("yarn config set %s failed: %w\n%s", key, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setYarnConfigNpmRegistryServer runs 'yarn config set npmRegistryServer <url>'
// in workingDir. Used in V4 native curation mode to route installs through the
// curation audit endpoint without touching auth credentials.
func setYarnConfigNpmRegistryServer(yarnExecPath, workingDir, registryURL string) error {
	return runYarnConfigSet(yarnExecPath, workingDir, "npmRegistryServer", registryURL)
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
			log.Debug(fmt.Sprintf("yarn V4: could not parse %s: %s", path, err))
			continue
		}
		// Scoped registry entry takes priority.
		if entry, ok := rc.NpmRegistries[registryURL]; ok && entry.NpmAuthToken != "" {
			log.Debug(fmt.Sprintf("yarn V4: using auth token from scoped npmRegistries entry in %s", path))
			return entry.NpmAuthToken
		}
		// Fall back to top-level npmAuthToken in the same file.
		if rc.NpmAuthToken != "" {
			log.Debug(fmt.Sprintf("yarn V4: using top-level npmAuthToken from %s", path))
			return rc.NpmAuthToken
		}
	}
	return ""
}
