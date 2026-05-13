package yarn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	biutils "github.com/jfrog/build-info-go/utils"

	"golang.org/x/exp/maps"

	"github.com/jfrog/build-info-go/build"
	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/gofrog/version"
	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
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

	installRequired, err := isInstallRequired(currentDir, params.InstallCommandArgs, params.SkipAutoInstall)
	if err != nil {
		return
	}

	if installRequired {
		installErr := configureYarnResolutionServerAndRunInstall(params, currentDir, executablePath)
		if installErr != nil {
			// 'yarn install' against a curation-enabled registry will commonly exit
			// non-zero on the first blocked tarball (HTTP 403). Yarn V2/V3 still
			// writes yarn.lock during the resolution phase (which only needs package
			// manifests, not tarballs), so when the lockfile is on disk we hand it
			// to the curation HEAD-check walker — that walker reports every blocked
			// package, not just the first one yarn happened to fetch. If no lockfile
			// was produced, curation is likely blocking manifests too and we surface
			// a clear actionable error.
			if err = handleCurationInstallError(params, currentDir, executablePath, installErr); err != nil {
				return
			}
		}
	}

	// Curation diagnostic: log how many resolved package entries are in
	// yarn.lock so debug logs make it obvious whether the lockfile reaching
	// the HEAD-check walker is complete (matches the project's full transitive
	// set) or partial (some manifests were 403'd by curation and silently
	// skipped during '--mode=update-lockfile' resolve). Same count across V2
	// and V3 runs means the walker sees the same input regardless of which
	// yarn binary produced/normalised the lockfile.
	if params.IsCurationCmd {
		logYarnLockEntryCount(filepath.Join(currentDir, yarn.YarnLockFileName))
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

// logYarnExecutableVersion emits a single INFO line with the version of the
// yarn binary that will drive the audit. Sits next to the existing
// "Detected: yarn." line so the audit log carries enough context to correlate
// behaviour to a specific yarn release without re-running 'yarn --version'
// after the fact. If the version probe itself fails the audit must still
// proceed (a downstream call will surface the real error with full context),
// so failures are degraded to a DEBUG line and otherwise swallowed.
func logYarnExecutableVersion(yarnExecPath, curWd string) {
	versionStr, err := bibuildutils.GetVersion(yarnExecPath, curWd)
	if err != nil {
		log.Debug(fmt.Sprintf("could not determine yarn version from '%s': %s", yarnExecPath, err.Error()))
		return
	}
	log.Info(fmt.Sprintf("Yarn version: %s", strings.TrimSpace(versionStr)))
}

// logYarnLockEntryCount emits a single DEBUG line with the number of resolved
// package entries in yarn.lock — i.e. how many tarball HEAD requests the
// curation walker is about to issue. Used only for diagnostics on the
// 'jf curation-audit' path; cheap (one file read, one byte count) and safe to
// run unconditionally. Any read error is reported at DEBUG and otherwise
// swallowed so this helper never affects the audit's exit code.
//
// Counts Yarn V2/V3/V4 berry-format entries, which all share the
// "\n  resolution: " field per entry. Yarn V1 lockfiles use a different
// layout, but curation is only supported for V2/V3 so V1 never reaches here.
func logYarnLockEntryCount(yarnLockPath string) {
	data, err := os.ReadFile(yarnLockPath)
	if err != nil {
		log.Debug(fmt.Sprintf("yarn curation: could not read '%s' for entry-count diagnostic: %s", yarnLockPath, err.Error()))
		return
	}
	count := bytes.Count(data, []byte("\n  resolution: "))
	log.Debug(fmt.Sprintf("yarn curation: '%s' contains %d resolved package entries; the curation walker will HEAD-check this set", yarnLockPath, count))
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

// handleCurationInstallError translates a failed 'yarn install' into the right
// outcome for the calling command. For 'jf audit' any install error is fatal
// (matching pre-existing behaviour). For 'jf curation-audit' the install can
// exit non-zero because curation 403s the tarball downloads of blocked
// packages — that's expected. On V3+ we run install with --mode=update-lockfile
// which skips fetch entirely, so yarn.lock is produced regardless of which
// packages curation blocks. On V2 there is no lockfile-only install mode, so
// any blocked tarball aborts install before yarn.lock is written; we surface a
// V2-specific error pointing at either upgrading to V3 or pre-generating
// yarn.lock against a non-curation registry.
func handleCurationInstallError(params technologies.BuildInfoBomGeneratorParams, curWd, yarnExecPath string, installErr error) error {
	if !params.IsCurationCmd {
		return fmt.Errorf("failed to configure an Artifactory resolution server or running and install command: %s", installErr.Error())
	}
	yarnLockPath := filepath.Join(curWd, yarn.YarnLockFileName)
	lockExists, statErr := fileutils.IsFileExists(yarnLockPath, false)
	if statErr != nil {
		return errors.Join(installErr, fmt.Errorf("failed to check the existence of '%s' after install: %s", yarnLockPath, statErr.Error()))
	}
	if !lockExists {
		return curationNoLockfileError(params, curWd, yarnExecPath, installErr)
	}
	log.Warn(fmt.Sprintf("'yarn install' against curation repo '%s' exited with: %s", params.DependenciesRepository, installErr.Error()))
	log.Warn(fmt.Sprintf("'%s' was produced regardless; continuing with curation analysis. Blocked packages will appear in the report.", yarn.YarnLockFileName))
	return nil
}

// curationNoLockfileError builds a version-specific actionable error for the
// case where 'yarn install' did not produce yarn.lock. V2 has no lockfile-only
// install mode, so the recommended path is to upgrade to V3+ for in-place
// curation, or pre-generate yarn.lock against a non-curation registry.
//
// For V2 we additionally probe the curation-enabled repository for each direct
// dependency declared in package.json, so the user sees which packages were
// rejected with HTTP 403 and almost certainly caused 'yarn install' to abort —
// yarn V2 itself surfaces only "HTTPError: Response code 403 (Forbidden)" with
// no package context. The probe is best-effort: it covers direct deps only
// (transitive blockers are not enumerated) and uses each declared semver-range
// lower bound, so it may miss blocks that only apply to specific resolved
// versions. Users wanting the complete report should switch to Yarn V3.
func curationNoLockfileError(params technologies.BuildInfoBomGeneratorParams, curWd, yarnExecPath string, installErr error) error {
	yarnVersionStr, versionErr := bibuildutils.GetVersion(yarnExecPath, curWd)
	if versionErr == nil {
		yarnVersion := version.NewVersion(yarnVersionStr)
		isV2 := yarnVersion.Compare(yarnV2Version) <= 0 && yarnVersion.Compare(yarnV3Version) > 0
		if isV2 {
			probed := probeBlockedDirectDeps(params, curWd)
			tableNote := ""
			if len(probed) > 0 {
				if tableErr := printBlockedDirectDepsTable(probed); tableErr != nil {
					log.Debug(fmt.Sprintf("yarn curation probe: failed to render blocked deps table: %s", tableErr.Error()))
				} else {
					tableNote = " The direct dependencies that the curation repo rejected with HTTP 403 are listed in the table above (best-effort probe; transitive blockers are not enumerated)."
				}
			}
			return errorutils.CheckErrorf("'jf curation-audit' could not produce a '%s' through the curation-enabled repository ('%s') with Yarn %s. Yarn V2 has no lockfile-only install mode, so any package blocked by curation aborts the install before '%s' is written.%s Either upgrade the project to Yarn V3 (e.g. 'yarn set version 3.6.4') so curation can resolve the lockfile via '--mode=update-lockfile', or run 'yarn install' against a non-curation registry to pre-generate '%s' and re-run 'jf ca'. Underlying yarn error: %s", yarn.YarnLockFileName, params.DependenciesRepository, yarnVersionStr, yarn.YarnLockFileName, tableNote, yarn.YarnLockFileName, installErr.Error())
		}
	}
	return errorutils.CheckErrorf("'jf curation-audit' could not produce a '%s' through the curation-enabled repository ('%s'). 'yarn install' failed before the lockfile was written, which usually indicates that curation is blocking the package manifests, not just the tarballs. Please run 'yarn install' against a non-curation registry to produce '%s', then re-run 'jf ca'. Underlying yarn error: %s", yarn.YarnLockFileName, params.DependenciesRepository, yarn.YarnLockFileName, installErr.Error())
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

// probeBlockedDirectDeps walks the direct dependencies declared in package.json
// (deps + devDeps + optionalDeps + peerDeps) and probes each one's npm tarball
// URL against the curation-enabled Artifactory repository. Returns the deps
// that responded with HTTP 403, parsed for policy details when the body is a
// recognizable JFrog Curation error. All errors are logged at debug level and
// swallowed — this is a best-effort diagnostic invoked from an existing fatal
// error path; partial information is better than no information.
func probeBlockedDirectDeps(params technologies.BuildInfoBomGeneratorParams, curWd string) []blockedDirectDep {
	if params.ServerDetails == nil || params.DependenciesRepository == "" {
		return nil
	}
	packageInfo, err := bibuildutils.ReadPackageInfoFromPackageJsonIfExists(curWd, nil)
	if err != nil || packageInfo == nil {
		return nil
	}
	declared := mergeDirectDeps(packageInfo)
	if len(declared) == 0 {
		return nil
	}
	rtManager, err := rtUtils.CreateServiceManager(params.ServerDetails, 2, 0, false)
	if err != nil {
		log.Debug(fmt.Sprintf("yarn curation probe: failed to create Artifactory service manager: %s", err.Error()))
		return nil
	}
	rtAuth, err := params.ServerDetails.CreateArtAuthConfig()
	if err != nil {
		log.Debug(fmt.Sprintf("yarn curation probe: failed to create Artifactory auth config: %s", err.Error()))
		return nil
	}
	artiURL := strings.TrimSuffix(rtAuth.GetUrl(), "/")
	repo := params.DependenciesRepository

	names := maps.Keys(declared)
	sort.Strings(names)

	httpDetails := rtAuth.CreateHttpClientDetails()
	if httpDetails.Headers == nil {
		httpDetails.Headers = map[string]string{}
	}
	// Mirror the curation walker: this header asks Artifactory to include the
	// curation policy details in the 403 response body so we can show them.
	httpDetails.Headers["X-Artifactory-Curation-Request-Waiver"] = "syn"

	var blocked []blockedDirectDep
	for _, name := range names {
		probedVersion, ok := normalizeNpmVersion(declared[name])
		if !ok {
			continue
		}
		url := buildNpmTarballURL(artiURL, repo, name, probedVersion)
		resp, body, _, getErr := rtManager.Client().SendGet(url, true, &httpDetails)
		if resp == nil {
			if getErr != nil {
				log.Debug(fmt.Sprintf("yarn curation probe: GET %s failed without response: %s", url, getErr.Error()))
			}
			continue
		}
		if resp.StatusCode != http.StatusForbidden {
			continue
		}
		dep := blockedDirectDep{
			name:            name,
			declaredVersion: declared[name],
			probedVersion:   probedVersion,
		}
		parseProbe403Body(body, &dep)
		blocked = append(blocked, dep)
	}
	return blocked
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
	s := strings.TrimSpace(spec)
	if s == "" {
		return "", false
	}
	lc := strings.ToLower(s)
	for _, p := range []string{"file:", "link:", "workspace:", "patch:", "portal:", "git+", "git:", "http://", "https://", "npm:"} {
		if strings.HasPrefix(lc, p) {
			return "", false
		}
	}
	// Strip leading semver operators: ^ ~ = > >= < <=
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
	if !npmConcreteVersionRegex.MatchString(s) {
		return "", false
	}
	return s, true
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

// buildBlockedDirectDepsTableRows turns the probe results into the row slice
// that coreutils.PrintTable renders. The "Direct Dependency" and "Blocked
// Package" columns are intentionally populated with the same name/version
// because we only probe direct deps from package.json — for a V2-fallback
// report, the direct dep IS the blocked package. Keeping the column shape
// identical to the V3 success path means downstream tooling and visual muscle
// memory don't change.
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
func printBlockedDirectDepsTable(blocked []blockedDirectDep) error {
	rows := buildBlockedDirectDepsTableRows(blocked)
	if len(rows) == 0 {
		return nil
	}
	log.Output(fmt.Sprintf("Probed %d direct dependencies; %d rejected by curation with HTTP 403", len(blocked), len(blocked)))
	return coreutils.PrintTable(rows, "Curation", "Found 0 blocked packages", true)
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
	return runYarnInstallAccordingToVersion(curWd, yarnExecPath, params.InstallCommandArgs, params.IsCurationCmd)
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
func runYarnInstallAccordingToVersion(curWd, yarnExecPath string, installCommandArgs []string, isCurationCmd bool) (err error) {
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
			// V2 — has no equivalent to V3's --mode=update-lockfile, so install
			// always fetches tarballs. For curation this means any blocked package
			// returns 403 during fetch and yarn aborts before yarn.lock is written;
			// handleCurationInstallError then surfaces an actionable error.
			installCommandArgs = append(installCommandArgs, v2SkipBuildFlag)
		} else {
			// V3+
			if isCurationCmd {
				// --mode=update-lockfile skips fetch and link entirely — yarn just
				// resolves manifests and writes yarn.lock. The curation HEAD-check
				// walker enumerates blocked packages from the lockfile afterwards,
				// so we don't need yarn to download tarballs (which curation would
				// 403 anyway).
				// Note: yarn berry's clipanion takes the LAST --mode value, so
				// passing both --mode=update-lockfile and --mode=skip-build would
				// silently reduce to --mode=skip-build (a full install). For
				// curation we MUST pass only --mode=update-lockfile.
				installCommandArgs = append(installCommandArgs, v3UpdateLockfileFlag)
			} else {
				installCommandArgs = append(installCommandArgs, v3UpdateLockfileFlag, v3SkipBuildFlag)
			}
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
