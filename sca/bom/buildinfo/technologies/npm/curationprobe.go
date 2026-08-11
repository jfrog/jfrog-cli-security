package npm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	biutils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/gofrog/parallel"
	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	outFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// BlockedDirectDep is one direct dependency the curation repo rejected with 403; Policies holds every violated policy.
type BlockedDirectDep struct {
	Name            string
	DeclaredVersion string
	ProbedVersion   string
	Reason          string // "blocked_policy" | "not_found" | "unknown_403"
	Policies        []ProbedPolicy
}

// ProbedPolicy is a (policy, condition, explanation, recommendation) quartet parsed from a curation 403 body; duplicated from commands/curation to avoid an import cycle.
type ProbedPolicy struct {
	Policy         string
	Condition      string
	Explanation    string
	Recommendation string
}

// BlockedDepJSONRow mirrors commands/curation.PackageStatus's JSON tags (duplicated to avoid an import cycle) so --format=json matches normal audit output.
type BlockedDepJSONRow struct {
	Action         string                 `json:"action"`
	ParentName     string                 `json:"direct_dependency_package_name"`
	ParentVersion  string                 `json:"direct_dependency_package_version"`
	PackageName    string                 `json:"blocked_package_name"`
	PackageVersion string                 `json:"blocked_package_version"`
	BlockingReason string                 `json:"blocking_reason"`
	DepRelation    string                 `json:"dependency_relation"`
	PkgType        string                 `json:"type"`
	WaiverAllowed  bool                   `json:"waiver_allowed"`
	Policy         []BlockedDepPolicyJSON `json:"policies,omitempty"`
}

// BlockedDepPolicyJSON mirrors commands/curation.Policy JSON tags.
type BlockedDepPolicyJSON struct {
	Policy         string `json:"policy"`
	Condition      string `json:"condition"`
	Explanation    string `json:"explanation"`
	Recommendation string `json:"recommendation"`
}

// MergeDirectDeps flattens package.json's four dependency sections into one map; dependencies wins over devDeps/optionalDeps/peerDeps on name conflict.
func MergeDirectDeps(pi *biutils.PackageInfo) map[string]string {
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

// ExpandWorkspaceDirs expands already-decoded workspace glob patterns into matching directories, rejecting any match that escapes rootDir (patterns are untrusted, project-controlled input).
func ExpandWorkspaceDirs(rootDir string, patterns []string, logPrefix string) []string {
	if len(patterns) == 0 {
		return nil
	}
	rootAbs, rootErr := filepath.Abs(rootDir)
	if rootErr != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var dirs []string
	for _, pattern := range patterns {
		matches, globErr := filepath.Glob(filepath.Join(rootDir, pattern))
		if globErr != nil {
			log.Debug(fmt.Sprintf("%s curation probe: failed to expand workspace pattern '%s': %s", logPrefix, pattern, globErr.Error()))
			continue
		}
		for _, m := range matches {
			absMatch, absErr := filepath.Abs(m)
			if absErr != nil {
				continue
			}
			rel, relErr := filepath.Rel(rootAbs, absMatch)
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				log.Debug(fmt.Sprintf("%s curation probe: ignoring workspace match outside project root: %s", logPrefix, m))
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

// CollectDeclaredDirectDeps merges the root package.json's direct deps with every workspace member's, so a member-only dependency isn't invisible to the curation probe; on a name conflict, the last-processed member wins (root is applied first, so any member's spec overrides it).
func CollectDeclaredDirectDeps(curWd string, workspaceDirs []string) map[string]string {
	declared := map[string]string{}
	if rootPI, err := biutils.ReadPackageInfoFromPackageJsonIfExists(curWd, nil); err == nil && rootPI != nil {
		for n, v := range MergeDirectDeps(rootPI) {
			declared[n] = v
		}
	}
	for _, wsDir := range workspaceDirs {
		memberPI, err := biutils.ReadPackageInfoFromPackageJsonIfExists(wsDir, nil)
		if err != nil || memberPI == nil {
			continue
		}
		for n, v := range MergeDirectDeps(memberPI) {
			if existing, dup := declared[n]; dup && existing != v {
				log.Debug(fmt.Sprintf("curation: %s declared at both %s and %s across workspace members; using %s", n, existing, v, v))
			}
			declared[n] = v
		}
	}
	return declared
}

// normalizeNpmVersion strips range operators from a version specifier, returning ok=false for anything unprobeable (ranges, dist-tags, non-registry protocols).
func normalizeNpmVersion(spec string) (string, bool) {
	v, probeable, _ := ClassifyNpmVersionSpec(spec)
	if !probeable {
		return "", false
	}
	return v, true
}

// ClassifyNpmVersionSpec reports whether a version specifier is a probeable concrete semver, a range/dist-tag needing resolution, or a non-registry protocol.
func ClassifyNpmVersionSpec(spec string) (resolvedVer string, probeable, rangeOrTag bool) {
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

// npmConcreteVersionRegex matches a bare semver (no ranges, wildcards, or dist-tags).
var npmConcreteVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-]+)*$`)

// ParseProbe403Body extracts curation policy details from a 403 response body, falling back gracefully when it's not a recognizable curation message.
func ParseProbe403Body(body []byte, dep *BlockedDirectDep) {
	dep.Reason = "unknown_403"
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
		dep.Reason = "not_found"
		return
	}
	dep.Reason = "blocked_policy"
	for _, match := range probeCurationPolicyRegex.FindAllString(msg, -1) {
		raw := strings.TrimSuffix(strings.TrimPrefix(match, "{"), "}")
		parts := strings.Split(raw, ",")
		if len(parts) < 2 {
			continue
		}
		p := ProbedPolicy{
			Policy:    strings.TrimSpace(parts[0]),
			Condition: strings.TrimSpace(parts[1]),
		}
		if len(parts) >= 4 {
			// mirrors curation's ": "→":\n" / " | "→"\n" normalisation so this table matches the success-path layout.
			p.Explanation = makeLegibleProbePolicyDetail(strings.TrimSpace(parts[2]))
			p.Recommendation = makeLegibleProbePolicyDetail(strings.TrimSpace(parts[3]))
		}
		dep.Policies = append(dep.Policies, p)
	}
}

// makeLegibleProbePolicyDetail mirrors curation.makeLegiblePolicyDetails' formatting; duplicated to avoid an import cycle.
func makeLegibleProbePolicyDetail(s string) string {
	return strings.ReplaceAll(strings.Replace(s, ": ", ":\n", 1), " | ", "\n")
}

// ProbeBlockedDirectDeps HEAD/GET-probes each declared dependency's tarball URL directly — the shared fallback yarn and pnpm use when their lockfile-only resolve aborts before producing a lockfile.
func ProbeBlockedDirectDeps(params technologies.BuildInfoBomGeneratorParams, declared map[string]string, logPrefix string) ([]BlockedDirectDep, int) {
	if params.ServerDetails == nil || params.DependenciesRepository == "" || len(declared) == 0 {
		return nil, 0
	}
	rtManager, err := rtUtils.CreateServiceManager(params.ServerDetails, 2, 0, false)
	if err != nil {
		log.Debug(fmt.Sprintf("%s curation probe: failed to create Artifactory service manager: %s", logPrefix, err.Error()))
		return nil, 0
	}
	rtAuth, err := params.ServerDetails.CreateArtAuthConfig()
	if err != nil {
		log.Debug(fmt.Sprintf("%s curation probe: failed to create Artifactory auth config: %s", logPrefix, err.Error()))
		return nil, 0
	}
	artiURL := strings.TrimSuffix(rtAuth.GetUrl(), "/")
	repo := params.DependenciesRepository

	names := make([]string, 0, len(declared))
	for n := range declared {
		names = append(names, n)
	}
	sort.Strings(names)

	httpDetails := rtAuth.CreateHttpClientDetails()
	if httpDetails.Headers == nil {
		httpDetails.Headers = map[string]string{}
	}
	// asks Artifactory to include curation policy details in the 403 body, matching the curation walker.
	httpDetails.Headers["X-Artifactory-Curation-Request-Waiver"] = "syn"

	parallelRequests := params.ParallelRequests
	if parallelRequests == 0 {
		parallelRequests = 3
	}
	var (
		mu          sync.Mutex
		blocked     []BlockedDirectDep
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
						log.Debug(fmt.Sprintf("%s curation probe: HEAD %s failed without response: %s", logPrefix, url, headErr.Error()))
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
					log.Debug(fmt.Sprintf("%s curation probe: GET %s after HEAD 403 did not return 403: err=%v", logPrefix, url, getErr))
					return nil
				}
				dep := BlockedDirectDep{
					Name:            name,
					DeclaredVersion: declared[name],
					ProbedVersion:   probedVersion,
				}
				ParseProbe403Body(body, &dep)
				if len(dep.Policies) == 0 {
					log.Debug(fmt.Sprintf("%s curation probe: could not extract policy details for %s:%s — reason=%q, raw 403 body=%s",
						logPrefix, name, probedVersion, dep.Reason, string(body)))
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
		log.Debug(fmt.Sprintf("%s curation probe: parallel runner error: %s", logPrefix, err.Error()))
	}
	// distinguishes "probe ran, found nothing" from "probe never reached Artifactory" — both leave the table empty otherwise.
	if len(declared) > 0 && totalProbed == 0 {
		log.Warn(fmt.Sprintf(
			"%s curation probe: attempted to check %d direct dependencies but received no HTTP responses from Artifactory; the blocked-package table will be empty. Re-run with 'JFROG_CLI_LOG_LEVEL=DEBUG' to see the underlying HEAD failures.",
			logPrefix, len(declared)))
	}
	return blocked, totalProbed
}

// curationProbeTableRow mirrors commands/curation.PackageStatusTable's column layout so this fallback table matches the success-path table.
type curationProbeTableRow struct {
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

// convertBlockedDepsToJSON converts probe results to commands/curation.PackageStatus's JSON schema (duplicated to avoid an import cycle).
func convertBlockedDepsToJSON(blocked []BlockedDirectDep, pkgType techutils.Technology) []BlockedDepJSONRow {
	rows := make([]BlockedDepJSONRow, 0, len(blocked))
	for _, dep := range blocked {
		row := BlockedDepJSONRow{
			Action:         "blocked",
			ParentName:     dep.Name,
			ParentVersion:  dep.ProbedVersion,
			PackageName:    dep.Name,
			PackageVersion: dep.ProbedVersion,
			DepRelation:    "direct",
			PkgType:        string(pkgType),
		}
		if len(dep.Policies) == 0 {
			if dep.Reason == "not_found" {
				// mirrors curation.BlockingReasonNotFound — import cycle prevents direct use
				row.BlockingReason = "Package pending update"
			} else {
				// mirrors curation.BlockingReasonUnknown — import cycle prevents direct use
				row.BlockingReason = "Blocked by curation (response could not be parsed)"
			}
		} else {
			row.BlockingReason = "Policy violations"
			for _, p := range dep.Policies {
				row.Policy = append(row.Policy, BlockedDepPolicyJSON(p))
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// buildBlockedDirectDepsTableRows converts probe results into table rows, one per (package, policy) pair, alternating a trailing space so adjacent packages don't auto-merge.
func buildBlockedDirectDepsTableRows(blocked []BlockedDirectDep, pkgType techutils.Technology) []curationProbeTableRow {
	if len(blocked) == 0 {
		return nil
	}
	rows := make([]curationProbeTableRow, 0, len(blocked))
	for index, dep := range blocked {
		uniqLineSep := ""
		if index%2 == 0 {
			uniqLineSep = " "
		}
		baseRow := curationProbeTableRow{
			ID:             fmt.Sprintf("%d%s", index+1, uniqLineSep),
			ParentName:     dep.Name + uniqLineSep,
			ParentVersion:  dep.ProbedVersion + uniqLineSep,
			PackageName:    dep.Name + uniqLineSep,
			PackageVersion: dep.ProbedVersion + uniqLineSep,
			PkgType:        string(pkgType) + uniqLineSep,
		}
		if len(dep.Policies) == 0 {
			row := baseRow
			switch dep.Reason {
			case "not_found":
				// mirrors curation.BlockingReasonNotFound — import cycle prevents direct use
				row.Explanation = "Package pending update"
			default:
				// mirrors curation.BlockingReasonUnknown — import cycle prevents direct use
				row.Explanation = "Blocked by curation (response could not be parsed)"
			}
			rows = append(rows, row)
			continue
		}
		for _, p := range dep.Policies {
			row := baseRow
			row.Policy = p.Policy
			row.Condition = p.Condition
			row.Explanation = p.Explanation
			row.Recommendation = p.Recommendation
			rows = append(rows, row)
		}
	}
	return rows
}

// PrintBlockedDirectDepsTable renders probe results as the same table `jf ca` shows on a successful resolve.
func PrintBlockedDirectDepsTable(blocked []BlockedDirectDep, totalProbed int, format outFormat.OutputFormat, pkgType techutils.Technology) error {
	if len(blocked) == 0 {
		return nil
	}
	if format == outFormat.Json {
		jsonRows := convertBlockedDepsToJSON(blocked, pkgType)
		jsonBytes, err := json.MarshalIndent(jsonRows, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, string(jsonBytes))
		_ = os.Stdout.Sync() // flush before the progress-spinner can overwrite the last line via \r
		return err
	}
	rows := buildBlockedDirectDepsTableRows(blocked, pkgType)
	if len(rows) == 0 {
		return nil
	}
	log.Output(fmt.Sprintf("Probed %d direct dependencies; %d rejected by curation with HTTP 403", totalProbed, len(blocked)))
	err := coreutils.PrintTable(rows, "Curation", "Found 0 blocked packages", true)
	_, _ = fmt.Fprintln(os.Stdout) // blank separator: stdout table vs stderr log lines don't guarantee ordering on one TTY
	return err
}
