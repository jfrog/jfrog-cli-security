package curation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

// One reconstructed `silly placeDep` line:
//
//	<n> silly placeDep <Location> <Name>@<Version> OK for: <ParentName>@<ParentVersion> want: <Specifier>
//
// Version is blank when Arborist never resolved it — see classifyBlankVersionEntry.
type npmLogEntry struct {
	Location      string
	Name          string
	Version       string
	ParentName    string
	ParentVersion string
	Specifier     string
}

// npmEntryCategory classifies a blank-version npmLogEntry — see classifyBlankVersionEntry.
type npmEntryCategory int

const (
	// Concrete version in the log — standard per-package HEAD-check, same as the normal flow.
	npmEntryResolved npmEntryCategory = iota
	// Packument fetch itself 403'd (all versions blocked) — no HEAD-check needed or possible.
	npmEntryWholePackageBlocked
	// Non-registry specifier (git URL/shorthand, local file/link/workspace/patch, npm alias) — never probed.
	npmEntryNonRegistrySpecifier
	// Range/wildcard/dist-tag with no concrete version — never probed, since guessing one would be
	// misleading rather than just incomplete. Advisory only.
	npmEntryUnresolvableRange
	// Genuine "no matching version" for an already-bare, exact version — still probed to rule out a block.
	npmEntryETARGET
)

// npmBlockedInfo carries the policy/condition parsed from a whole-package-block notice line.
type npmBlockedInfo struct {
	Policy    string
	Condition string
}

var (
	// Matches: 42 notice All versions blocked - {policy:X,condition:Y}
	npmNoticeBlockedRegex = regexp.MustCompile(`^\d+\s+notice\s+All versions blocked - \{policy:([^,]+),condition:([^}]+)\}`)
	// Matches: 43 http fetch GET 403 https://.../api/npm/<repo>/<name> ... — excludes tarball fetches (path has /-/).
	npmFetch403Regex = regexp.MustCompile(`^\d+\s+http fetch GET 403\s+\S*/api/npm/[^/\s]+/((?:@[^/\s]+/)?[^/\s]+)\s`)
	// Matches: 110 silly placeDep ROOT accepts@2.0.0 OK for: express@5.2.1 want: ^2.0.0
	// want is `.+?` since OR-ranges ("1.0.0 || 2.0.0") and hyphen-ranges contain spaces.
	npmPlaceDepRegex = regexp.MustCompile(
		`^\d+\s+silly\s+placeDep\s+(\S+)\s+((?:@[^@\s]+/)?[^@\s]+)@(\S*)\s+OK for:\s+((?:@[^@\s]+/)?[^@\s]+)@(\S+)\s+want:\s+(.+?)\s*$`)
)

// parseNpmDebugLog reads every chunk of the newest npm run under logsDir newer than afterKey
// (see findNewestNpmDebugLogChunksAfter) as one continuous stream. Returns the chunk paths
// read too, so the caller can decide whether to remove them.
func parseNpmDebugLog(logsDir string, afterKey int64) (entries []npmLogEntry, blockedPackages map[string]npmBlockedInfo, logFilePaths []string, err error) {
	logFilePaths, err = findNewestNpmDebugLogChunksAfter(logsDir, afterKey)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(logFilePaths) == 0 {
		return nil, nil, nil, nil
	}

	blockedPackages = map[string]npmBlockedInfo{}
	// FIFO queue, not a single value: concurrent fetches can leave multiple notices pending at
	// once. Notices and their matching 403 lines come from separate emit paths (a
	// response-header handler vs. a request-completion logger), so same-relative-order isn't
	// provable under concurrency — see pendingNotice.ambiguous for how that's handled.
	var pendingNotices []pendingNotice
	for _, logFile := range logFilePaths {
		entries, pendingNotices, err = scanNpmDebugLogChunk(logFile, entries, blockedPackages, pendingNotices)
		if err != nil {
			return nil, nil, logFilePaths, err
		}
	}
	return entries, blockedPackages, logFilePaths, nil
}

// npmUnknownBlockedInfo replaces a guessed policy/condition when the notice→403 FIFO pairing
// is ambiguous — a wrong guess is worse than an honest "unknown".
var npmUnknownBlockedInfo = npmBlockedInfo{Policy: "unknown", Condition: "unknown"}

// pendingNotice is a queued "notice" awaiting its matching 403. ambiguous is set once it has
// ever overlapped with another unresolved notice, since FIFO order can no longer be trusted
// from that point on — it then degrades to npmUnknownBlockedInfo when matched.
type pendingNotice struct {
	info      npmBlockedInfo
	ambiguous bool
}

// scanNpmDebugLogChunk scans one chunk file; pendingNotices threads through since chunks of one run are a continuous stream.
func scanNpmDebugLogChunk(logFile string, entries []npmLogEntry, blockedPackages map[string]npmBlockedInfo, pendingNotices []pendingNotice) ([]npmLogEntry, []pendingNotice, error) {
	f, err := os.Open(logFile)
	if err != nil {
		return entries, pendingNotices, errorutils.CheckErrorf("failed to open npm debug log %q: %v", logFile, err)
	}
	defer func() {
		_ = f.Close()
	}()

	scanner := bufio.NewScanner(f)
	// Some policy-violation lines are long; grow past bufio's 64KB default to avoid truncation.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()

		if m := npmNoticeBlockedRegex.FindStringSubmatch(line); m != nil {
			next := pendingNotice{info: npmBlockedInfo{Policy: strings.TrimSpace(m[1]), Condition: strings.TrimSpace(m[2])}}
			if len(pendingNotices) > 0 {
				// A prior notice is still unresolved — both it and this one become ambiguous,
				// since same-relative-order with their eventual 403s is no longer provable.
				next.ambiguous = true
				for i := range pendingNotices {
					pendingNotices[i].ambiguous = true
				}
			}
			pendingNotices = append(pendingNotices, next)
			continue
		}
		if len(pendingNotices) > 0 {
			if m := npmFetch403Regex.FindStringSubmatch(line); m != nil {
				// npm-package-arg percent-encodes the scope separator in this URL (@scope/name
				// -> @scope%2fname), unlike placeDep's literal "/" form — decode so the two agree.
				name := m[1]
				if decoded, decodeErr := url.PathUnescape(name); decodeErr == nil {
					name = decoded
				}
				popped := pendingNotices[0]
				info := popped.info
				if popped.ambiguous {
					info = npmUnknownBlockedInfo
				}
				blockedPackages[name] = info
				pendingNotices = pendingNotices[1:]
			}
			// Fall through on a non-match too — this line may also be a placeDep line.
		}

		if m := npmPlaceDepRegex.FindStringSubmatch(line); m != nil {
			entries = append(entries, npmLogEntry{
				Location:      m[1],
				Name:          m[2],
				Version:       m[3],
				ParentName:    m[4],
				ParentVersion: m[5],
				Specifier:     m[6],
			})
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return entries, pendingNotices, errorutils.CheckErrorf("failed to scan npm debug log %q: %v", logFile, scanErr)
	}
	return entries, pendingNotices, nil
}

// npmDebugLogChunkRegex matches npm's debug-log filenames, e.g. "2026-01-01T00_00_00_000Z-debug-0.log".
// The trailing digit is the chunk index — npm splits one run past 50,000 log lines, same timestamp.
var npmDebugLogChunkRegex = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2}_\d{3}Z)-debug-(\d+)\.log$`)

// npmDebugLogFilenameTimeLayout is the captured group above with "_" restored to ":" and ".".
const npmDebugLogFilenameTimeLayout = "2006-01-02T15:04:05.000Z"

// npmDebugLogChunkInfo parses the embedded run timestamp (nanoseconds since epoch, for ranking
// runs) and the chunk index (for ordering multiple files of the same run) from a filename.
func npmDebugLogChunkInfo(name string) (timestamp int64, chunk int, ok bool) {
	m := npmDebugLogChunkRegex.FindStringSubmatch(name)
	if m == nil {
		return 0, 0, false
	}
	raw := m[1]
	standard := raw[:13] + ":" + raw[14:16] + ":" + raw[17:19] + "." + raw[20:]
	t, err := time.Parse(npmDebugLogFilenameTimeLayout, standard)
	if err != nil {
		return 0, 0, false
	}
	chunkNum, err := strconv.Atoi(m[2])
	if err != nil {
		return 0, 0, false
	}
	return t.UnixNano(), chunkNum, true
}

// newestNpmDebugLogGroup scans logsDir and returns the most recent run's timestamp key and its
// chunk file paths in ascending chunk order (0 key, nil paths if none exist). Groups by embedded
// timestamp (falls back to ModTime(), its own single-chunk group, since ModTime() alone can tie).
func newestNpmDebugLogGroup(logsDir string) (int64, []string, error) {
	dirEntries, err := os.ReadDir(logsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil, nil
		}
		return 0, nil, errorutils.CheckErrorf("failed to read npm debug log directory %q: %v", logsDir, err)
	}

	type chunkFile struct {
		name  string
		chunk int
	}
	groups := map[int64][]chunkFile{}
	var newestKey int64
	haveAny := false
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".log") {
			continue
		}
		key, chunk, ok := npmDebugLogChunkInfo(de.Name())
		if !ok {
			info, infoErr := de.Info()
			if infoErr != nil {
				continue
			}
			key = info.ModTime().UnixNano()
			chunk = 0
		}
		groups[key] = append(groups[key], chunkFile{name: de.Name(), chunk: chunk})
		if !haveAny || key > newestKey {
			newestKey = key
			haveAny = true
		}
	}
	if !haveAny {
		return 0, nil, nil
	}
	newestGroup := groups[newestKey]
	sort.Slice(newestGroup, func(i, j int) bool { return newestGroup[i].chunk < newestGroup[j].chunk })
	paths := make([]string, len(newestGroup))
	for i, c := range newestGroup {
		paths[i] = filepath.Join(logsDir, c.name)
	}
	return newestKey, paths, nil
}

// npmDebugLogNewestKey returns logsDir's current newest run's timestamp key (0 if none exist
// yet) — a pre-install baseline so the fallback can later tell a genuinely new log from a stale one.
func npmDebugLogNewestKey(logsDir string) (int64, error) {
	key, _, err := newestNpmDebugLogGroup(logsDir)
	return key, err
}

// findNewestNpmDebugLogChunksAfter returns the newest run's chunk files, in order — but only
// if newer than afterKey. Returns nil otherwise (nothing exists, or it predates afterKey).
func findNewestNpmDebugLogChunksAfter(logsDir string, afterKey int64) ([]string, error) {
	key, paths, err := newestNpmDebugLogGroup(logsDir)
	if err != nil || key <= afterKey {
		return nil, err
	}
	return paths, nil
}

// resolveNpmAliasTarget parses an "npm:<name>@<versionSpec>" alias specifier — how an npm
// alias ("pkg-cjs": "npm:pkg@6.0.1") is recorded in npm's debug log — into the real registry
// package name and the version/range it targets. ok=false for anything else, including a
// malformed alias (no '@' after stripping the prefix) — that's treated as genuinely
// unresolvable rather than guessed at.
func resolveNpmAliasTarget(spec string) (name, versionSpec string, ok bool) {
	const npmAliasPrefix = "npm:"
	trimmed := strings.TrimSpace(spec)
	if !strings.HasPrefix(strings.ToLower(trimmed), npmAliasPrefix) {
		return "", "", false
	}
	rest := trimmed[len(npmAliasPrefix):]
	// LastIndex, not Index: a scoped real name ("@babel/code-frame") contains its own '@', so
	// the version separator is always the final one.
	i := strings.LastIndex(rest, "@")
	if i <= 0 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// resolveNpmAliasEntries rewrites every entry whose Specifier is a resolvable npm alias
// ("pkg-cjs": "npm:pkg@6.0.1") to the real package it targets — Name becomes the real name and
// Specifier becomes the inner version/range — then propagates that rename to any other entry's
// ParentName that referenced the alias, so parent-child edges in the reconstructed tree still
// line up.
//
// npm's debug log always names a placeDep entry after the alias, never the real package.
// Artifactory's block notices and the registry both know it only by the real name, so every
// blockedPackages lookup, HEAD-check, and graph edge downstream must see the real name — done
// once here, at the point the wrong name would otherwise enter the system, so every consumer
// below (classification, the graph, the report) needs no alias-awareness of its own. See
// RTECO-1882 / XRAY-157605: the same class of bug this fixes on the non-fallback path.
func resolveNpmAliasEntries(entries []npmLogEntry) []npmLogEntry {
	aliasToReal := map[string]string{}
	for i, entry := range entries {
		if realName, realSpec, ok := resolveNpmAliasTarget(entry.Specifier); ok {
			aliasToReal[entry.Name] = realName
			entries[i].Name = realName
			entries[i].Specifier = realSpec
		}
	}
	if len(aliasToReal) == 0 {
		return entries
	}
	for i, entry := range entries {
		if realParent, ok := aliasToReal[entry.ParentName]; ok {
			entries[i].ParentName = realParent
		}
	}
	return entries
}

// classifyBlankVersionEntry categorizes an npmLogEntry whose Version is blank (non-blank is
// always npmEntryResolved). A range/wildcard/dist-tag is never treated as probeable even after
// stripping its operator (e.g. "^2.0.0" -> "2.0.0") — that stripped value is a guess at what npm
// might have installed, not the real answer, so it'd be misleading rather than just incomplete.
func classifyBlankVersionEntry(entry npmLogEntry, blockedPackages map[string]npmBlockedInfo) npmEntryCategory {
	if entry.Version != "" {
		return npmEntryResolved
	}
	if _, blocked := blockedPackages[entry.Name]; blocked {
		return npmEntryWholePackageBlocked
	}
	resolvedVer, probeable, rangeOrTag := classifyNpmSpecifier(entry.Specifier)
	switch {
	case !probeable && !rangeOrTag:
		return npmEntryNonRegistrySpecifier
	case !probeable && rangeOrTag:
		return npmEntryUnresolvableRange
	case entry.Specifier != resolvedVer:
		return npmEntryUnresolvableRange
	default:
		return npmEntryETARGET
	}
}

// effectiveGraphVersion falls back to entry.Specifier for ETARGET/non-registry rows, since those vary by specifier even with a blank Version.
func effectiveGraphVersion(entry npmLogEntry, blockedPackages map[string]npmBlockedInfo) string {
	if entry.Version != "" {
		return entry.Version
	}
	switch classifyBlankVersionEntry(entry, blockedPackages) {
	case npmEntryETARGET, npmEntryNonRegistrySpecifier:
		return entry.Specifier
	default:
		return entry.Version
	}
}

// npmConcreteVersionRegex matches a single concrete semver, optional pre-release/build metadata.
var npmConcreteVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-]+)*$`)

// classifyNpmSpecifier inspects a package.json version specifier: probeable=true means it
// resolves to a single concrete semver after stripping range operators; rangeOrTag=true means
// a range/wildcard/dist-tag; both false means a non-registry protocol (file:, link:, workspace:,
// patch:, portal:, git+, git:, http(s):, npm:) or git host shorthand (github:, gitlab:,
// bitbucket:, gist:).
//
// Deliberate self-contained copy of yarn.go's classifyNpmVersionSpec (PR #759/XRAY-138688) —
// kept scoped to npm only so this doesn't touch yarn's code. The two have since diverged
// (npm handles extra git-host prefixes yarn doesn't); unifying them is unrequested cleanup.
func classifyNpmSpecifier(spec string) (resolvedVer string, probeable, rangeOrTag bool) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return "", false, false
	}
	lc := strings.ToLower(s)
	for _, p := range []string{
		"file:", "link:", "workspace:", "patch:", "portal:", "git+", "git:", "http://", "https://", "npm:",
		"github:", "gitlab:", "bitbucket:", "gist:",
	} {
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

type npmProjectPackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// rootIdentityFromLogEntries recovers the true project name/version from a ROOT-location
// entry, for when package.json can't be read.
func rootIdentityFromLogEntries(entries []npmLogEntry) (name, version string, ok bool) {
	for _, e := range entries {
		if e.Location == "ROOT" {
			return e.ParentName, e.ParentVersion, true
		}
	}
	return "", "", false
}

func readNpmProjectNameVersion(projectDir string) (name, version string, err error) {
	data, err := os.ReadFile(filepath.Join(projectDir, "package.json"))
	if err != nil {
		return "", "", errorutils.CheckErrorf("failed to read package.json in %q: %v", projectDir, err)
	}
	var pkg npmProjectPackageJSON
	if err = json.Unmarshal(data, &pkg); err != nil {
		return "", "", errorutils.CheckErrorf("failed to parse package.json in %q: %v", projectDir, err)
	}
	return pkg.Name, pkg.Version, nil
}

// npmNodeId matches the "npm://name:version" format parseNpmDependenciesList uses in the
// normal flow, so the reconstructed tree is indistinguishable from a real one downstream.
func npmNodeId(name, version string) string {
	return techutils.Npm.GetXrayPackageTypeId() + name + ":" + version
}

// buildGraphFromLogEntries reconstructs a *xrayUtils.GraphNode tree from placeDep entries.
// Only immediate parent->child edges are recorded; resolving a deep node to its root-level
// direct-dependency ancestor is fillGraphRelations's job, reused unmodified.
func buildGraphFromLogEntries(entries []npmLogEntry, rootName, rootVersion string, blockedPackages map[string]npmBlockedInfo) *xrayUtils.GraphNode {
	treeMap := make(map[string]xray.DepTreeNode)
	for _, entry := range entries {
		childId := npmNodeId(entry.Name, effectiveGraphVersion(entry, blockedPackages))
		parentId := npmNodeId(entry.ParentName, entry.ParentVersion)
		depTreeNode := treeMap[parentId]
		depTreeNode.Children = appendUniqueChildId(depTreeNode.Children, childId)
		treeMap[parentId] = depTreeNode
	}
	rootId := npmNodeId(rootName, rootVersion)
	graph, _ := xray.BuildXrayDependencyTree(treeMap, rootId)
	return graph
}

// npmSyntheticNodeForKey wraps just the id needed to derive a preProcessMap key, so
// whole-package-blocked/non-registry entries (synthesized directly) land under the same key
// fillGraphRelations will later compute for the same package.
func npmSyntheticNodeForKey(name, version string) *xrayUtils.GraphNode {
	return &xrayUtils.GraphNode{Id: npmNodeId(name, version)}
}

func npmPackageKey(tech techutils.Technology, artiUrl, repo, name, version string) (string, error) {
	urls, _, _, _ := getUrlNameAndVersionByTech(tech, npmSyntheticNodeForKey(name, version), nil, artiUrl, repo)
	if len(urls) == 0 {
		return "", fmt.Errorf("could not derive a preProcessMap key for %s:%s", name, version)
	}
	return urls[0], nil
}

// appendUniqueChildId is a local copy of the npm tech package's own unexported appendUniqueChild.
func appendUniqueChildId(children []string, childId string) []string {
	for _, existing := range children {
		if existing == childId {
			return children
		}
	}
	return append(children, childId)
}

// sortedNpmLogEntries sorts by Name then Version for deterministic, reproducible output.
func sortedNpmLogEntries(entries []npmLogEntry) []npmLogEntry {
	sorted := make([]npmLogEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Version < sorted[j].Version
	})
	return sorted
}
