package curation

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	// TestDataDir is defined in curationaudit_test.go (same package).

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNpmDebugLog(t *testing.T) {
	entries, blockedPackages, logFilePaths, err := parseNpmDebugLog(filepath.Join(TestDataDir, "curation", "npmlogs", "mixed-crash", "_logs"), 0)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	require.Len(t, logFilePaths, 1)
	assert.Equal(t, "2026-01-01T00_00_00_000Z-debug-0.log", filepath.Base(logFilePaths[0]))

	// Whole-package block: notice immediately followed by the matching 403 fetch line.
	require.Contains(t, blockedPackages, "depd")
	assert.Equal(t, "blocks open ssf", blockedPackages["depd"].Policy)
	assert.Equal(t, "open ssf", blockedPackages["depd"].Condition)

	byName := map[string]npmLogEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}

	// Resolved.
	require.Contains(t, byName, "express")
	assert.Equal(t, "5.2.1", byName["express"].Version)
	assert.Equal(t, "mypnpmproject-v11", byName["express"].ParentName)

	// Whole-package-blocked placeDep line: blank version, real parent.
	require.Contains(t, byName, "depd")
	assert.Empty(t, byName["depd"].Version)
	assert.Equal(t, "express", byName["depd"].ParentName)

	// Git-URL: blank version, specifier contains "/".
	require.Contains(t, byName, "is-thirteen")
	assert.Empty(t, byName["is-thirteen"].Version)
	assert.Equal(t, "github:jonschlinkert/is-thirteen", byName["is-thirteen"].Specifier)

	// Genuine ETARGET: blank version, no notice, specifier has no "/".
	require.Contains(t, byName, "lodash")
	assert.Empty(t, byName["lodash"].Version)
	assert.Equal(t, "99.99.99", byName["lodash"].Specifier)
	assert.NotContains(t, blockedPackages, "lodash")

	// Unresolvable range: blank version, not blocked, not a bare version.
	require.Contains(t, byName, "some-range-pkg")
	assert.Empty(t, byName["some-range-pkg"].Version)
	assert.Equal(t, "^3.0.0", byName["some-range-pkg"].Specifier)
	assert.NotContains(t, blockedPackages, "some-range-pkg")
}

// An unrelated line between a notice and its matching 403 must not discard the notice.
func TestParseNpmDebugLog_NoticeSurvivesInterleavedLine(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "1 verbose cli npm\n" +
		"52 notice All versions blocked - {policy:blocks open ssf,condition:open ssf}\n" +
		"53 http fetch GET 200 https://z0test.jfrogdev.org/artifactory/api/npm/my-pnpm-remote/otherpkg 100ms (cache revalidated)\n" +
		"54 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-pnpm-remote/depd 196ms (cache skip)\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	_, blockedPackages, _, err := parseNpmDebugLog(logsDir, 0)
	require.NoError(t, err)
	assert.Contains(t, blockedPackages, "depd", "notice+403 pair separated only by an unrelated concurrent fetch line must still be attributed")
}

// A want: specifier containing a literal space (OR-ranges, hyphen-ranges) must still match.
func TestParseNpmDebugLog_WantSpecifierWithSpaceStillMatches(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "1 verbose cli npm\n" +
		"10 silly placeDep ROOT or-range-pkg@ OK for: myproj@1.0.0 want: 1.0.0 || 2.0.0\n" +
		"11 silly placeDep ROOT hyphen-range-pkg@ OK for: myproj@1.0.0 want: 1.0.0 - 2.0.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	entries, _, _, err := parseNpmDebugLog(logsDir, 0)
	require.NoError(t, err)
	byName := map[string]npmLogEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	require.Contains(t, byName, "or-range-pkg", "an OR-range want specifier must not silently drop the whole line")
	assert.Equal(t, "1.0.0 || 2.0.0", byName["or-range-pkg"].Specifier)
	require.Contains(t, byName, "hyphen-range-pkg", "a hyphen-range want specifier must not silently drop the whole line")
	assert.Equal(t, "1.0.0 - 2.0.0", byName["hyphen-range-pkg"].Specifier)
}

// A tarball-fetch 403 must not be mistaken for a packument-fetch 403 and desync the pendingNotices FIFO.
func TestParseNpmDebugLog_TarballFetch403DoesNotConsumePendingNotice(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "1 verbose cli npm\n" +
		"50 notice All versions blocked - {policy:blocks-cve,condition:cve}\n" +
		"51 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-pnpm-remote/otherpkg/-/otherpkg-1.0.0.tgz 100ms (cache skip)\n" +
		"52 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-pnpm-remote/depd 196ms (cache skip)\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	_, blockedPackages, _, err := parseNpmDebugLog(logsDir, 0)
	require.NoError(t, err)
	assert.Contains(t, blockedPackages, "depd", "the real packument 403 must still consume the pending notice")
	assert.NotContains(t, blockedPackages, "otherpkg", "a tarball-fetch 403 must never be mistaken for a packument block")
	assert.NotContains(t, blockedPackages, "otherpkg/-/otherpkg-1.0.0.tgz", "the tarball path must never be captured as a package name")
}

// npm-package-arg percent-encodes the scope separator in the packument-fetch URL (@babel/core
// -> @babel%2fcore) while placeDep lines use the literal "/" form. blockedPackages must be
// keyed on the decoded name so classifyBlankVersionEntry's entry.Name lookup actually matches,
// or a genuinely whole-package-blocked scoped package silently downgrades to an
// npmEntryUnresolvableRange advisory instead of npmEntryWholePackageBlocked.
func TestParseNpmDebugLog_ScopedPackageBlockedPercentEncodedSlashStillMatches(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "1 verbose cli npm\n" +
		"50 notice All versions blocked - {policy:blocks open ssf,condition:open ssf}\n" +
		"51 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-npm-remote/@babel%2fcore 100ms (cache skip)\n" +
		"10 silly placeDep ROOT @babel/core@ OK for: myproj@1.0.0 want: ^7.0.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	entries, blockedPackages, _, err := parseNpmDebugLog(logsDir, 0)
	require.NoError(t, err)
	require.Contains(t, blockedPackages, "@babel/core", "blockedPackages must be keyed on the decoded scoped name")

	var babelEntry npmLogEntry
	for _, e := range entries {
		if e.Name == "@babel/core" {
			babelEntry = e
		}
	}
	require.Equal(t, "@babel/core", babelEntry.Name)
	assert.Equal(t, npmEntryWholePackageBlocked, classifyBlankVersionEntry(babelEntry, blockedPackages),
		"a genuinely blocked scoped package must not downgrade to an unresolvable-range advisory")
}

// Two packages with notices pending at once must not have their policies misattributed.
// Both pkg-a and pkg-b overlap (two notices queue up before either 403 arrives), so FIFO order
// can't be trusted for either — both must degrade to "unknown" rather than risk a confidently
// wrong policy/condition, even though this particular log happens to be in the correct order.
func TestParseNpmDebugLog_OverlappingPendingNoticesDegradeToUnknownPolicy(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "1 verbose cli npm\n" +
		"50 notice All versions blocked - {policy:blocks-cve,condition:cve}\n" +
		"51 notice All versions blocked - {policy:blocks-license,condition:license}\n" +
		"52 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-pnpm-remote/pkg-a 100ms (cache skip)\n" +
		"53 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-pnpm-remote/pkg-b 100ms (cache skip)\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	_, blockedPackages, _, err := parseNpmDebugLog(logsDir, 0)
	require.NoError(t, err)
	require.Contains(t, blockedPackages, "pkg-a", "still reported as blocked — just with unknown policy, not dropped entirely")
	require.Contains(t, blockedPackages, "pkg-b")
	assert.Equal(t, "unknown", blockedPackages["pkg-a"].Policy)
	assert.Equal(t, "unknown", blockedPackages["pkg-b"].Policy)
}

// A single notice resolved before the next one ever queues is unambiguous — FIFO order is
// trivially correct here, so the real policy must still be reported, not degraded.
func TestParseNpmDebugLog_SequentialNonOverlappingNoticesKeepRealPolicy(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))
	logContent := "1 verbose cli npm\n" +
		"50 notice All versions blocked - {policy:blocks-cve,condition:cve}\n" +
		"51 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-pnpm-remote/pkg-a 100ms (cache skip)\n" +
		"52 notice All versions blocked - {policy:blocks-license,condition:license}\n" +
		"53 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-pnpm-remote/pkg-b 100ms (cache skip)\n"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(logContent), 0644))

	_, blockedPackages, _, err := parseNpmDebugLog(logsDir, 0)
	require.NoError(t, err)
	require.Contains(t, blockedPackages, "pkg-a")
	require.Contains(t, blockedPackages, "pkg-b")
	assert.Equal(t, "blocks-cve", blockedPackages["pkg-a"].Policy)
	assert.Equal(t, "blocks-license", blockedPackages["pkg-b"].Policy)
}

// npm splits one run's debug log into multiple numbered chunk files past 50,000 log lines,
// all sharing the same run timestamp. All chunks of the newest run must be read, in order, as
// one continuous stream — including pendingNotices state carrying across the chunk boundary.
func TestParseNpmDebugLog_MultipleChunksOfSameRunAreAllRead(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))

	// Chunk 0: ROOT placeDep entries plus a notice with no matching 403 yet (still pending).
	chunk0 := "0 verbose cli npm\n" +
		"1 silly placeDep ROOT accepts@2.0.0 OK for: myproj@1.0.0 want: ^2.0.0\n" +
		"2 notice All versions blocked - {policy:blocks open ssf,condition:open ssf}\n"
	// Chunk 1: the matching 403 for chunk 0's pending notice, plus another placeDep entry.
	chunk1 := "50000 http fetch GET 403 https://z0test.jfrogdev.org/artifactory/api/npm/my-npm-remote/depd 100ms (cache skip)\n" +
		"50001 silly placeDep node_modules/accepts depd@ OK for: accepts@2.0.0 want: ^1.0.0\n"

	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-0.log"), []byte(chunk0), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "2026-01-01T00_00_00_000Z-debug-1.log"), []byte(chunk1), 0644))

	entries, blockedPackages, logFilePaths, err := parseNpmDebugLog(logsDir, 0)
	require.NoError(t, err)
	require.Len(t, logFilePaths, 2, "both chunks of the run must be read")
	assert.Contains(t, logFilePaths[0], "debug-0.log")
	assert.Contains(t, logFilePaths[1], "debug-1.log")

	byName := map[string]npmLogEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	require.Contains(t, byName, "accepts", "chunk 0's placeDep entry must survive")
	require.Contains(t, byName, "depd", "chunk 1's placeDep entry must survive")

	require.Contains(t, blockedPackages, "depd",
		"the notice from chunk 0 must still pair with its matching 403 in chunk 1")
	assert.Equal(t, "blocks open ssf", blockedPackages["depd"].Policy)
}

func TestParseNpmDebugLog_NoLogsDir(t *testing.T) {
	entries, blockedPackages, logFilePaths, err := parseNpmDebugLog(t.TempDir(), 0)
	require.NoError(t, err)
	assert.Nil(t, entries)
	assert.Nil(t, blockedPackages)
	assert.Empty(t, logFilePaths)
}

// Git host shorthand (github:/gitlab:/bitbucket:/gist:) must not regress — real evidence
// (github:jonschlinkert/is-thirteen) depends on it.
func TestClassifyNpmSpecifier(t *testing.T) {
	cases := []struct {
		spec           string
		wantVer        string
		wantProbeable  bool
		wantRangeOrTag bool
	}{
		{"3.0.1", "3.0.1", true, false},
		{"^3.0.1", "3.0.1", true, false},
		{"~1.2.3", "1.2.3", true, false},
		{"1.2.3-beta.1", "1.2.3-beta.1", true, false},
		{"1.x", "", false, true},
		{"*", "", false, true},
		{"latest", "", false, true},
		{"1.0.0 || 2.0.0", "", false, true},
		{"file:./local-pkg", "", false, false},
		{"link:../sibling", "", false, false},
		{"workspace:*", "", false, false},
		{"patch:react@npm%3A18.0.0", "", false, false},
		{"git+https://github.com/foo/bar.git", "", false, false},
		{"https://example.com/pkg.tgz", "", false, false},
		{"npm:other-name@1.0.0", "", false, false},
		// The exact gap found in yarn's own classifyNpmVersionSpec via real testing —
		// git host shorthand, distinct from the explicit git:/git+ prefixes above.
		{"github:jonschlinkert/is-thirteen", "", false, false},
		{"gitlab:owner/repo", "", false, false},
		{"bitbucket:owner/repo", "", false, false},
		{"gist:1234567890abcdef", "", false, false},
		{"", "", false, false},
		{"   ", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			ver, probeable, rangeOrTag := classifyNpmSpecifier(tc.spec)
			assert.Equal(t, tc.wantVer, ver)
			assert.Equal(t, tc.wantProbeable, probeable)
			assert.Equal(t, tc.wantRangeOrTag, rangeOrTag)
		})
	}
}

func TestClassifyBlankVersionEntry(t *testing.T) {
	blockedPackages := map[string]npmBlockedInfo{"depd": {Policy: "blocks open ssf", Condition: "open ssf"}}

	assert.Equal(t, npmEntryResolved, classifyBlankVersionEntry(
		npmLogEntry{Name: "accepts", Version: "2.0.0"}, blockedPackages))

	assert.Equal(t, npmEntryWholePackageBlocked, classifyBlankVersionEntry(
		npmLogEntry{Name: "depd", Version: ""}, blockedPackages))

	// Genuine git URL — non-registry, no probe.
	assert.Equal(t, npmEntryNonRegistrySpecifier, classifyBlankVersionEntry(
		npmLogEntry{Name: "is-thirteen", Version: "", Specifier: "github:jonschlinkert/is-thirteen"}, blockedPackages))

	// Local workspace/file/link/patch reference and npm alias — also non-registry, no probe.
	for _, spec := range []string{"workspace:*", "file:../local-pkg", "link:../sibling", "npm:other-name@^1.0.0", "patch:react@npm%3A18.0.0"} {
		assert.Equal(t, npmEntryNonRegistrySpecifier, classifyBlankVersionEntry(
			npmLogEntry{Name: "some-pkg", Version: "", Specifier: spec}, blockedPackages), "specifier %q", spec)
	}

	// Genuinely bare, exact version — the only case that's safe to probe.
	assert.Equal(t, npmEntryETARGET, classifyBlankVersionEntry(
		npmLogEntry{Name: "lodash", Version: "", Specifier: "99.99.99"}, blockedPackages))

	// Never probed, even reduced to a bare number after stripping its operator — a guess, not what was requested.
	for _, spec := range []string{"^2.0.0", "~1.2.0", ">=1.0.0", "1.x", "*", "latest", "1.0.0 || 2.0.0"} {
		assert.Equal(t, npmEntryUnresolvableRange, classifyBlankVersionEntry(
			npmLogEntry{Name: "some-pkg", Version: "", Specifier: spec}, blockedPackages), "specifier %q", spec)
	}
}

func TestBuildGraphFromLogEntries(t *testing.T) {
	entries := []npmLogEntry{
		{Name: "express", Version: "5.2.1", ParentName: "myproj", ParentVersion: "1.0.0"},
		{Name: "accepts", Version: "2.0.0", ParentName: "express", ParentVersion: "5.2.1"},
		{Name: "depd", Version: "", ParentName: "express", ParentVersion: "5.2.1"},
	}
	graph := buildGraphFromLogEntries(entries, "myproj", "1.0.0", map[string]npmBlockedInfo{})
	require.NotNil(t, graph)
	assert.Equal(t, npmNodeId("myproj", "1.0.0"), graph.Id)
	require.Len(t, graph.Nodes, 1)
	assert.Equal(t, npmNodeId("express", "5.2.1"), graph.Nodes[0].Id)

	childIds := map[string]bool{}
	for _, child := range graph.Nodes[0].Nodes {
		childIds[child.Id] = true
	}
	assert.True(t, childIds[npmNodeId("accepts", "2.0.0")])
	assert.True(t, childIds[npmNodeId("depd", "")])
}

func TestNpmPackageKey_ConsistentWithGetUrlNameAndVersionByTech(t *testing.T) {
	// The key runNpmLogFallback stores under must be exactly what fillGraphRelations
	// derives when it later walks the reconstructed tree and looks the node up —
	// both must go through the same getUrlNameAndVersionByTech call.
	key, err := npmPackageKey(techutils.Npm, "https://example.jfrog.io/artifactory", "npm-remote", "depd", "")
	require.NoError(t, err)

	node := npmSyntheticNodeForKey("depd", "")
	urls, name, _, version := getUrlNameAndVersionByTech(techutils.Npm, node, nil, "https://example.jfrog.io/artifactory", "npm-remote")
	require.Len(t, urls, 1)
	assert.Equal(t, urls[0], key)
	assert.Equal(t, "depd", name)
	assert.Empty(t, version)
}

func TestReadNpmProjectNameVersion(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"myproj","version":"2.0.0"}`), 0644))

	name, version, err := readNpmProjectNameVersion(dir)
	require.NoError(t, err)
	assert.Equal(t, "myproj", name)
	assert.Equal(t, "2.0.0", version)
}

func TestFindNewestNpmDebugLog_PicksFilenameNewestOnModTimeTie(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "_logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))

	olderName := "2026-01-01T00_00_00_000Z-debug-0.log"
	newerName := "2026-01-01T00_00_01_000Z-debug-0.log"
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, olderName), []byte("older"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, newerName), []byte("newer"), 0644))

	// Force an exact ModTime tie so only the filename timestamp can disambiguate.
	tie := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(filepath.Join(logsDir, olderName), tie, tie))
	require.NoError(t, os.Chtimes(filepath.Join(logsDir, newerName), tie, tie))

	newest, err := findNewestNpmDebugLogChunksAfter(logsDir, 0)
	require.NoError(t, err)
	require.Len(t, newest, 1)
	assert.Equal(t, newerName, filepath.Base(newest[0]))
}
