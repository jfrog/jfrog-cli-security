package githubactions

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixturesRoot = "../../../tests/testdata/projects/githubactions"

// How the runner lays out _actions, which is what the cases below are built to mirror. Taken from
// actions/runner, src/Runner.Worker/ActionManager.cs:
//
//   - The destination for every resolved action is <_actions>/<owner>/<repo>/<ref> (:1193). The ref
//     is joined verbatim, so one containing "/" - a branch such as copilot/backport-v4 - nests a
//     level deeper than a tag does.
//   - On a cache miss the archive is extracted there and <ref>.completed is written beside it
//     (:1378, named at :1402).
//   - With ACTIONS_RUNNER_SYMLINK_CACHED_ACTIONS set and a hit in ACTIONS_RUNNER_ACTION_ARCHIVE_CACHE,
//     that same path is instead made a symlink to the already-unpacked copy (:1259) - the single
//     nested folder inside <ARCHIVE_CACHE>/<owner>_<repo>/<sha>, since a GitHub repository archive
//     always unpacks to exactly one. This branch returns before writing a watermark, which is why
//     the link itself has to mark where the ref ends.
//
// The link therefore lands on the ref directory and never on the owner or repo directory above it:
// ActionManager.cs:1259 is the only place the runner creates a symlink under _actions. So no case
// here links at those higher levels to stand for an action - that would describe a cache nothing
// produces. The higher-level links below are all dangling, used only to fabricate an entry that
// exists but cannot be classified, which a broken mount or a pruned target produces just as well.
// --actions-cache-dir does not widen any of this: it is a local-testing override pointing at a
// directory shaped the same way.
const archiveCacheSHA = "e1b2c3d4e5f60718293a4b5c6d7e8f9012345678"

// symlinkOrSkip links newname -> oldname, skipping the test where the OS won't allow it
// (Windows needs privileges for symlink creation).
func symlinkOrSkip(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("cannot create symlinks on this platform: %v", err)
	}
}

// captureWarnings redirects the package logger into a buffer for the rest of one test.
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	original := log.Logger
	log.SetLogger(log.NewLogger(log.WARN, buf))
	t.Cleanup(func() { log.SetLogger(original) })
	return buf
}

// actionCache is the cache a discovery case starts from, expressed as data. Either a checked-in
// fixture, or a tree built under a temp base - where the cache root is <base>/_actions and every
// other path is relative to <base>, so a symlink target can sit outside the cache the way the
// runner's archive cache does.
type actionCache struct {
	fixture  string            // a project under fixturesRoot; its _work/_actions is the cache
	dirs     []string          // directories to create, relative to <base>
	files    map[string]string // files to write, relative to <base>
	symlinks map[string]string // link path -> target path, both relative to <base>
	// unreadable lists directories to strip of every permission, relative to <base>, so that
	// listing them fails the way a runner filesystem error would.
	unreadable []string
}

func (c actionCache) build(t *testing.T) (cacheRoot string) {
	t.Helper()
	if c.fixture != "" {
		return filepath.Join(fixturesRoot, c.fixture, "_work", "_actions")
	}
	base := t.TempDir()
	for _, dir := range c.dirs {
		require.NoError(t, os.MkdirAll(filepath.Join(base, filepath.FromSlash(dir)), 0755))
	}
	for name, content := range c.files {
		require.NoError(t, os.WriteFile(filepath.Join(base, filepath.FromSlash(name)), []byte(content), 0600))
	}
	for link, target := range c.symlinks {
		symlinkOrSkip(t, filepath.Join(base, filepath.FromSlash(target)), filepath.Join(base, filepath.FromSlash(link)))
	}
	for _, dir := range c.unreadable {
		makeUnreadableOrSkip(t, filepath.Join(base, filepath.FromSlash(dir)))
	}
	return filepath.Join(base, "_actions")
}

// makeUnreadableOrSkip strips every permission from dir, skipping the test where that still
// leaves it listable - running as root, or on a platform that ignores the mode.
func makeUnreadableOrSkip(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.Chmod(dir, 0o000))
	// Registered after t.TempDir's own cleanup, so it runs first and leaves the tree removable.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := os.ReadDir(dir); err == nil {
		t.Skipf("cannot make %q unreadable on this platform", dir)
	}
}

func TestDiscoverActionCache(t *testing.T) {
	tests := []struct {
		name        string
		cache       actionCache
		wantEntries []string
		// wantUnaccounted lists every entry the walk must refuse to skip, as a path relative to
		// the cache root. A non-empty list means the command fails rather than reporting.
		wantUnaccounted []string
		// wantWarn is a substring the run must warn about; "" asserts nothing.
		wantWarn string
		// wantErr marks a cache the walk cannot begin on at all, as distinct from one it walks
		// and cannot fully resolve.
		wantErr bool
	}{
		{
			name:        "verify when the cache is well-formed then one entry per owner repo ref is returned",
			cache:       actionCache{fixture: "curation-project"},
			wantEntries: []string{"actions/checkout@v4", "github/codeql-action@v3", "some-org/transitive-action@v1"},
		},
		{
			name:  "verify when the cache directory does not exist then the result is empty and no error",
			cache: actionCache{fixture: "does-not-exist"},
		},
		{
			// stray-file.txt (owner level), actions/stray-file-at-repo-level.txt (repo level) and
			// onlyowner/ (an owner dir with no repo subdirectories).
			name:        "verify when an entry is not a well-formed triple then it is skipped without error",
			cache:       actionCache{fixture: "malformed-project"},
			wantEntries: []string{"actions/checkout@v4"},
		},
		{
			// What ACTIONS_RUNNER_SYMLINK_CACHED_ACTIONS produces, in the shape the runner writes
			// it. Both entries of one cache: a hit, served from the archive cache as a symlink, and
			// a miss, extracted in place beside its watermark.
			name: "verify when an entry is symlinked into the archive cache then it is followed",
			cache: actionCache{
				dirs: []string{
					"_actions/actions/checkout/v4", // a miss: extracted, so a real directory
					"_actions/actions/setup-node",
					// <ARCHIVE_CACHE>/<owner>_<repo>/<sha>, holding the single nested folder a
					// GitHub repository archive always unpacks to.
					"archive-cache/actions_setup-node/" + archiveCacheSHA + "/setup-node-" + archiveCacheSHA,
				},
				// The watermark the runner drops beside an extracted entry is still not an action.
				files: map[string]string{"_actions/actions/checkout/v4.completed": "ts"},
				// The link lands on the ref directory itself, and nothing above it.
				symlinks: map[string]string{
					"_actions/actions/setup-node/v4": "archive-cache/actions_setup-node/" + archiveCacheSHA + "/setup-node-" + archiveCacheSHA,
				},
			},
			wantEntries: []string{"actions/checkout@v4", "actions/setup-node@v4"},
		},
		{
			// Measured on a hosted runner: a branch ref nests, and the runner puts its watermark
			// beside the real root rather than at a fixed depth. Reading only three levels deep
			// would report actions/checkout@copilot - an action that does not exist - and leave
			// the one that actually executes undiscovered.
			name: "verify when the ref contains a slash then the whole ref is recovered",
			cache: actionCache{
				dirs: []string{"_actions/actions/checkout/copilot/backport-2518-releases-v4"},
				files: map[string]string{
					"_actions/actions/checkout/copilot/backport-2518-releases-v4.completed":  "ts",
					"_actions/actions/checkout/copilot/backport-2518-releases-v4/action.yml": "runs:\n  using: node20\n",
				},
			},
			wantEntries: []string{"actions/checkout@copilot/backport-2518-releases-v4"},
		},
		{
			// The same tree the probe produced: a slashed ref and a plain one under one repo.
			name: "verify when a repo holds both a plain and a slashed ref then each is reported once",
			cache: actionCache{
				dirs: []string{"_actions/actions/checkout/v4", "_actions/actions/checkout/copilot/backport-v4"},
				files: map[string]string{
					"_actions/actions/checkout/v4.completed":                  "ts",
					"_actions/actions/checkout/copilot/backport-v4.completed": "ts",
				},
			},
			wantEntries: []string{"actions/checkout@v4", "actions/checkout@copilot/backport-v4"},
		},
		{
			// Three monorepo actions, each carrying subpath manifests. Only the ref root is
			// watermarked, which is what stops analyze/ and init/ surfacing as their own actions -
			// manifest presence could not tell them apart.
			name: "verify when a monorepo action has subpaths then only the ref root is reported",
			cache: actionCache{
				dirs: []string{
					"_actions/github/codeql-action/v3/analyze", "_actions/github/codeql-action/v3/init",
					"_actions/anchore/sbom-action/v0/download-syft", "_actions/anchore/sbom-action/v0/publish-sbom",
					"_actions/anchore/scan-action/v7/download-grype",
				},
				files: map[string]string{
					"_actions/github/codeql-action/v3.completed":                "ts",
					"_actions/github/codeql-action/v3/action.yml":               "runs:\n  using: node20\n",
					"_actions/github/codeql-action/v3/analyze/action.yml":       "runs:\n  using: node20\n",
					"_actions/github/codeql-action/v3/init/action.yml":          "runs:\n  using: node20\n",
					"_actions/anchore/sbom-action/v0.completed":                 "ts",
					"_actions/anchore/sbom-action/v0/download-syft/action.yml":  "runs:\n  using: node20\n",
					"_actions/anchore/sbom-action/v0/publish-sbom/action.yml":   "runs:\n  using: node20\n",
					"_actions/anchore/scan-action/v7.completed":                 "ts",
					"_actions/anchore/scan-action/v7/download-grype/action.yml": "runs:\n  using: node20\n",
				},
			},
			wantEntries: []string{"github/codeql-action@v3", "anchore/sbom-action@v0", "anchore/scan-action@v7"},
		},
		{
			// A symlinked root carries no watermark - the runner returns before writing one - so
			// the link itself has to end the ref, at a plain depth or a nested one.
			name: "verify when a symlinked root sits at a slashed ref then the whole ref is recovered",
			cache: actionCache{
				dirs:     []string{"archive-cache/unpacked", "_actions/actions/checkout/feature"},
				symlinks: map[string]string{"_actions/actions/checkout/feature/my-branch": "archive-cache/unpacked"},
			},
			wantEntries: []string{"actions/checkout@feature/my-branch"},
		},
		{
			// The marker is what identifies a root, so an entry missing one in a cache whose other
			// entries have them cannot be placed. Reporting actions/checkout@feature would name an
			// action that does not exist while the one that does stays unexamined, so it is dropped
			// and said out loud instead.
			name: "verify when one entry in a marked cache has no marker then it is unaccounted for",
			cache: actionCache{
				dirs: []string{"_actions/actions/checkout/v4", "_actions/actions/checkout/feature/my-branch"},
				files: map[string]string{
					"_actions/actions/checkout/v4.completed":                 "ts",
					"_actions/actions/checkout/feature/my-branch/action.yml": "runs:\n  using: node20\n",
				},
			},
			wantEntries:     []string{"actions/checkout@v4"},
			wantUnaccounted: []string{"actions/checkout/feature"},
		},
		{
			// Two refs of one monorepo, each reached through a different subpath - init@v2 and
			// analyze@v3. Both roots are watermarked, so each ref is named in full and neither
			// subpath is mistaken for a root of its own.
			name: "verify when one monorepo has two refs then each is reported under its own ref",
			cache: actionCache{
				dirs: []string{"_actions/github/codeql-action/v2/init", "_actions/github/codeql-action/v3/analyze"},
				files: map[string]string{
					"_actions/github/codeql-action/v2.completed":          "ts",
					"_actions/github/codeql-action/v2/init/action.yml":    "runs:\n  using: node20\n",
					"_actions/github/codeql-action/v3.completed":          "ts",
					"_actions/github/codeql-action/v3/analyze/action.yml": "runs:\n  using: node20\n",
				},
			},
			wantEntries: []string{"github/codeql-action@v2", "github/codeql-action@v3"},
		},
		{
			// A branch may carry any number of slashes, so there is no depth at which the descent
			// can stop counting and still be right. What ends it is the cache's own shape: each
			// intermediate holds only the next segment, so the marker is reached however deep it is.
			name: "verify when a ref spans many segments then the whole ref is recovered",
			cache: actionCache{
				dirs: []string{"_actions/actions/checkout/v4", "_actions/actions/checkout/release/2024/q1/hotfix/v2"},
				files: map[string]string{
					"_actions/actions/checkout/v4.completed":                         "ts",
					"_actions/actions/checkout/release/2024/q1/hotfix/v2.completed":  "ts",
					"_actions/actions/checkout/release/2024/q1/hotfix/v2/action.yml": "runs:\n  using: node20\n",
				},
			},
			wantEntries: []string{"actions/checkout@v4", "actions/checkout@release/2024/q1/hotfix/v2"},
		},
		{
			// The descent stops where content starts, so a file left in an intermediate ends it
			// early. The marker is still what names a ref, so the entry is dropped and said out
			// loud rather than reported under the prefix reached so far.
			name: "verify when an intermediate holds a stray file then the entry is unaccounted rather than truncated",
			cache: actionCache{
				dirs: []string{"_actions/actions/checkout/v4", "_actions/actions/checkout/release/hotfix/v2"},
				files: map[string]string{
					"_actions/actions/checkout/v4.completed":                 "ts",
					"_actions/actions/checkout/release/.DS_Store":            "junk",
					"_actions/actions/checkout/release/hotfix/v2.completed":  "ts",
					"_actions/actions/checkout/release/hotfix/v2/action.yml": "runs:\n  using: node20\n",
				},
			},
			wantEntries:     []string{"actions/checkout@v4"},
			wantUnaccounted: []string{"actions/checkout/release"},
		},
		{
			// Every shape one cache can hold at once: a tag ref at depth one, a deep branch ref, and
			// a monorepo whose subpaths must not surface as refs of their own. The marker decides all
			// three; the walk never reads inside any of them.
			name: "verify when one cache mixes ref depths and a monorepo then each action is reported once",
			cache: actionCache{
				dirs: []string{
					"_actions/actions/checkout/v4/dist",
					"_actions/actions/checkout/release/2024/q1/hotfix/v2/dist",
					"_actions/github/codeql-action/v3/init",
					"_actions/github/codeql-action/v3/analyze",
				},
				files: map[string]string{
					"_actions/actions/checkout/v4.completed":                         "ts",
					"_actions/actions/checkout/v4/action.yml":                        "runs:\n  using: node20\n",
					"_actions/actions/checkout/v4/README.md":                         "x",
					"_actions/actions/checkout/release/2024/q1/hotfix/v2.completed":  "ts",
					"_actions/actions/checkout/release/2024/q1/hotfix/v2/action.yml": "runs:\n  using: node20\n",
					"_actions/github/codeql-action/v3.completed":                     "ts",
					"_actions/github/codeql-action/v3/action.yml":                    "runs:\n  using: node20\n",
					"_actions/github/codeql-action/v3/init/action.yml":               "runs:\n  using: node20\n",
					"_actions/github/codeql-action/v3/analyze/action.yml":            "runs:\n  using: node20\n",
				},
			},
			wantEntries: []string{"actions/checkout@v4", "actions/checkout@release/2024/q1/hotfix/v2", "github/codeql-action@v3"},
		},
		{
			// Nothing stops a branch from being called release.completed, so the watermark test
			// has to distinguish the marker file from a directory that shares its suffix.
			name: "verify when a ref itself ends in the watermark suffix then it is still an action",
			cache: actionCache{
				dirs: []string{"_actions/actions/checkout/release.completed"},
				files: map[string]string{
					"_actions/actions/checkout/release.completed.completed":  "ts",
					"_actions/actions/checkout/release.completed/action.yml": "runs:\n  using: node20\n",
				},
			},
			wantEntries: []string{"actions/checkout@release.completed"},
		},
		{
			// The entry names an action, so it cannot be waved through: its content is gone, and
			// nothing here can say what curating it would have concluded.
			name: "verify when a symlink resolves to nothing then it is unaccounted rather than skipped",
			cache: actionCache{
				dirs:     []string{"_actions/actions/checkout"},
				symlinks: map[string]string{"_actions/actions/checkout/v4": "nowhere"},
			},
			wantUnaccounted: []string{"actions/checkout/v4"},
		},
		{
			// A runner filesystem error at owner and at repo level. One action still resolves, so
			// this pins that a partial walk is a failure rather than a short report.
			name: "verify when an owner or repo directory cannot be listed then it is unaccounted for",
			cache: actionCache{
				dirs: []string{
					"_actions/actions/checkout/v4",
					"_actions/github/codeql-action/v3",
					"_actions/good-org/good-action/v1",
				},
				files: map[string]string{
					"_actions/github/codeql-action/v3.completed": "ts",
					"_actions/good-org/good-action/v1.completed": "ts",
				},
				unreadable: []string{"_actions/actions", "_actions/github/codeql-action"},
			},
			wantEntries:     []string{"good-org/good-action@v1"},
			wantUnaccounted: []string{"actions", "github/codeql-action"},
		},
		{
			// Dangling links at owner and repo level, where the walk learns an entry exists before
			// it can classify it. Nothing names an action yet, but something is there.
			name: "verify when an owner or repo entry cannot be resolved then it is unaccounted for",
			cache: actionCache{
				dirs:     []string{"_actions/good-org/good-action/v1"},
				files:    map[string]string{"_actions/good-org/good-action/v1.completed": "ts"},
				symlinks: map[string]string{"_actions/ghost-owner": "nowhere", "_actions/good-org/ghost-repo": "nowhere"},
			},
			wantEntries:     []string{"good-org/good-action@v1"},
			wantUnaccounted: []string{"ghost-owner", "good-org/ghost-repo"},
		},
		{
			// Below the ref level, inside what could be a slashed ref: one intermediate that cannot
			// be listed, one that can but holds a dangling link. Each is named once, by the reason
			// the descent stopped. branch itself is not also reported as unmarked - the dangling
			// entry under it is the specific fact, and a missing marker would just restate it.
			name: "verify when a nested ref segment cannot be read then it is unaccounted exactly once",
			cache: actionCache{
				dirs:       []string{"_actions/actions/checkout/v4", "_actions/actions/checkout/unlistable", "_actions/actions/checkout/branch"},
				files:      map[string]string{"_actions/actions/checkout/v4.completed": "ts"},
				symlinks:   map[string]string{"_actions/actions/checkout/branch/ghost": "nowhere"},
				unreadable: []string{"_actions/actions/checkout/unlistable"},
			},
			wantEntries: []string{"actions/checkout@v4"},
			wantUnaccounted: []string{
				"actions/checkout/unlistable",   // cannot be listed
				"actions/checkout/branch/ghost", // listed, but the entry does not resolve
			},
		},
		{
			name:    "verify when the cache root is not a directory then the walk fails rather than reporting nothing",
			cache:   actionCache{files: map[string]string{"_actions": "not a directory"}},
			wantErr: true,
		},
		{
			// Every entry was understood and none held an action, which is a clean result rather
			// than a blind spot - so it warns instead of going unaccounted.
			name: "verify when a populated cache holds no action at all then it warns without failing",
			cache: actionCache{
				dirs:  []string{"_actions/onlyowner"},
				files: map[string]string{"_actions/stray.txt": "x"},
			},
			wantWarn: "none resolved to an",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheRoot := tt.cache.build(t)
			warnings := captureWarnings(t)

			scan, err := DiscoverActionCache(cacheRoot)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tt.wantWarn != "" {
				assert.Contains(t, warnings.String(), tt.wantWarn)
			}
			assert.NotNil(t, scan.Refs, "an empty result must still be a usable slice")

			unaccounted := make([]string, len(scan.Unaccounted))
			for i, entry := range scan.Unaccounted {
				rel, relErr := filepath.Rel(cacheRoot, entry.Path)
				require.NoError(t, relErr)
				unaccounted[i] = filepath.ToSlash(rel)
				assert.NotEmpty(t, entry.Reason, "an unaccounted entry must say why")
			}
			assert.ElementsMatch(t, tt.wantUnaccounted, unaccounted)
			assert.Equal(t, len(tt.wantUnaccounted) > 0, scan.UnaccountedError() != nil,
				"UnaccountedError must be non-nil exactly when an entry went unaccounted")

			found := make([]string, len(scan.Refs))
			for i, ref := range scan.Refs {
				found[i] = ref.Owner + "/" + ref.Repo + "@" + ref.Ref
			}
			assert.ElementsMatch(t, tt.wantEntries, found)
			for _, ref := range scan.Refs {
				assert.Equal(t, filepath.Join(cacheRoot, ref.Owner, ref.Repo, ref.Ref), ref.Path)
				assert.Empty(t, ref.Subpaths, "DiscoverActionCache must not set Subpaths - that's CrossReference's job")
				assert.Empty(t, ref.Parent, "DiscoverActionCache must not set Parent - that's CrossReference's job")
			}
		})
	}
}

func TestDefaultActionsCacheDir(t *testing.T) {
	tests := []struct {
		name            string
		runnerWorkspace string
		want            string
		wantErr         bool
	}{
		{
			name:            "verify when RUNNER_WORKSPACE is set then the cache path is its sibling",
			runnerWorkspace: "/home/runner/work/my-repo",
			want:            filepath.Clean("/home/runner/work/_actions"),
		},
		{
			name:            "verify when RUNNER_WORKSPACE is unset then an error is returned rather than a guess",
			runnerWorkspace: "",
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(RunnerWorkspaceEnvVar, tt.runnerWorkspace)

			dir, err := DefaultActionsCacheDir()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, dir)
		})
	}
}

func TestDefaultWorkflowFile(t *testing.T) {
	tests := []struct {
		name        string
		workflowRef string
		want        string
	}{
		{"verify when the ref is standard then the repo-relative path is returned", "octocat/hello-world/.github/workflows/ci.yml@refs/heads/main", ".github/workflows/ci.yml"},
		{"verify when the ref contains slashes then the path is still returned", "octocat/hello-world/.github/workflows/ci.yml@refs/heads/my/feature", ".github/workflows/ci.yml"},
		{"verify when the ref is a tag then the path is still returned", "octocat/hello-world/.github/workflows/release.yaml@refs/tags/v1.2.3", ".github/workflows/release.yaml"},
		{"verify when the variable is unset then the path is empty", "", ""},
		{"verify when the value carries no path then the result is empty", "octocat/hello-world@refs/heads/main", ""},
		{"verify when the value has no ref suffix then the path is still returned", "octocat/hello-world/.github/workflows/ci.yml", ".github/workflows/ci.yml"},
		{"verify when the value is malformed then the result is empty rather than an error", "nonsense", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(WorkflowRefEnvVar, tt.workflowRef)
			assert.Equal(t, tt.want, DefaultWorkflowFile())
		})
	}
}

func TestDefaultJobID(t *testing.T) {
	t.Setenv(JobIDEnvVar, "build")
	assert.Equal(t, "build", DefaultJobID())

	t.Setenv(JobIDEnvVar, "")
	assert.Empty(t, DefaultJobID())
}

func TestDefaultGithubRepo(t *testing.T) {
	t.Setenv(GithubRepoEnvVar, "octocat/hello-world")
	assert.Equal(t, "octocat/hello-world", DefaultGithubRepo())

	t.Setenv(GithubRepoEnvVar, "")
	assert.Empty(t, DefaultGithubRepo())
}

func TestExcludeDeliveryAction(t *testing.T) {
	tests := []struct {
		name      string
		refs      []ActionRef
		wantRepos []string
	}{
		{
			name: "verify when the delivery action is present at any ref then it is dropped",
			refs: []ActionRef{
				{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "v4"},
				{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "9a4c2881"},
				{Owner: "actions", Repo: "checkout", Ref: "v4"},
			},
			wantRepos: []string{"checkout"},
		},
		{
			// GitHub resolves owner and repo case-insensitively and the runner names the cache
			// directory from the uses: line verbatim, so this spelling really reaches disk.
			name: "verify when the delivery action is spelled with different casing then it is still dropped",
			refs: []ActionRef{
				{Owner: "JFrog", Repo: "setup-jfrog-cli", Ref: "v4"},
				{Owner: "JFROG", Repo: "Setup-JFrog-CLI", Ref: "v4"},
				{Owner: "actions", Repo: "checkout", Ref: "v4"},
			},
			wantRepos: []string{"checkout"},
		},
		{
			name: "verify when another jfrog action is present then it is kept",
			refs: []ActionRef{
				{Owner: "jfrog", Repo: "frogbot", Ref: "v2"},
				{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "v4"},
			},
			wantRepos: []string{"frogbot"},
		},
		{
			name: "verify when another owner ships a same-named action then it is kept",
			refs: []ActionRef{
				{Owner: "not-jfrog", Repo: "setup-jfrog-cli", Ref: "v4"},
			},
			wantRepos: []string{"setup-jfrog-cli"},
		},
		{
			name:      "verify when only the delivery action is present then nothing is left to curate",
			refs:      []ActionRef{{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "v4"}},
			wantRepos: nil,
		},
		{
			name:      "verify when there are no refs then the result stays empty",
			refs:      nil,
			wantRepos: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept := ExcludeDeliveryAction(tt.refs)
			repos := make([]string, len(kept))
			for i, ref := range kept {
				repos[i] = ref.Repo
			}
			if tt.wantRepos == nil {
				assert.Empty(t, repos)
				return
			}
			assert.Equal(t, tt.wantRepos, repos)
		})
	}
}

func TestExcludeDeliveryAction_PreservesTransitiveAttribution(t *testing.T) {
	// Excluding the delivery action must not orphan anything it pulled in: attribution runs
	// before this filter, so a child keeps its Parent even though that parent is not reported.
	kept := ExcludeDeliveryAction([]ActionRef{
		{Owner: "jfrog", Repo: "setup-jfrog-cli", Ref: "v4"},
		{Owner: "some-org", Repo: "pulled-in-by-delivery", Ref: "v1", Parent: "jfrog/setup-jfrog-cli@v4"},
	})

	if assert.Len(t, kept, 1) {
		assert.Equal(t, "pulled-in-by-delivery", kept[0].Repo)
		assert.Equal(t, "jfrog/setup-jfrog-cli@v4", kept[0].Parent, "attribution must survive the exclusion")
	}
}
