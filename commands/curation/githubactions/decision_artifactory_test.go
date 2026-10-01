package githubactions

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vcsAPIPath = "/artifactory/api/vcs/"

// fakeArtifactory serves getRefs and the download APIs, recording each request's escaped path.
type fakeArtifactory struct {
	refsStatus     int
	refsBody       string
	downloadStatus int
	downloadHeader http.Header
	downloadBody   []byte

	mu       sync.Mutex
	requests []string
}

func (f *fakeArtifactory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, strings.TrimPrefix(r.URL.EscapedPath(), vcsAPIPath))
	f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, vcsAPIPath+"refs/") {
		w.WriteHeader(f.refsStatus)
		_, _ = w.Write([]byte(f.refsBody))
		return
	}
	for k, v := range f.downloadHeader {
		w.Header()[k] = v
	}
	w.WriteHeader(f.downloadStatus)
	_, _ = w.Write(f.downloadBody)
}

func (f *fakeArtifactory) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// deciderAdvertisement advertises a tag, a branch, and the measured tag/branch name collision.
var deciderAdvertisement = advertisement(
	pkt(branchTip+" HEAD\x00symref=HEAD:refs/heads/main object-format=sha1\n"),
	pkt(branchTip+" refs/heads/main\n"),
	pkt(branchTip+" refs/heads/collision\n"),
	pkt(branchTip+" refs/heads/Feature/X\n"),
	pkt("11d5960a326750d5838078e36cf38b85af677262 refs/tags/v4\n"),
	pkt(tagObject+" refs/tags/collision\n"),
	pkt(tagCommit+" refs/tags/collision^{}\n"),
)

func newTestDecider(t *testing.T, fake *fakeArtifactory) ActionCurationDecider {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	decider, err := NewArtifactoryActionCurationDecider(&config.ServerDetails{
		ArtifactoryUrl: server.URL + "/artifactory/",
		AccessToken:    testAccessToken,
	})
	require.NoError(t, err)
	return decider
}

// approvingArtifactory serves the advertisement and approves every download with filename.
func approvingArtifactory(t *testing.T, filename string) *fakeArtifactory {
	t.Helper()
	header := http.Header{}
	if filename != "" {
		header.Set(headerArtifactoryFilename, filename)
	}
	return &fakeArtifactory{
		refsStatus: http.StatusOK, refsBody: deciderAdvertisement,
		downloadStatus: http.StatusOK, downloadHeader: header, downloadBody: actionArchive(t),
	}
}

func TestArtifactoryDeciderApproves(t *testing.T) {
	const checkoutV4Commit = "11d5960a326750d5838078e36cf38b85af677262"
	tests := []struct {
		name         string
		owner, repo  string
		ref          string
		filename     string
		wantRequests []string
		wantNotes    string
	}{
		{
			name: "verify when a bare tag is approved then it downloads by tag and notes no SHA", owner: "actions", repo: "checkout", ref: "v4",
			filename:     "checkout-v4.tar.gz",
			wantRequests: []string{"refs/github-vcs/actions/checkout", "downloadTag/github-vcs/actions/checkout/v4"},
		},
		{
			name: "verify when a branch is approved then it downloads by branch and notes the resolved SHA", owner: "actions", repo: "checkout", ref: "main",
			filename:     "checkout-main-" + branchTip + ".tar.gz",
			wantRequests: []string{"refs/github-vcs/actions/checkout", "downloadBranch/github-vcs/actions/checkout/main"},
			wantNotes:    resolvedSHANotePrefix + branchTip,
		},
		{
			name: "verify when a full SHA is approved then git refs are not fetched", owner: "actions", repo: "checkout", ref: checkoutV4Commit,
			filename:     "checkout-" + checkoutV4Commit + ".tar.gz",
			wantRequests: []string{"downloadCommit/github-vcs/actions/checkout/" + checkoutV4Commit},
			wantNotes:    resolvedSHANotePrefix + checkoutV4Commit,
		},
		{
			name: "verify when an uppercase SHA is approved then it is requested lower-cased", owner: "actions", repo: "checkout", ref: strings.ToUpper(checkoutV4Commit),
			filename:     "checkout-" + checkoutV4Commit + ".tar.gz",
			wantRequests: []string{"downloadCommit/github-vcs/actions/checkout/" + checkoutV4Commit},
			wantNotes:    resolvedSHANotePrefix + checkoutV4Commit,
		},
		{
			name: "verify when a fully-qualified tag is approved then the short name is requested", owner: "actions", repo: "checkout", ref: "refs/tags/v4",
			filename:     "checkout-v4.tar.gz",
			wantRequests: []string{"refs/github-vcs/actions/checkout", "downloadTag/github-vcs/actions/checkout/v4"},
		},
		{
			name: "verify when a fully-qualified branch collides with a tag then its tip commit is requested", owner: "actions", repo: "checkout", ref: "refs/heads/collision",
			filename:     "checkout-" + branchTip + ".tar.gz",
			wantRequests: []string{"refs/github-vcs/actions/checkout", "downloadCommit/github-vcs/actions/checkout/" + branchTip},
			wantNotes:    resolvedSHANotePrefix + branchTip,
		},
		{
			name: "verify when owner and repo are mixed case then they are requested lower-cased", owner: "Actions", repo: "Checkout", ref: "v4",
			filename:     "checkout-v4.tar.gz",
			wantRequests: []string{"refs/github-vcs/actions/checkout", "downloadTag/github-vcs/actions/checkout/v4"},
		},
		{
			name: "verify when a branch name is mixed case then its casing is kept", owner: "actions", repo: "checkout", ref: "Feature/X",
			filename:     "X-" + branchTip + ".tar.gz",
			wantRequests: []string{"refs/github-vcs/actions/checkout", "downloadBranch/github-vcs/actions/checkout/Feature/X"},
			wantNotes:    resolvedSHANotePrefix + branchTip,
		},
		{
			name: "verify when the response names no archive then the action is approved without a note", owner: "actions", repo: "checkout", ref: "main",
			wantRequests: []string{"refs/github-vcs/actions/checkout", "downloadBranch/github-vcs/actions/checkout/main"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := approvingArtifactory(t, tt.filename)
			actionDir := runnerCache(t, tt.ref)
			ref := ActionRef{Owner: tt.owner, Repo: tt.repo, Ref: tt.ref, Path: actionDir}

			got, err := newTestDecider(t, fake).Decide(context.Background(), testRepoKey, ref)

			require.NoError(t, err)
			assert.Equal(t, ActionCurationResult{Status: ActionApproved, Notes: tt.wantNotes}, got)
			assert.Equal(t, tt.wantRequests, fake.recorded())
			// The served content lands where the runner put the action, under its literal ref.
			assert.Equal(t, "name: curated\n", readFile(t, filepath.Join(actionDir, "action.yml")))
			assert.NoFileExists(t, filepath.Join(actionDir, "stale.js"))
		})
	}
}

func TestArtifactoryDeciderRejects(t *testing.T) {
	t.Run("verify when a download is blocked by curation then the verdict is Rejected with the reason and the runner's copy is kept", func(t *testing.T) {
		fake := &fakeArtifactory{
			refsStatus: http.StatusOK, refsBody: deciderAdvertisement,
			downloadStatus: http.StatusForbidden, downloadBody: []byte(blockedEnvelope),
		}
		actionDir := runnerCache(t, "v4")
		ref := ActionRef{Owner: "actions", Repo: "checkout", Ref: "v4", Path: actionDir}

		got, err := newTestDecider(t, fake).Decide(context.Background(), testRepoKey, ref)

		require.NoError(t, err, "a curation block is a verdict, not an error")
		assert.Equal(t, ActionCurationResult{Status: ActionRejected, Notes: "Package is blocked by policy: no-unpinned-actions"}, got)
		assertOriginalIntact(t, actionDir)
	})
}

func TestArtifactoryDeciderErrors(t *testing.T) {
	tests := []struct {
		name         string
		fake         *fakeArtifactory
		ref          string
		wantDenied   bool
		wantNotFound bool
		wantRequests int
	}{
		{
			name: "verify when a download returns 401 then it is an access failure",
			fake: &fakeArtifactory{refsStatus: http.StatusOK, refsBody: deciderAdvertisement, downloadStatus: http.StatusUnauthorized},
			ref:  "v4", wantDenied: true, wantRequests: 2,
		},
		{
			name: "verify when getRefs returns 401 then it is an access failure and nothing is downloaded",
			fake: &fakeArtifactory{refsStatus: http.StatusUnauthorized},
			ref:  "v4", wantDenied: true, wantRequests: 1,
		},
		{
			name: "verify when getRefs returns 403 then it is an access failure and not a Rejected verdict",
			fake: &fakeArtifactory{refsStatus: http.StatusForbidden, refsBody: blockedEnvelope},
			ref:  "v4", wantDenied: true, wantRequests: 1,
		},
		{
			name: "verify when a download returns 404 then it is an error but not an access failure",
			fake: &fakeArtifactory{refsStatus: http.StatusOK, refsBody: deciderAdvertisement, downloadStatus: http.StatusNotFound, downloadBody: []byte(notFoundBody)},
			ref:  "v4", wantRequests: 2,
		},
		{
			name: "verify when the ref is not advertised then it errors without downloading",
			fake: &fakeArtifactory{refsStatus: http.StatusOK, refsBody: deciderAdvertisement},
			ref:  "no-such-ref", wantNotFound: true, wantRequests: 1,
		},
		{
			name: "verify when the served archive is not a tarball then it errors and the runner's copy is kept",
			fake: &fakeArtifactory{refsStatus: http.StatusOK, refsBody: deciderAdvertisement, downloadStatus: http.StatusOK, downloadBody: []byte("not a tarball")},
			ref:  "v4", wantRequests: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionDir := runnerCache(t, tt.ref)
			ref := ActionRef{Owner: "actions", Repo: "checkout", Ref: tt.ref, Path: actionDir}

			got, err := newTestDecider(t, tt.fake).Decide(context.Background(), testRepoKey, ref)

			require.Error(t, err)
			assert.Equal(t, ActionCurationResult{}, got, "an error must not also carry a verdict")
			assert.Equal(t, tt.wantDenied, errors.Is(err, ErrAccessDenied), "Decide() error = %v, want errors.Is(ErrAccessDenied) = %v", err, tt.wantDenied)
			assert.Equal(t, tt.wantNotFound, errors.Is(err, ErrRefNotAdvertised), "Decide() error = %v, want errors.Is(ErrRefNotAdvertised) = %v", err, tt.wantNotFound)
			assert.Len(t, tt.fake.recorded(), tt.wantRequests)
			assertOriginalIntact(t, actionDir)
		})
	}
}

func TestArtifactoryDeciderHonoursCancelledContext(t *testing.T) {
	t.Run("verify when the context is already cancelled then no request is made", func(t *testing.T) {
		fake := approvingArtifactory(t, "")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := newTestDecider(t, fake).Decide(ctx, testRepoKey, ActionRef{Owner: "actions", Repo: "checkout", Ref: "v4", Path: runnerCache(t, "v4")})

		assert.True(t, errors.Is(err, context.Canceled), "Decide() error = %v, want context.Canceled", err)
		assert.Empty(t, fake.recorded())
	})
}
