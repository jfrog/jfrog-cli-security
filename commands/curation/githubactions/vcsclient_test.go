package githubactions

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRepoKey     = "github-vcs"
	testAccessToken = "test-token"
	// Artifactory's curation-block body, in the shape it is changing to.
	blockedEnvelope = `{"errors":[{"status":403,"message":"Package is blocked by policy: no-unpinned-actions"}]}`
	notFoundBody    = `{"errors":[{"status":404,"message":"Not found"}]}`
)

// newTestVCSClient returns a client for a fake Artifactory served by handler.
func newTestVCSClient(t *testing.T, handler http.Handler) *vcsClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := newVCSClient(&config.ServerDetails{
		ArtifactoryUrl: server.URL + "/artifactory/",
		AccessToken:    testAccessToken,
	})
	require.NoError(t, err)
	return client
}

// respond answers every request with status, headers and body, counting requests.
func respond(status int, header http.Header, body string, calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

// capturedAdvertisement is a small valid getRefs body.
var capturedAdvertisement = advertisement(
	pkt(branchTip+" HEAD\x00symref=HEAD:refs/heads/main object-format=sha1\n"),
	pkt(branchTip+" refs/heads/main\n"),
)

func TestVCSClientGetRefs(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantCalls   int32
		wantDenied  bool
		wantAnyErr  bool
		wantInError string
	}{
		{name: "verify when getRefs returns 200 then the advertisement is parsed", status: http.StatusOK, body: capturedAdvertisement, wantCalls: 1},
		{name: "verify when getRefs returns 401 then it is an access failure", status: http.StatusUnauthorized, wantCalls: 1, wantDenied: true, wantAnyErr: true},
		// getRefs has no curation flow: a 403 is a permission problem, not a block.
		{name: "verify when getRefs returns 403 then it is an access failure and not a curation block", status: http.StatusForbidden, body: blockedEnvelope, wantCalls: 1, wantDenied: true, wantAnyErr: true},
		{name: "verify when getRefs returns 404 then the error carries Artifactory's message", status: http.StatusNotFound, body: notFoundBody, wantCalls: 1, wantAnyErr: true, wantInError: "Not found"},
		{name: "verify when getRefs returns 500 then it is retried and then fails", status: http.StatusInternalServerError, wantCalls: vcsHTTPRetries + 1, wantAnyErr: true},
		{name: "verify when getRefs returns 429 then it is retried and then fails", status: http.StatusTooManyRequests, wantCalls: vcsHTTPRetries + 1, wantAnyErr: true},
		{name: "verify when getRefs returns 200 with a malformed body then it fails to parse", status: http.StatusOK, body: "not a pkt-line stream", wantCalls: 1, wantAnyErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			// getRefs labels its pkt-line body application/json; the client must not care.
			header := http.Header{"Content-Type": {"application/json"}}
			client := newTestVCSClient(t, respond(tt.status, header, tt.body, &calls))

			got, err := client.GetRefs(testRepoKey, "actions", "checkout")

			assert.Equal(t, tt.wantCalls, calls.Load(), "GetRefs() request count")
			var blocked *BlockedError
			assert.False(t, errors.As(err, &blocked), "GetRefs() error = %v; a getRefs failure must never be a curation block", err)
			if !tt.wantAnyErr {
				require.NoError(t, err)
				assert.Equal(t, "main", got.DefaultBranch)
				assert.Equal(t, branchTip, got.Refs["refs/heads/main"])
				return
			}
			require.Error(t, err)
			assert.Nil(t, got)
			assert.Equal(t, tt.wantDenied, errors.Is(err, ErrAccessDenied), "GetRefs() error = %v, want errors.Is(ErrAccessDenied) = %v", err, tt.wantDenied)
			if tt.wantInError != "" {
				assert.ErrorContains(t, err, tt.wantInError)
			}
		})
	}
}

func TestVCSClientGetRefsRequest(t *testing.T) {
	t.Run("verify when refs are requested then the documented path and the configured token are used", func(t *testing.T) {
		var gotPath, gotAuth string
		client := newTestVCSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
			_, _ = io.WriteString(w, capturedAdvertisement)
		}))

		_, err := client.GetRefs(testRepoKey, "actions", "checkout")

		require.NoError(t, err)
		assert.Equal(t, "/artifactory/api/vcs/refs/github-vcs/actions/checkout", gotPath)
		assert.Equal(t, "Bearer "+testAccessToken, gotAuth)
	})
}

func TestVCSClientGetRefsIsFetchedOncePerRepository(t *testing.T) {
	t.Run("verify when many callers ask for one repository's refs concurrently then it is requested once", func(t *testing.T) {
		var calls atomic.Int32
		release := make(chan struct{})
		client := newTestVCSClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			<-release // hold the first request so the other callers pile up behind it
			_, _ = io.WriteString(w, capturedAdvertisement)
		}))
		const callers = 20
		var started, done sync.WaitGroup
		errs := make([]error, callers)
		for i := range callers {
			started.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				started.Done()
				_, errs[i] = client.GetRefs(testRepoKey, "actions", "checkout")
			}()
		}
		started.Wait()
		close(release)
		done.Wait()

		_, err := client.GetRefs(testRepoKey, "actions", "checkout") // served from the cache

		require.NoError(t, err)
		for i, err := range errs {
			assert.NoError(t, err, "GetRefs() caller %d", i)
		}
		assert.Equal(t, int32(1), calls.Load(), "GetRefs() request count across %d callers", callers+1)
	})
	t.Run("verify when different repositories are asked for then each is requested", func(t *testing.T) {
		var calls atomic.Int32
		client := newTestVCSClient(t, respond(http.StatusOK, nil, capturedAdvertisement, &calls))

		_, errCheckout := client.GetRefs(testRepoKey, "actions", "checkout")
		_, errSetupNode := client.GetRefs(testRepoKey, "actions", "setup-node")

		require.NoError(t, errCheckout)
		require.NoError(t, errSetupNode)
		assert.Equal(t, int32(2), calls.Load())
	})
}

func TestVCSClientDownload(t *testing.T) {
	archive := "archive-bytes"
	tests := []struct {
		name         string
		status       int
		header       http.Header
		body         string
		wantCalls    int32
		wantFilename string
		wantBlocked  string // "" = not a curation block
		wantDenied   bool
		wantAnyErr   bool
	}{
		{
			name:   "verify when a download returns 200 then the body and the Artifactory filename are returned",
			status: http.StatusOK, header: http.Header{headerArtifactoryFilename: {"checkout-main-" + branchTip + ".tar.gz"}},
			body: archive, wantCalls: 1, wantFilename: "checkout-main-" + branchTip + ".tar.gz",
		},
		{
			name:   "verify when only Content-Disposition names the archive then that filename is returned",
			status: http.StatusOK, header: http.Header{headerContentDisposition: {`attachment; filename="checkout-v4.tar.gz"`}},
			body: archive, wantCalls: 1, wantFilename: "checkout-v4.tar.gz",
		},
		{
			name:   "verify when the response names no archive then the filename is empty",
			status: http.StatusOK, body: archive, wantCalls: 1,
		},
		{
			name:   "verify when a download returns 403 with the errors envelope then it is a curation block carrying the reason",
			status: http.StatusForbidden, body: blockedEnvelope, wantCalls: 1,
			wantBlocked: "Package is blocked by policy: no-unpinned-actions", wantAnyErr: true,
		},
		{
			name:   "verify when a download returns 403 with an unparsable body then it is still a curation block",
			status: http.StatusForbidden, body: "<html>Forbidden</html>", wantCalls: 1,
			wantBlocked: blockedReasonUnparsable, wantAnyErr: true,
		},
		{
			name:   "verify when a download returns 401 then it is an access failure",
			status: http.StatusUnauthorized, wantCalls: 1, wantDenied: true, wantAnyErr: true,
		},
		{
			name:   "verify when a download returns 404 then it is neither a block nor an access failure",
			status: http.StatusNotFound, body: notFoundBody, wantCalls: 1, wantAnyErr: true,
		},
		{
			name:   "verify when a download returns 500 then it is retried and then fails",
			status: http.StatusInternalServerError, wantCalls: vcsHTTPRetries + 1, wantAnyErr: true,
		},
		{
			name:   "verify when a download returns 429 then it is retried and then fails",
			status: http.StatusTooManyRequests, wantCalls: vcsHTTPRetries + 1, wantAnyErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			client := newTestVCSClient(t, respond(tt.status, tt.header, tt.body, &calls))

			body, filename, err := client.Download(testRepoKey, "actions", "checkout", ResolvedRef{Kind: RefKindBranch, APIRef: "main"})

			assert.Equal(t, tt.wantCalls, calls.Load(), "Download() request count")
			if !tt.wantAnyErr {
				require.NoError(t, err)
				got, readErr := io.ReadAll(body)
				require.NoError(t, readErr)
				require.NoError(t, body.Close())
				assert.Equal(t, archive, string(got))
				assert.Equal(t, tt.wantFilename, filename)
				return
			}
			require.Error(t, err)
			assert.Nil(t, body)
			var blocked *BlockedError
			if tt.wantBlocked != "" {
				require.True(t, errors.As(err, &blocked), "Download() error = %v, want a *BlockedError", err)
				assert.Equal(t, tt.wantBlocked, blocked.Reason)
				// One blocked action must not stop the whole run.
				assert.False(t, errors.Is(err, ErrAccessDenied), "Download() curation block must not be an access failure")
				return
			}
			assert.False(t, errors.As(err, &blocked), "Download() error = %v, want no *BlockedError", err)
			assert.Equal(t, tt.wantDenied, errors.Is(err, ErrAccessDenied), "Download() error = %v, want errors.Is(ErrAccessDenied) = %v", err, tt.wantDenied)
		})
	}
}

func TestVCSClientDownloadPath(t *testing.T) {
	tests := []struct {
		name     string
		ref      ResolvedRef
		wantPath string
	}{
		{name: "verify when a tag is downloaded then downloadTag is called with the short name", ref: ResolvedRef{Kind: RefKindTag, APIRef: "v4"}, wantPath: "/artifactory/api/vcs/downloadTag/github-vcs/actions/checkout/v4"},
		{name: "verify when a commit is downloaded then downloadCommit is called with the id", ref: ResolvedRef{Kind: RefKindCommit, APIRef: branchTip}, wantPath: "/artifactory/api/vcs/downloadCommit/github-vcs/actions/checkout/" + branchTip},
		// Measured: releases/v3 must arrive as two segments; %2F-encoding it 404s.
		{name: "verify when a slashed branch is downloaded then its slash stays a path separator", ref: ResolvedRef{Kind: RefKindBranch, APIRef: "releases/v3"}, wantPath: "/artifactory/api/vcs/downloadBranch/github-vcs/actions/checkout/releases/v3"},
		{name: "verify when a deeply nested branch is downloaded then every slash stays a separator", ref: ResolvedRef{Kind: RefKindBranch, APIRef: "dependabot/npm_and_yarn/types/node-26.1.1"}, wantPath: "/artifactory/api/vcs/downloadBranch/github-vcs/actions/checkout/dependabot/npm_and_yarn/types/node-26.1.1"},
		{name: "verify when a branch segment has a reserved character then that segment is escaped", ref: ResolvedRef{Kind: RefKindBranch, APIRef: "fix/a#b"}, wantPath: "/artifactory/api/vcs/downloadBranch/github-vcs/actions/checkout/fix/a%23b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath, gotExt string
			client := newTestVCSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotExt = r.URL.EscapedPath(), r.URL.Query().Get("ext")
				_, _ = io.WriteString(w, "archive")
			}))

			body, _, err := client.Download(testRepoKey, "actions", "checkout", tt.ref)

			require.NoError(t, err)
			require.NoError(t, body.Close())
			assert.Equal(t, tt.wantPath, gotPath)
			assert.Equal(t, "tar.gz", gotExt, "Download() must request tar.gz explicitly; GitHub Enterprise remotes default to zip")
		})
	}
}

func TestVCSClientTimesOutAStalledResponse(t *testing.T) {
	tests := []struct {
		name string
		// stall is how the fake Artifactory stops responding.
		stall     func(w http.ResponseWriter, r *http.Request)
		wantCalls int32
	}{
		{
			name:      "verify when Artifactory never sends headers then the request times out and is retried",
			stall:     func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() },
			wantCalls: vcsHTTPRetries + 1,
		},
		{
			// A 200 has already been received, so nothing is retried; the read of the body fails.
			name: "verify when Artifactory stalls mid-body then reading the archive times out",
			stall: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "partial")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			},
			wantCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := vcsHTTPRequestTimeout
			vcsHTTPRequestTimeout = 200 * time.Millisecond
			t.Cleanup(func() { vcsHTTPRequestTimeout = original })
			var calls atomic.Int32
			client := newTestVCSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				tt.stall(w, r)
			}))

			body, _, err := client.Download(testRepoKey, "actions", "checkout", ResolvedRef{Kind: RefKindTag, APIRef: "v4"})
			if err == nil {
				_, err = io.ReadAll(body)
				closeResponseBody(body)
			}

			require.Error(t, err, "Download() of a stalled response must fail, not hang")
			assert.Equal(t, tt.wantCalls, calls.Load(), "Download() request count")
		})
	}
}
