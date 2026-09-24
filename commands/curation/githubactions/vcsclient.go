package githubactions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/sync/singleflight"
)

const (
	// One retry, spaced out, for a transient failure. Kept low on purpose: runners bill by the
	// minute, and a throttling Artifactory is better met by lowering --threads than by retrying
	// harder. Retried here rather than by the client, whose wait is fixed: a random jitter keeps
	// the --threads decisions that failed together from all retrying at the same instant.
	vcsHTTPRetries        = 1
	vcsHTTPRetryWait      = 300 * time.Millisecond
	vcsHTTPRetryMaxJitter = 200 * time.Millisecond
	vcsArchiveExtension   = "tar.gz"

	headerArtifactoryFilename = "X-Artifactory-Filename"
	headerContentDisposition  = "Content-Disposition"
)

// vcsHTTPRequestTimeout bounds each request end to end, body included, so a stalled Artifactory
// fails the action fast rather than holding the runner - billed by the minute - until the job's
// own timeout. A variable so a test can shorten it.
var vcsHTTPRequestTimeout = time.Minute

// ErrAccessDenied is wrapped when Artifactory refuses the configured credentials: a 401 from any
// VCS API, or a 403 from getRefs. Every call in a run uses the same credentials and the same
// VCS repository, so every later call would be refused too - callers stop the run on it.
//
// A 403 from a download API is not this: that is a curation block on one action, a BlockedError.
var ErrAccessDenied = errors.New("access denied by Artifactory")

// BlockedError is a download refused by curation policy, with Artifactory's reason.
type BlockedError struct {
	Reason string
}

func (e *BlockedError) Error() string {
	return "blocked by curation policy: " + e.Reason
}

// blockedReasonUnparsable stands in when a download 403's body is not the errors envelope. The
// 403 itself is authoritative, so the action is still recorded as blocked.
const blockedReasonUnparsable = "blocked by curation (the response could not be parsed)"

// artifactoryErrors is Artifactory's error envelope: {"errors":[{"status":403,"message":"..."}]}.
type artifactoryErrors struct {
	Errors []struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
	} `json:"errors"`
}

// vcsClient calls the Artifactory VCS APIs this command needs: getRefs, and the three tarball
// downloads. It is safe for concurrent use.
type vcsClient struct {
	client  *jfroghttpclient.JfrogHttpClient
	details httputils.HttpClientDetails
	// apiURL is "<artifactory>/api/vcs/", with the trailing slash.
	apiURL string

	refsFlight singleflight.Group
	refsMu     sync.Mutex
	refs       map[string]*RefAdvertisement
}

func newVCSClient(serverDetails *config.ServerDetails) (*vcsClient, error) {
	// The client must not retry: get does the one retry (vcsHTTPRetries), with jitter, and client
	// retries would stack on top of it.
	manager, err := rtUtils.CreateServiceManagerWithContext(context.Background(), serverDetails, false, 0, 0, 0, vcsHTTPRequestTimeout)
	if err != nil {
		return nil, fmt.Errorf("creating the Artifactory client: %w", err)
	}
	// The manager's own auth config, so the credentials and the client's token-refresh
	// interceptors come from one source.
	auth := manager.GetConfig().GetServiceDetails()
	baseURL := auth.GetUrl()
	if baseURL == "" {
		return nil, errors.New("the configured JFrog server has no Artifactory URL")
	}
	return &vcsClient{
		client:  manager.Client(),
		details: auth.CreateHttpClientDetails(),
		apiURL:  strings.TrimSuffix(baseURL, "/") + "/api/vcs/",
		refs:    map[string]*RefAdvertisement{},
	}, nil
}

// GetRefs returns the ref advertisement of owner/repo through the VCS repository repoKey.
//
// One advertisement serves every ref of a repository, so it is fetched once per run: concurrent
// callers for the same repository share one in-flight request, and later ones read the cache.
// A failure is not cached.
func (c *vcsClient) GetRefs(repoKey, owner, repo string) (*RefAdvertisement, error) {
	key := repoKey + "/" + owner + "/" + repo
	if adv, ok := c.cachedRefs(key); ok {
		return adv, nil
	}
	v, err, _ := c.refsFlight.Do(key, func() (any, error) {
		// Re-checked inside the flight: a caller that missed the cache just as another flight
		// finished would otherwise start a second request for the same repository.
		if adv, ok := c.cachedRefs(key); ok {
			return adv, nil
		}
		adv, err := c.fetchRefs(repoKey, owner, repo)
		if err != nil {
			return nil, err
		}
		c.refsMu.Lock()
		c.refs[key] = adv
		c.refsMu.Unlock()
		return adv, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*RefAdvertisement), nil
}

func (c *vcsClient) cachedRefs(key string) (*RefAdvertisement, bool) {
	c.refsMu.Lock()
	defer c.refsMu.Unlock()
	adv, ok := c.refs[key]
	return adv, ok
}

func (c *vcsClient) fetchRefs(repoKey, owner, repo string) (*RefAdvertisement, error) {
	endpoint := c.repoEndpoint("refs", repoKey, owner, repo)
	body, resp, err := c.get(endpoint)
	if err != nil {
		return nil, err
	}
	defer closeResponseBody(body)
	switch resp.StatusCode {
	case http.StatusOK:
		// Accepted on status alone: getRefs declares application/json for a pkt-line body.
		adv, err := ParseGitRefs(body)
		if err != nil {
			return nil, fmt.Errorf("parsing git refs from %s: %w", endpoint, err)
		}
		return adv, nil
	case http.StatusUnauthorized:
		return nil, errUnauthorized(endpoint)
	case http.StatusForbidden:
		// getRefs has no curation flow behind it, so a 403 here is a permission problem.
		return nil, fmt.Errorf("%w: %s returned 403 Forbidden - the configured JFrog server's credentials "+
			"are not permitted to read VCS repository %q. This is an access problem, not a curation block",
			ErrAccessDenied, endpoint, repoKey)
	}
	return nil, errUnexpectedStatus(endpoint, resp, body)
}

// Download fetches the tar.gz archive for ref and returns its body, which the caller must close,
// and the archive filename Artifactory reports - where the resolved SHA is read from, see
// ExtractResolvedSHA. The filename is "" when the response names none.
//
// A curation block is returned as a *BlockedError.
func (c *vcsClient) Download(repoKey, owner, repo string, ref ResolvedRef) (io.ReadCloser, string, error) {
	api, err := downloadAPI(ref.Kind)
	if err != nil {
		return nil, "", err
	}
	// ext is explicit: GitHub Enterprise remotes default to zip, and the override unpacks tar.gz.
	endpoint := c.repoEndpoint(api, repoKey, owner, repo) + "/" + escapeRefPath(ref.APIRef) + "?ext=" + vcsArchiveExtension
	body, resp, err := c.get(endpoint)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode == http.StatusOK {
		return body, archiveFilename(resp.Header), nil
	}
	defer closeResponseBody(body)
	switch resp.StatusCode {
	case http.StatusForbidden:
		return nil, "", &BlockedError{Reason: blockedReason(body)}
	case http.StatusUnauthorized:
		return nil, "", errUnauthorized(endpoint)
	}
	return nil, "", errUnexpectedStatus(endpoint, resp, body)
}

// get sends a GET and returns the response body left open for streaming, whatever the status. A
// transport error, a 5xx or a 429 is retried vcsHTTPRetries times after a jittered wait.
func (c *vcsClient) get(endpoint string) (io.ReadCloser, *http.Response, error) {
	for attempt := 0; ; attempt++ {
		body, resp, err := c.getOnce(endpoint)
		if attempt == vcsHTTPRetries || !retryable(resp, err) {
			return body, resp, err
		}
		if body != nil {
			closeResponseBody(body)
		}
		wait := vcsHTTPRetryWait + rand.N(vcsHTTPRetryMaxJitter)
		log.Debug(fmt.Sprintf("github-actions curation: retrying GET %s in %s", endpoint, wait))
		time.Sleep(wait)
	}
}

// retryable reports whether a GET failed in a way worth one more attempt.
func retryable(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	return resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests
}

func (c *vcsClient) getOnce(endpoint string) (io.ReadCloser, *http.Response, error) {
	// Cloned per request: pre-request interceptors may rewrite the headers, and the client is
	// shared across goroutines.
	details := c.details.Clone()
	body, resp, err := c.client.ReadRemoteFile(endpoint, details)
	if err != nil {
		return nil, nil, fmt.Errorf("sending GET %s: %w", endpoint, err)
	}
	if resp == nil {
		return nil, nil, fmt.Errorf("GET %s returned no response", endpoint)
	}
	if body == nil {
		// Off a 200 the client hands back the response alone, with its body still open.
		body = resp.Body
	}
	return body, resp, nil
}

// repoEndpoint is "<api>/<repoKey>/<owner>/<repo>" under the VCS API, each part escaped as a
// single path segment.
func (c *vcsClient) repoEndpoint(api, repoKey, owner, repo string) string {
	return c.apiURL + api + "/" + url.PathEscape(repoKey) + "/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}

// escapeRefPath escapes a ref for the URL path while keeping its own slashes as separators: a
// branch like releases/v4 must reach Artifactory as two segments, and %2F-encoding it 404s.
func escapeRefPath(ref string) string {
	parts := strings.Split(ref, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func downloadAPI(kind RefKind) (string, error) {
	switch kind {
	case RefKindTag:
		return "downloadTag", nil
	case RefKindBranch:
		return "downloadBranch", nil
	case RefKindCommit:
		return "downloadCommit", nil
	}
	return "", fmt.Errorf("no download API for ref kind %s", kind)
}

// archiveFilename reads the archive's name from X-Artifactory-Filename, falling back to
// Content-Disposition's filename.
func archiveFilename(header http.Header) string {
	if name := header.Get(headerArtifactoryFilename); name != "" {
		return name
	}
	if _, params, err := mime.ParseMediaType(header.Get(headerContentDisposition)); err == nil {
		return params["filename"]
	}
	return ""
}

// blockedReason takes a download 403's reason from the errors envelope's first message.
func blockedReason(body io.Reader) string {
	raw, err := io.ReadAll(body)
	if err != nil {
		return blockedReasonUnparsable
	}
	if message := firstErrorMessage(raw); message != "" {
		return message
	}
	return blockedReasonUnparsable
}

func errUnauthorized(endpoint string) error {
	return fmt.Errorf("%w: %s returned 401 Unauthorized - the credentials of the configured JFrog server were rejected",
		ErrAccessDenied, endpoint)
}

// errUnexpectedStatus names the status and, when the body is the errors envelope, its message.
func errUnexpectedStatus(endpoint string, resp *http.Response, body io.Reader) error {
	statusErr := fmt.Errorf("%s returned %s", endpoint, resp.Status)
	raw, err := io.ReadAll(body)
	if err != nil {
		// The status is the failure; an unreadable body only costs the detail.
		return errors.Join(statusErr, fmt.Errorf("reading the error response: %w", err))
	}
	if message := firstErrorMessage(raw); message != "" {
		return fmt.Errorf("%w: %s", statusErr, message)
	}
	return statusErr
}

// firstErrorMessage returns the first message of Artifactory's errors envelope, or "" when raw
// is not one.
func firstErrorMessage(raw []byte) string {
	var envelope artifactoryErrors
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Errors) == 0 {
		return ""
	}
	return envelope.Errors[0].Message
}

// closeResponseBody closes a response body the caller has finished with. Its error cannot change
// the outcome - the body has been read, or deliberately abandoned - so it is logged, not returned.
func closeResponseBody(body io.Closer) {
	if err := body.Close(); err != nil {
		log.Debug(fmt.Sprintf("github-actions curation: closing an Artifactory response body: %v", err))
	}
}
