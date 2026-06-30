package huggingface

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/huggingface/discovery"
	"github.com/jfrog/jfrog-cli-security/utils/artifactory"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

// HuggingFacePackagePrefix is the node-id prefix used for Hugging Face model/dataset references.
const HuggingFacePackagePrefix = "huggingfaceml://"

// DefaultRevision re-exports discovery.DefaultRevision (single source of truth).
const DefaultRevision = discovery.DefaultRevision

// hfEndpointEnv is the env var the Hugging Face client uses to point at the Artifactory
// proxy, e.g. "https://my.jfrog.io/artifactory/api/huggingfaceml/my-hugging-face-repo".
const hfEndpointEnv = "HF_ENDPOINT"

// hfEndpointRepoMarker precedes the Artifactory repository name in HF_ENDPOINT.
const hfEndpointRepoMarker = "api/huggingfaceml/"

// ModelInfo holds the parsed components of a --hugging-face-model flag value
// ("<repo-id>[:<revision>]"). The Artifactory repository is derived from HF_ENDPOINT.
type ModelInfo struct {
	RepoID   string
	Revision string
}

// modelNodeID builds the graph node id for a model reference. Shared by both the
// explicit --hugging-face-model path and the auto-discovery path.
func modelNodeID(repoID, revision string) string {
	return HuggingFacePackagePrefix + repoID + ":" + revision
}

// SplitRepoIDAndRevision splits "<repo-id>[:<revision>]" on the last ':'.
//
// Revisions can contain '/' (e.g. "refs/pr/3"), so the split isn't slash-guarded,
// or such revisions get glued onto repoID and 404 on probe.
//
// No ':' in raw: revision is "" and repoID is raw unchanged. Trailing ':' (e.g.
// "org/model:") also yields revision == "" — callers apply their own default.
func SplitRepoIDAndRevision(raw string) (repoID, revision string) {
	if idx := strings.LastIndex(raw, ":"); idx >= 0 {
		return raw[:idx], raw[idx+1:]
	}
	return raw, ""
}

// ParseModelReference parses "<repo-id>[:<revision>]" into a ModelInfo.
// Revision defaults to "main" when not specified.
func ParseModelReference(modelRef string) (*ModelInfo, error) {
	modelRef = strings.TrimSpace(strings.TrimPrefix(modelRef, HuggingFacePackagePrefix))
	if modelRef == "" {
		return nil, fmt.Errorf("hugging face model reference is empty")
	}

	originalRef := modelRef
	repoID, revision := SplitRepoIDAndRevision(modelRef)
	if repoID == "" {
		return nil, fmt.Errorf("invalid hugging face model reference %q: missing repo id; expected '<repo-id>[:<revision>]' (revision defaults to 'main'), comma-separated for multiple (e.g. 'mcpotato/42-eicar-street:main,bert-base-uncased')", originalRef)
	}
	if revision == "" {
		revision = DefaultRevision
	}
	info := &ModelInfo{RepoID: repoID, Revision: revision}

	log.Debug(fmt.Sprintf("Parsed Hugging Face model - RepoID: %s, Revision: %s", info.RepoID, info.Revision))
	return info, nil
}

// ParseModelReferences parses a comma-separated list of "<repo-id>[:<revision>]" entries.
func ParseModelReferences(modelRefs string) ([]*ModelInfo, error) {
	var infos []*ModelInfo
	for _, ref := range strings.Split(modelRefs, ",") {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		info, err := ParseModelReference(ref)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("hugging face model reference is empty")
	}
	return infos, nil
}

// repoFromHFEndpoint extracts the Artifactory repository name from the HF_ENDPOINT env var.
// HF_ENDPOINT looks like ".../artifactory/api/huggingfaceml/<repo>"; we return "<repo>".
func repoFromHFEndpoint() (string, error) {
	endpoint := strings.TrimSpace(os.Getenv(hfEndpointEnv))
	if endpoint == "" {
		return "", fmt.Errorf("%s is not set. Export it to your Artifactory Hugging Face repository, e.g. '%s=https://<server>/artifactory/%s<repo>'",
			hfEndpointEnv, hfEndpointEnv, hfEndpointRepoMarker)
	}
	idx := strings.Index(endpoint, hfEndpointRepoMarker)
	if idx < 0 {
		return "", fmt.Errorf("%s ('%s') does not contain '%s'; cannot determine the Artifactory repository", hfEndpointEnv, endpoint, hfEndpointRepoMarker)
	}
	// The repository is the first path segment after the marker (ignore any trailing path/query).
	repo := strings.Trim(endpoint[idx+len(hfEndpointRepoMarker):], "/")
	if before, _, found := strings.Cut(repo, "/"); found {
		repo = before
	}
	if before, _, found := strings.Cut(repo, "?"); found {
		repo = before
	}
	if repo == "" {
		return "", fmt.Errorf("%s ('%s') has no repository segment after '%s'", hfEndpointEnv, endpoint, hfEndpointRepoMarker)
	}
	return repo, nil
}

// BuildDependencyTree builds the HF dependency graph.
// If --hugging-face-model is set it audits only those models (spot-check, no source scan).
// Otherwise it auto-discovers model references in Python source and notebooks.
func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (trees []*xrayUtils.GraphNode, uniqueIDs []string, warnings []string, err error) {
	workingDir := params.WorkingDirectory
	if workingDir == "" {
		workingDir = "."
	}

	var children []*xrayUtils.GraphNode
	seen := map[string]bool{}
	add := func(nodeID string) {
		if seen[nodeID] {
			return
		}
		seen[nodeID] = true
		children = append(children, &xrayUtils.GraphNode{Id: nodeID})
		uniqueIDs = append(uniqueIDs, nodeID)
	}

	if params.HuggingFaceModel != "" {
		models, perr := ParseModelReferences(params.HuggingFaceModel)
		if perr != nil {
			return nil, nil, nil, perr
		}
		for _, m := range models {
			add(modelNodeID(m.RepoID, m.Revision))
		}
		if len(children) == 0 {
			return nil, nil, nil, nil
		}
		root := &xrayUtils.GraphNode{Id: rootNodeName(params), Nodes: children}
		return []*xrayUtils.GraphNode{root}, uniqueIDs, nil, nil
	}

	// 2) Auto-discovery mode: scan Python source / notebooks in the working dir.
	log.Debug(fmt.Sprintf("Hugging Face: scanning %s for model references", workingDir))
	result, serr := discovery.ScanDir(workingDir)
	if serr != nil {
		return nil, nil, nil, fmt.Errorf("hugging face source scan failed: %w", serr)
	}
	if warn := discovery.FormatWarnings(result.Unresolved); warn != "" {
		warnings = append(warnings, warn)
	}
	// Datasets are detected but not audited — Catalog does not score datasets.
	if warn := discovery.FormatDatasetWarning(result.Datasets); warn != "" {
		warnings = append(warnings, warn)
	}
	// Unreadable/unparsable files mean the scan is partial — surface this to the
	// user rather than silently reporting complete coverage (debug log only).
	if warn := discovery.FormatSkippedFilesWarning(result.Skipped); warn != "" {
		warnings = append(warnings, warn)
	}
	for _, m := range result.Discovered {
		nodeID := modelNodeID(m.RepoID, m.Revision)
		if m.RevisionDefaulted {
			log.Info(fmt.Sprintf("Hugging Face: %s has no pinned revision — auditing against current HEAD of '%s'", m.RepoID, m.Revision))
		}
		if m.RevisionDynamic {
			warnings = append(warnings, fmt.Sprintf("Hugging Face: %s has a dynamic revision in source — audited against '%s' (may not match the revision resolved at runtime)", m.RepoID, m.Revision))
		}
		add(nodeID)
	}

	if len(children) == 0 {
		log.Debug("Hugging Face: no model references found (flag or source)")
		return nil, nil, warnings, nil
	}

	// Flat graph: one root node whose children are the unique model/dataset refs.
	root := &xrayUtils.GraphNode{Id: rootNodeName(params), Nodes: children}
	return []*xrayUtils.GraphNode{root}, uniqueIDs, warnings, nil
}

// rootNodeName returns the synthetic root node ID for the HF dependency graph.
// Prefers params.HFProjectName (set via DisambiguateRootNodeNames for multiple
// --working-dirs); falls back to the working directory basename.
func rootNodeName(params technologies.BuildInfoBomGeneratorParams) string {
	if params.HFProjectName != "" {
		return params.HFProjectName
	}
	dir := params.WorkingDirectory
	if dir == "" || dir == "." {
		if cwd, err := os.Getwd(); err == nil {
			dir = cwd
		}
	}
	if name := filepath.Base(dir); name != "" && name != "." && name != "/" {
		return name
	}
	return "huggingface-project"
}

// DisambiguateRootNodeNames maps each working directory to a unique project name,
// even when directories share a basename (e.g. two "model" dirs under different
// parents). Basenames are used when unique; collisions fall back to "parent/base",
// then the full absolute path.
func DisambiguateRootNodeNames(workingDirs []string) map[string]string {
	seen := map[string]bool{}
	var abs []string
	for _, wd := range workingDirs {
		a := wd
		if resolved, err := filepath.Abs(wd); err == nil {
			a = resolved
		}
		if !seen[a] {
			seen[a] = true
			abs = append(abs, a)
		}
	}

	names := make(map[string]string, len(abs))
	// assign names paths whose candidate name is unique; returns the rest for the next tier.
	assign := func(nameOf func(string) string) (remaining []string) {
		counts := map[string]int{}
		candidate := map[string]string{}
		for _, p := range abs {
			n := nameOf(p)
			candidate[p] = n
			counts[n]++
		}
		for p, n := range candidate {
			if counts[n] == 1 {
				names[p] = n
			} else {
				remaining = append(remaining, p)
			}
		}
		return
	}

	remaining := assign(func(p string) string {
		if name := filepath.Base(p); name != "" && name != "." && name != "/" {
			return name
		}
		return "huggingface-project"
	})
	if len(remaining) == 0 {
		return names
	}

	abs = remaining
	remaining = assign(func(p string) string {
		return filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)
	})
	if len(remaining) == 0 {
		return names
	}

	// Last resort: the full absolute path.
	for _, p := range remaining {
		names[p] = p
	}
	return names
}

// GetHuggingFaceRepositoryConfig resolves the Artifactory repository from HF_ENDPOINT
// and verifies it exists on serverDetails (mirrors docker.GetDockerRepositoryConfig).
//
// serverDetails must be the server already resolved for this command (respects
// --server-id) — it is NOT re-resolved here. HF_ENDPOINT's host is validated against
// it so a stale HF_ENDPOINT can't silently probe the wrong Artifactory instance.
func GetHuggingFaceRepositoryConfig(serverDetails *config.ServerDetails) (*project.RepositoryConfig, error) {
	if serverDetails == nil {
		return nil, fmt.Errorf("no Artifactory server configured. Use 'jf c add' to configure a server")
	}
	repo, err := repoFromHFEndpoint()
	if err != nil {
		return nil, err
	}
	if err = validateHFEndpointHost(serverDetails); err != nil {
		return nil, err
	}
	exists, err := artifactory.IsRepoExists(repo, serverDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to check if repository '%s' exists on Artifactory '%s': %w", repo, serverDetails.Url, err)
	}
	if !exists {
		return nil, fmt.Errorf("repository '%s' (from %s) was not found on Artifactory (%s), ensure the repository exists", repo, hfEndpointEnv, serverDetails.Url)
	}

	repoConfig := &project.RepositoryConfig{}
	repoConfig.SetServerDetails(serverDetails).SetTargetRepo(repo)
	return repoConfig, nil
}

// validateHFEndpointHost ensures HF_ENDPOINT points at the same Artifactory host as
// serverDetails. Only the host is compared — path/scheme differences are tolerated.
func validateHFEndpointHost(serverDetails *config.ServerDetails) error {
	endpoint := strings.TrimSpace(os.Getenv(hfEndpointEnv))
	endpointHost, err := hostOf(endpoint)
	if err != nil {
		return fmt.Errorf("%s ('%s') is not a valid URL: %w", hfEndpointEnv, endpoint, err)
	}
	serverURL := serverDetails.GetArtifactoryUrl()
	serverHost, err := hostOf(serverURL)
	if err != nil {
		return fmt.Errorf("failed to parse the configured Artifactory URL '%s': %w", serverURL, err)
	}
	if !strings.EqualFold(endpointHost, serverHost) {
		return fmt.Errorf("%s ('%s') points at '%s', but the selected Artifactory server ('%s') is '%s'; "+
			"export %s for the same server you're auditing against (or pass the matching --server-id)",
			hfEndpointEnv, endpoint, endpointHost, serverDetails.ServerId, serverHost, hfEndpointEnv)
	}
	return nil
}

// hostOf parses rawURL and returns its host[:port], erroring if it has none.
// The port is omitted when it's the scheme's default (443/80), so equivalent
// URLs don't false-mismatch in validateHFEndpointHost.
//
// A URL with no scheme (e.g. "my.jfrog.io/artifactory/...") parses without
// error but with an empty Host — url.Parse treats it as a relative path — so
// that specific case gets a more actionable message pointing at the missing
// scheme, rather than a bare "no host in URL".
func hostOf(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		if !strings.Contains(rawURL, "://") {
			return "", fmt.Errorf("no host found — missing a scheme (e.g. 'https://')")
		}
		return "", fmt.Errorf("no host in URL")
	}
	if port := parsed.Port(); port != "" && isDefaultPort(parsed.Scheme, port) {
		return parsed.Hostname(), nil
	}
	return parsed.Host, nil
}

// isDefaultPort reports whether port is the well-known default for scheme.
func isDefaultPort(scheme, port string) bool {
	switch strings.ToLower(scheme) {
	case "http":
		return port == "80"
	case "https":
		return port == "443"
	default:
		return false
	}
}
