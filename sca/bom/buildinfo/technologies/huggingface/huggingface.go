package huggingface

import (
	"fmt"
	"os"
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

// DatasetNodeMarker is inserted immediately after HuggingFacePackagePrefix in a node id
// to mark the reference as a dataset. Datasets are probed via the api/datasets/ endpoint
// rather than api/models/. The '|' separator cannot appear in a HF repo id or revision,
// so it round-trips cleanly through getHuggingFaceNameAndVersion.
const DatasetNodeMarker = "dataset|"

// DefaultRevision is used when the model reference does not pin an explicit revision.
const DefaultRevision = "main"

// hfEndpointEnv is the env var the Hugging Face client uses to point at the Artifactory
// proxy, e.g. "https://my.jfrog.io/artifactory/api/huggingfaceml/my-hugging-face-repo".
const hfEndpointEnv = "HF_ENDPOINT"

// hfEndpointRepoMarker precedes the Artifactory repository name in HF_ENDPOINT.
const hfEndpointRepoMarker = "api/huggingfaceml/"

// ModelInfo holds the parsed components of a --hugging-face-model reference.
//
// The flag value is the Hugging Face model/dataset id with an optional revision:
// "<org>/<model>[:<revision>]" e.g. "mcpotato/42-eicar-street:main".
//   - RepoId   = "mcpotato/42-eicar-street" (the Hugging Face model/dataset id)
//   - Revision = "main" (branch, tag, or 40-char commit sha; defaults to "main")
//
// The Artifactory repository is NOT part of the flag — it is read from the HF_ENDPOINT
// environment variable (the same one the HF client uses to resolve through the proxy).
type ModelInfo struct {
	RepoId   string
	Revision string
}

// ParseModelReference parses a --hugging-face-model value ("<org>/<model>[:<revision>]")
// into the model id and revision. The revision defaults to "main" when not pinned,
// mirroring the Hugging Face client's snapshot_download(..., revision="main").
func ParseModelReference(modelRef string) (*ModelInfo, error) {
	modelRef = strings.TrimSpace(strings.TrimPrefix(modelRef, HuggingFacePackagePrefix))
	if modelRef == "" {
		return nil, fmt.Errorf("hugging face model reference is empty")
	}

	info := &ModelInfo{Revision: DefaultRevision}

	// Split off the optional revision. A revision never contains '/', so only treat a
	// trailing ":<suffix>" as a revision when the suffix has no path separator.
	if idx := strings.LastIndex(modelRef, ":"); idx > 0 && !strings.Contains(modelRef[idx+1:], "/") {
		info.Revision = modelRef[idx+1:]
		modelRef = modelRef[:idx]
	}

	if modelRef == "" {
		return nil, fmt.Errorf("invalid hugging face model reference: expected '<org>/<model>[:<revision>]'")
	}
	info.RepoId = modelRef

	log.Debug(fmt.Sprintf("Parsed Hugging Face model - RepoId: %s, Revision: %s", info.RepoId, info.Revision))
	return info, nil
}

// ParseModelReferences parses a comma-separated list of --hugging-face-model values
// ("<model-id>:<revision>,<model-id>:<revision>,...") into individual ModelInfo entries.
// Whitespace around each entry is trimmed and empty entries are skipped, so trailing
// commas and accidental spaces are tolerated.
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

// BuildDependencyTree builds the dependency graph for Hugging Face models/datasets.
//
// Two modes:
//  1. Flag mode (--hugging-face-model set): pure spot-check — audits only the
//     explicitly named models (comma-separated), skips source scanning entirely.
//     Fast and unambiguous: you get exactly what you asked for.
//  2. Auto-discovery mode (no flag): scans Python source and notebooks in the
//     working directory for from_pretrained / snapshot_download / load_dataset /
//     hf_hub_download call sites. Unresolved (dynamic) call sites are returned as
//     warnings for the caller to surface after the curation tables.
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

	// 1) Explicit models from the --hugging-face-model flag (comma-separated).
	// Flag mode is a pure spot-check: only the named models are audited, the source
	// scanner is skipped entirely so the result is fast and unambiguous.
	if params.HuggingFaceModel != "" {
		models, perr := ParseModelReferences(params.HuggingFaceModel)
		if perr != nil {
			return nil, nil, nil, perr
		}
		for _, m := range models {
			add(HuggingFacePackagePrefix + m.RepoId + ":" + m.Revision)
		}
		if len(children) == 0 {
			return nil, nil, nil, nil
		}
		root := &xrayUtils.GraphNode{Id: "huggingface-project", Nodes: children}
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
	for _, m := range result.Discovered {
		nodeID := HuggingFacePackagePrefix + m.RepoID + ":" + m.Revision
		if m.RepoType == discovery.RepoTypeDataset {
			nodeID = HuggingFacePackagePrefix + DatasetNodeMarker + m.RepoID + ":" + m.Revision
		}
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
	root := &xrayUtils.GraphNode{Id: "huggingface-project", Nodes: children}
	return []*xrayUtils.GraphNode{root}, uniqueIDs, warnings, nil
}

// GetHuggingFaceRepositoryConfig resolves the Artifactory repository from HF_ENDPOINT
// and verifies it exists, mirroring docker.GetDockerRepositoryConfig.
func GetHuggingFaceRepositoryConfig() (*project.RepositoryConfig, error) {
	serverDetails, err := config.GetDefaultServerConf()
	if err != nil {
		return nil, err
	}
	if serverDetails == nil {
		return nil, fmt.Errorf("no Artifactory server configured. Use 'jf c add' to configure a server")
	}
	repo, err := repoFromHFEndpoint()
	if err != nil {
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
