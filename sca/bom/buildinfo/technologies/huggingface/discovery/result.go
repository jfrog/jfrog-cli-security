package discovery

// DefaultRevision is the fallback revision when none is pinned in source,
// mirroring the Hugging Face client's default behaviour.
const DefaultRevision = "main"

// RepoType distinguishes HF model repos from dataset repos. Only models are
// audited; datasets are detected and reported but not curated (see RepoTypeDataset).
type RepoType string

const (
	RepoTypeModel   RepoType = "model"
	RepoTypeDataset RepoType = "dataset"
)

// Location identifies a specific line in a source file.
// For Jupyter notebooks the File is "notebook.ipynb#cell-<n>" and Line is
// relative to the start of that cell.
type Location struct {
	File string
	Line int // 1-based
}

// DiscoveredModel is a fully or partially resolved HF reference extracted from source.
type DiscoveredModel struct {
	RepoID string
	// Revision is the pinned branch/tag/sha, or DefaultRevision when absent in source.
	Revision string
	// RevisionDefaulted is true when no revision was present in the call —
	// the audit targets whatever commit the branch currently points to.
	RevisionDefaulted bool
	// RevisionDynamic is true when a revision arg was present but non-literal.
	// The model is still audited against DefaultRevision with a warning.
	RevisionDynamic bool
	RepoType        RepoType
	// Sources lists every call site that produced this reference (after dedup).
	Sources []Location
}

// UnresolvedSite records a call site whose repo_id could not be statically resolved.
// These are NOT audited; they are surfaced in the warning block so the user can
// pass them explicitly via --hugging-face-model.
type UnresolvedSite struct {
	Location Location
	// Snippet shows the call's arguments; quoted content is redacted as
	// <redacted> since it may embed a secret and this text goes to CI logs.
	Snippet string
	// Reason is one of "non-literal repo_id", "f-string repo_id",
	// "dynamic repo_id", "local filesystem path",
	// "ambiguous local path or Hub repo id", "non-literal repo_type",
	// "f-string repo_type", or "unsupported repo_type".
	Reason string
}

// SkippedFile records a source file/entry that could not be read or parsed
// during the scan — any HF references it held were not discovered.
type SkippedFile struct {
	Path string
	Err  string
}

// ScanResult is the output of a full directory scan.
type ScanResult struct {
	// Discovered holds deduplicated model (repo_type == model) tuples ready to
	// hand to the curation walker.
	Discovered []DiscoveredModel
	// Datasets holds deduplicated dataset references. These are reported but NOT
	// audited: Catalog does not score datasets, so curation cannot evaluate them.
	Datasets []DiscoveredModel
	// Unresolved holds call sites that could not be statically resolved.
	Unresolved []UnresolvedSite
	// Skipped holds files/entries that could not be read or parsed. Non-empty
	// means the scan is partial.
	Skipped []SkippedFile
}
