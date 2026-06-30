package discovery

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// defaultExcludeDirs are directory names skipped during the walk.
// These mirror the exclusion list used by other jf ca BOM builders.
var defaultExcludeDirs = map[string]struct{}{
	".git":          {},
	".hg":           {},
	"node_modules":  {},
	"__pycache__":   {},
	".venv":         {},
	"venv":          {},
	"env":           {},
	".env":          {},
	"site-packages": {},
	".tox":          {},
	"dist":          {},
	"build":         {},
	".eggs":         {},
	// Jupyter's autosave copies — scanning them would double-report or surface stale
	// (already-edited-away) model references from the checkpointed version.
	".ipynb_checkpoints": {},
}

// IsExcludedWalkDir reports whether a directory basename should be skipped when
// scanning for Python/Hugging Face sources (venv artifacts, build outputs, etc.).
func IsExcludedWalkDir(name string) bool {
	_, skip := defaultExcludeDirs[name]
	return skip
}

// maxScannableFileSize caps how large a single .py/.ipynb file can be before it's
// skipped unread. Generous relative to real source files (even notebooks with
// embedded base64 image outputs rarely approach this) — it exists to guard against
// a pathologically large or misnamed file being fully loaded into memory.
const maxScannableFileSize = 10 * 1024 * 1024 // 10 MiB

// ScanDir walks root recursively and discovers all Hugging Face model/dataset
// references in *.py files and *.ipynb notebooks.
// It returns a deduplicated ScanResult with the warning block pre-formatted.
func ScanDir(root string) (*ScanResult, error) {
	var allDiscovered []DiscoveredModel
	var allUnresolved []UnresolvedSite
	var skipped []SkippedFile

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Debug(fmt.Sprintf("huggingface scanner: skipping %s: %v", path, err))
			skipped = append(skipped, SkippedFile{Path: path, Err: err.Error()})
			return nil
		}
		if d.IsDir() {
			if IsExcludedWalkDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".py" && ext != ".ipynb" {
			log.Debug(fmt.Sprintf("huggingface scanner: skipping %s: unsupported extension", path))
			return nil
		}
		if info, infoErr := d.Info(); infoErr == nil && info.Size() > maxScannableFileSize {
			ferr := fmt.Errorf("file size %d bytes exceeds the %d byte scan limit", info.Size(), maxScannableFileSize)
			log.Debug(fmt.Sprintf("huggingface scanner: skipping %s: %v", path, ferr))
			skipped = append(skipped, SkippedFile{Path: path, Err: ferr.Error()})
			return nil
		}
		switch ext {
		case ".py":
			disc, unres, ferr := scanPyFile(path, root)
			if ferr != nil {
				log.Debug(fmt.Sprintf("huggingface scanner: skipping %s: %v", path, ferr))
				skipped = append(skipped, SkippedFile{Path: path, Err: ferr.Error()})
				return nil
			}
			allDiscovered = append(allDiscovered, disc...)
			allUnresolved = append(allUnresolved, unres...)
		case ".ipynb":
			disc, unres, ferr := ParseNotebook(path, root)
			if ferr != nil {
				log.Debug(fmt.Sprintf("huggingface scanner: skipping notebook %s: %v", path, ferr))
				skipped = append(skipped, SkippedFile{Path: path, Err: ferr.Error()})
				return nil
			}
			// Relativise notebook path for display.
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			for i := range disc {
				for j := range disc[i].Sources {
					disc[i].Sources[j].File = rebaseNotebook(disc[i].Sources[j].File, path, rel)
				}
			}
			for i := range unres {
				unres[i].Location.File = rebaseNotebook(unres[i].Location.File, path, rel)
			}
			allDiscovered = append(allDiscovered, disc...)
			allUnresolved = append(allUnresolved, unres...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("huggingface scanner: walking %s: %w", root, err)
	}

	// Split models from datasets: Catalog scores only models, so datasets are
	// reported (via FormatDatasetWarning) but never handed to the curation walker.
	var models, datasets []DiscoveredModel
	for _, m := range dedup(allDiscovered) {
		if m.RepoType == RepoTypeDataset {
			datasets = append(datasets, m)
		} else {
			models = append(models, m)
		}
	}

	for i := range skipped {
		// Falls back to the absolute path on error (e.g. different volume on Windows) —
		// still usable in the warning, just more verbose.
		if rel, relErr := filepath.Rel(root, skipped[i].Path); relErr == nil {
			skipped[i].Path = rel
		}
	}

	return &ScanResult{
		Discovered: models,
		Datasets:   datasets,
		Unresolved: allUnresolved,
		Skipped:    skipped,
	}, nil
}

// FormatWarnings returns the consolidated warning block for unresolved call sites,
// or an empty string if there are none.
func FormatWarnings(unresolved []UnresolvedSite) string {
	if len(unresolved) == 0 {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d Hugging Face reference(s) could not be statically resolved and were NOT audited:\n", len(unresolved))
	for _, u := range unresolved {
		fmt.Fprintf(&sb, "  %s:%d\t%s\t— %s\n", u.Location.File, u.Location.Line, u.Snippet, u.Reason)
	}
	sb.WriteString("These references could not be tied to a Hub repo id statically (runtime values or local filesystem paths), so they were not audited here.\n")
	sb.WriteString("A local path is typically a model fetched in an earlier step (e.g. via `jf hf download`), where curation is enforced at download time.\n")
	sb.WriteString("To audit them here, re-run with --hugging-face-model=<model-id>:<revision> (comma-separate multiple models; pin the revision you ship).")
	return sb.String()
}

// FormatDatasetWarning returns an advisory for detected dataset references, which
// are reported but not audited (Catalog does not score datasets). Empty when none.
func FormatDatasetWarning(datasets []DiscoveredModel) string {
	if len(datasets) == 0 {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d Hugging Face dataset reference(s) found but NOT audited — curation does not currently cover datasets (Catalog limitation). Only models are evaluated.\n", len(datasets))
	for _, d := range datasets {
		loc := ""
		if len(d.Sources) > 0 {
			loc = fmt.Sprintf("%s:%d\t", d.Sources[0].File, d.Sources[0].Line)
		}
		fmt.Fprintf(&sb, "  %s%s\n", loc, d.RepoID)
	}
	return strings.TrimRight(sb.String(), "\n")
}

// FormatSkippedFilesWarning returns a user-visible warning listing source files
// that could not be read or parsed (scan is partial). Empty when none were skipped.
func FormatSkippedFilesWarning(skipped []SkippedFile) string {
	if len(skipped) == 0 {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d source file(s) could not be scanned for Hugging Face references and were skipped — the scan results are PARTIAL:\n", len(skipped))
	for _, s := range skipped {
		fmt.Fprintf(&sb, "  %s — %s\n", s.Path, s.Err)
	}
	sb.WriteString("Any Hugging Face models/datasets referenced only in these files were not audited.")
	return strings.TrimRight(sb.String(), "\n")
}

// ---- internal helpers -----------------------------------------------------

func scanPyFile(path, root string) ([]DiscoveredModel, []UnresolvedSite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	disc, unres := ParsePythonSource(string(data), rel, nil, root)
	return disc, unres, nil
}

// rebaseNotebook replaces the absolute notebook path prefix with the relative one.
func rebaseNotebook(location, absPath, relPath string) string {
	return strings.Replace(location, absPath, relPath, 1)
}

// dedup collapses DiscoveredModel entries with the same (repo_type, repo_id, revision)
// into one, merging their Sources lists.
func dedup(models []DiscoveredModel) []DiscoveredModel {
	type key struct {
		repoType RepoType
		repoID   string
		revision string
	}
	index := map[key]int{}
	var result []DiscoveredModel
	for _, m := range models {
		k := key{m.RepoType, m.RepoID, m.Revision}
		if idx, exists := index[k]; exists {
			result[idx].Sources = append(result[idx].Sources, m.Sources...)
			// Propagate flags: if any reference lacked a revision, flag it.
			if m.RevisionDefaulted {
				result[idx].RevisionDefaulted = true
			}
			if m.RevisionDynamic {
				result[idx].RevisionDynamic = true
			}
		} else {
			index[k] = len(result)
			result = append(result, m)
		}
	}
	return result
}
