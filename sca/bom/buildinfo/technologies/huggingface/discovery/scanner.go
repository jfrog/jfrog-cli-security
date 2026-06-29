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
	".git":         {},
	".hg":          {},
	"node_modules": {},
	"__pycache__":  {},
	".venv":        {},
	"venv":         {},
	"env":          {},
	".env":         {},
	"site-packages": {},
	".tox":         {},
	"dist":         {},
	"build":        {},
	".eggs":        {},
}

// ScanDir walks root recursively and discovers all Hugging Face model/dataset
// references in *.py files and *.ipynb notebooks.
// It returns a deduplicated ScanResult with the warning block pre-formatted.
func ScanDir(root string) (*ScanResult, error) {
	var allDiscovered []DiscoveredModel
	var allUnresolved []UnresolvedSite

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Debug(fmt.Sprintf("huggingface scanner: skipping %s: %v", path, err))
			return nil
		}
		if d.IsDir() {
			if _, skip := defaultExcludeDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".py":
			disc, unres, ferr := scanPyFile(path, root)
			if ferr != nil {
				log.Debug(fmt.Sprintf("huggingface scanner: skipping %s: %v", path, ferr))
				return nil
			}
			allDiscovered = append(allDiscovered, disc...)
			allUnresolved = append(allUnresolved, unres...)
		case ".ipynb":
			disc, unres, ferr := ParseNotebook(path)
			if ferr != nil {
				log.Debug(fmt.Sprintf("huggingface scanner: skipping notebook %s: %v", path, ferr))
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

	return &ScanResult{
		Discovered: dedup(allDiscovered),
		Unresolved: allUnresolved,
	}, nil
}

// FormatWarnings returns the consolidated warning block for unresolved sites,
// or an empty string when there are none.
func FormatWarnings(unresolved []UnresolvedSite) string {
	if len(unresolved) == 0 {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "WARN: %d Hugging Face reference(s) could not be statically resolved and were NOT audited:\n", len(unresolved))
	for _, u := range unresolved {
		fmt.Fprintf(&sb, "  %s:%d\t%s\t— %s\n", u.Location.File, u.Location.Line, u.Snippet, u.Reason)
	}
	sb.WriteString("These references resolve their model id or revision at runtime, so they cannot be checked statically.\n")
	sb.WriteString("To audit them, re-run with --hugging-face-model=<model-id>:<revision> (comma-separate multiple models; pin the revision you ship).")
	return sb.String()
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
	disc, unres := ParsePythonSource(string(data), rel, nil)
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
