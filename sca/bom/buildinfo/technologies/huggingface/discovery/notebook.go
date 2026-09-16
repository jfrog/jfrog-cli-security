package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ipynbNotebook is the minimal structure we need from a .ipynb JSON file.
type ipynbNotebook struct {
	Cells []ipynbCell `json:"cells"`
}

type ipynbCell struct {
	CellType string `json:"cell_type"`
	// Source is either a []string (list of lines) or a single string, depending
	// on the nbformat version; json.RawMessage lets us handle both.
	Source json.RawMessage `json:"source"`
}

// ParseNotebook reads a .ipynb file and returns discovered/unresolved entries.
// Code cells are extracted and fed through the Python scanner. Cells that
// contain notebook magic commands (leading ! or %) are cleaned before parsing.
// root is an optional scan root, forwarded to ParsePythonSource for filesystem-backed
// classification of ambiguous local-output-path literals (see classifyRepoIDLiteral).
func ParseNotebook(path string, root ...string) (discovered []DiscoveredModel, unresolved []UnresolvedSite, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading notebook %s: %w", path, err)
	}
	return parseNotebookBytes(data, path, root...)
}

// parseNotebookBytes is the testable core of ParseNotebook.
func parseNotebookBytes(data []byte, filename string, root ...string) (discovered []DiscoveredModel, unresolved []UnresolvedSite, err error) {
	var nb ipynbNotebook
	if err = json.Unmarshal(data, &nb); err != nil {
		return nil, nil, fmt.Errorf("parsing notebook JSON %s: %w", filename, err)
	}

	for cellIdx, cell := range nb.Cells {
		if cell.CellType != "code" {
			continue
		}
		src, parseErr := cellSource(cell.Source)
		if parseErr != nil {
			// Malformed cell — skip rather than abort.
			continue
		}
		if strings.TrimSpace(src) == "" {
			continue
		}
		src = stripMagics(src)
		cellFile := fmt.Sprintf("%s#cell-%d", filename, cellIdx)
		d, u := ParsePythonSource(src, cellFile, nil, root...)
		discovered = append(discovered, d...)
		unresolved = append(unresolved, u...)
	}
	return
}

// cellSource decodes the source field which can be a JSON string or []string.
func cellSource(raw json.RawMessage) (string, error) {
	// Try []string first (most common in nbformat 4).
	var lines []string
	if err := json.Unmarshal(raw, &lines); err == nil {
		return strings.Join(lines, ""), nil
	}
	// Fall back to a single string.
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

// stripMagics removes lines that start with ! or % (IPython magic commands
// and shell escapes) so the Python parser doesn't choke on them.
// Lines starting with # (comments) are left intact.
func stripMagics(src string) string {
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		trimmed := strings.TrimLeft(l, " \t")
		if strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, "%") {
			out = append(out, "") // preserve line numbers
		} else {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
