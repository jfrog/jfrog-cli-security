package discovery

import (
	"regexp"
	"strings"
)

// callPattern describes one of the HF call signatures we recognise.
type callPattern struct {
	// namePattern is matched against the bare function/method name (suffix after the last dot).
	namePattern *regexp.Regexp
	// repoIDArgName is the keyword-arg name for repo_id (empty = first positional only).
	repoIDArgName string
	// revisionArgName is the keyword-arg name for the revision.
	revisionArgName string
	// repoTypeArgName is the keyword-arg name for repo_type (empty = fixed).
	repoTypeArgName string
	// defaultRepoType is used when repoTypeArgName is empty or not present in the call.
	defaultRepoType RepoType
}

// callName extracts the bare function/method name from a raw call token.
// e.g. "AutoModel.from_pretrained" → "from_pretrained", "snapshot_download" → "snapshot_download".
func callName(s string) string {
	if idx := strings.LastIndex(s, "."); idx >= 0 {
		return s[idx+1:]
	}
	return s
}

var knownCalls = []callPattern{
	{
		namePattern:     regexp.MustCompile(`^from_pretrained$`),
		repoIDArgName:   "pretrained_model_name_or_path",
		revisionArgName: "revision",
		defaultRepoType: RepoTypeModel,
	},
	{
		namePattern:     regexp.MustCompile(`^snapshot_download$`),
		repoIDArgName:   "repo_id",
		revisionArgName: "revision",
		repoTypeArgName: "repo_type",
		defaultRepoType: RepoTypeModel,
	},
	{
		namePattern:     regexp.MustCompile(`^hf_hub_download$`),
		repoIDArgName:   "repo_id",
		revisionArgName: "revision",
		repoTypeArgName: "repo_type",
		defaultRepoType: RepoTypeModel,
	},
	{
		namePattern:     regexp.MustCompile(`^load_dataset$`),
		repoIDArgName:   "",
		revisionArgName: "revision",
		defaultRepoType: RepoTypeDataset,
	},
}

// argValue represents one resolved argument value.
type argValue struct {
	literal  string // non-empty when the value is a string literal
	isDynamic bool   // true when value is non-literal (Name not in const table, f-string, call, etc.)
	isFString bool   // sub-kind of dynamic: f-string (for a more specific reason string)
}

// ParsePythonSource scans a Python source string and returns all discovered HF
// references. filename is used for Location.File in the results.
// constTable allows callers (e.g. a multi-file scanner) to pass in pre-populated
// module-level constants; pass nil and it will be built from src itself.
func ParsePythonSource(src, filename string, constTable map[string]string) (discovered []DiscoveredModel, unresolved []UnresolvedSite) {
	if constTable == nil {
		constTable = buildConstTable(src)
	}
	logicalLines := joinContinuationLines(src)
	for _, ll := range logicalLines {
		d, u := matchLogicalLine(ll.text, ll.startLine, filename, constTable)
		discovered = append(discovered, d...)
		unresolved = append(unresolved, u...)
	}
	return
}

// ---- constant table -------------------------------------------------------

// simpleAssignRe matches: NAME = "literal"  or  NAME = 'literal'
// Anchored to avoid matching mid-expression assignments.
var simpleAssignRe = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']+)["'][ \t]*(?:#.*)?$`)

// buildConstTable performs a single pass over src and collects module-level
// single-assignment string constants. A name that is assigned more than once
// is removed from the table (we won't trust it).
func buildConstTable(src string) map[string]string {
	table := map[string]string{}
	seen := map[string]bool{}
	for _, m := range simpleAssignRe.FindAllStringSubmatch(src, -1) {
		name, val := m[1], m[2]
		if seen[name] {
			delete(table, name) // reassigned → not constant
		} else {
			seen[name] = true
			table[name] = val
		}
	}
	return table
}

// ---- logical line joining --------------------------------------------------

type logicalLine struct {
	text      string
	startLine int // 1-based line number of the first physical line
}

// joinContinuationLines collapses backslash continuations and open-paren spans
// into single logical lines, preserving the starting line number of each.
func joinContinuationLines(src string) []logicalLine {
	physical := strings.Split(src, "\n")
	var result []logicalLine
	var buf strings.Builder
	startLine := 0
	depth := 0

	flush := func(endIdx int) {
		if buf.Len() > 0 {
			result = append(result, logicalLine{text: buf.String(), startLine: startLine + 1})
			buf.Reset()
		}
	}

	for i, line := range physical {
		trimmed := strings.TrimRight(line, " \t\r")
		if buf.Len() == 0 {
			startLine = i
		}
		// Count unquoted parens (rough but good enough for our call patterns)
		depth += countParenDepthChange(trimmed)

		if strings.HasSuffix(trimmed, "\\") {
			buf.WriteString(strings.TrimSuffix(trimmed, "\\"))
			continue
		}
		buf.WriteString(trimmed)
		if depth <= 0 {
			depth = 0
			flush(i)
		} else {
			buf.WriteString(" ")
		}
	}
	flush(len(physical))
	return result
}

// countParenDepthChange returns the net change in paren depth ignoring quoted strings.
// An unquoted '#' starts a Python comment, so the rest of the line is prose (which may
// contain unbalanced parens or apostrophes like "tab's") and must be ignored — otherwise
// a comment can corrupt depth tracking and glue unrelated statements together.
func countParenDepthChange(s string) int {
	depth := 0
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && (inSingle || inDouble) {
			i++ // skip escaped char
			continue
		}
		switch {
		case c == '#' && !inSingle && !inDouble:
			return depth // rest of the line is a comment
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '(' && !inSingle && !inDouble:
			depth++
		case c == ')' && !inSingle && !inDouble:
			depth--
		}
	}
	return depth
}

// ---- call matching --------------------------------------------------------

// callRe matches a function/method call: captures the call expression and args
// between the outermost parens. The function name may include a dotted prefix.
var callRe = regexp.MustCompile(`((?:[A-Za-z_][A-Za-z0-9_.]*\.)?[A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)`)

func matchLogicalLine(line string, startLine int, filename string, constTable map[string]string) (discovered []DiscoveredModel, unresolved []UnresolvedSite) {
	// Strip leading whitespace and inline comments for cleaner matching.
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") {
		return
	}

	for _, m := range callRe.FindAllStringSubmatch(line, -1) {
		fullName := m[1]
		argsRaw := m[2]
		name := callName(fullName)

		for _, cp := range knownCalls {
			if !cp.namePattern.MatchString(name) {
				continue
			}
			loc := Location{File: filename, Line: startLine}
			d, u := resolveCall(cp, argsRaw, loc, constTable)
			discovered = append(discovered, d...)
			unresolved = append(unresolved, u...)
		}
	}
	return
}

// ---- argument resolution --------------------------------------------------

// resolveCall parses the raw argument string for a matched call and produces
// DiscoveredModel or UnresolvedSite entries.
func resolveCall(cp callPattern, argsRaw string, loc Location, constTable map[string]string) (discovered []DiscoveredModel, unresolved []UnresolvedSite) {
	positional, keyword := parseArgs(argsRaw)

	// Resolve repo_id
	var repoIDArg argValue
	if cp.repoIDArgName != "" {
		if v, ok := keyword[cp.repoIDArgName]; ok {
			repoIDArg = resolveArgValue(v, constTable)
		} else if len(positional) > 0 {
			repoIDArg = resolveArgValue(positional[0], constTable)
		}
	} else if len(positional) > 0 {
		repoIDArg = resolveArgValue(positional[0], constTable)
	}

	if repoIDArg.literal == "" {
		// Cannot determine repo_id — record as unresolved.
		reason := "non-literal repo_id"
		if repoIDArg.isFString {
			reason = "f-string repo_id"
		}
		snippet := buildSnippet(loc.File, argsRaw)
		unresolved = append(unresolved, UnresolvedSite{Location: loc, Snippet: snippet, Reason: reason})
		return
	}

	// Resolve revision
	var revision string
	revDefaulted := false
	revDynamic := false
	if v, ok := keyword[cp.revisionArgName]; ok {
		rv := resolveArgValue(v, constTable)
		if rv.literal != "" {
			revision = rv.literal
		} else {
			revDynamic = true
			revision = DefaultRevision
		}
	} else {
		revision = DefaultRevision
		revDefaulted = true
	}

	// Resolve repo_type
	repoType := cp.defaultRepoType
	if cp.repoTypeArgName != "" {
		if v, ok := keyword[cp.repoTypeArgName]; ok {
			rv := resolveArgValue(v, constTable)
			if rv.literal == "dataset" {
				repoType = RepoTypeDataset
			}
		}
	}

	discovered = append(discovered, DiscoveredModel{
		RepoID:            repoIDArg.literal,
		Revision:          revision,
		RevisionDefaulted: revDefaulted,
		RevisionDynamic:   revDynamic,
		RepoType:          repoType,
		Sources:           []Location{loc},
	})
	return
}

// parseArgs splits a raw argument string into positional and keyword slices.
// It handles simple cases well; deeply nested calls may produce imperfect
// splits, but those will fail the literal-string check and become UnresolvedSite.
func parseArgs(raw string) (positional []string, keyword map[string]string) {
	keyword = map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return
	}
	parts := splitArgs(raw)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// keyword arg: name = value
		if idx := strings.Index(part, "="); idx > 0 {
			k := strings.TrimSpace(part[:idx])
			v := strings.TrimSpace(part[idx+1:])
			// Only treat as keyword if k is a valid identifier
			if isIdentifier(k) {
				keyword[k] = v
				continue
			}
		}
		positional = append(positional, part)
	}
	return
}

// splitArgs splits a comma-separated argument list respecting quoted strings
// and nested parentheses.
func splitArgs(s string) []string {
	var parts []string
	depth := 0
	inSingle, inDouble := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && (inSingle || inDouble) {
			i++
			continue
		}
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case (c == '(' || c == '[' || c == '{') && !inSingle && !inDouble:
			depth++
		case (c == ')' || c == ']' || c == '}') && !inSingle && !inDouble:
			depth--
		case c == ',' && depth == 0 && !inSingle && !inDouble:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// resolveArgValue classifies a raw argument token.
func resolveArgValue(raw string, constTable map[string]string) argValue {
	s := strings.TrimSpace(raw)

	// String literal: "value" or 'value'
	if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) && len(s) >= 2) ||
		(strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`) && len(s) >= 2) {
		return argValue{literal: s[1 : len(s)-1]}
	}

	// f-string → dynamic
	if strings.HasPrefix(s, `f"`) || strings.HasPrefix(s, `f'`) ||
		strings.HasPrefix(s, `F"`) || strings.HasPrefix(s, `F'`) {
		return argValue{isDynamic: true, isFString: true}
	}

	// Simple identifier → check constant table
	if isIdentifier(s) {
		if v, ok := constTable[s]; ok {
			return argValue{literal: v}
		}
		return argValue{isDynamic: true}
	}

	return argValue{isDynamic: true}
}

// isIdentifier returns true if s is a valid Python/Go identifier token.
var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func isIdentifier(s string) bool {
	return identRe.MatchString(s)
}

func buildSnippet(filename, argsRaw string) string {
	if len(argsRaw) > 60 {
		return argsRaw[:60] + "..."
	}
	return argsRaw
}
