package discovery

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// callPattern describes one of the HF call signatures we recognise.
type callPattern struct {
	// namePattern is matched against the bare function/method name (suffix after the last dot).
	namePattern *regexp.Regexp
	// repoIDArgName is the keyword-arg name for repo_id (empty = first positional only).
	repoIDArgName string
	// keywordOnly suppresses the positional-argument fallback for repoIDArgName.
	// Use for calls like pipeline() whose first positional arg is NOT the model id
	// (it is the task string) — only the keyword form `model=` is a valid repo id.
	keywordOnly bool
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
		repoIDArgName:   "path",
		revisionArgName: "revision",
		defaultRepoType: RepoTypeDataset,
	},
	{
		// sentence-transformers library: SentenceTransformer("model-id")
		namePattern:     regexp.MustCompile(`^SentenceTransformer$`),
		repoIDArgName:   "model_name_or_path",
		revisionArgName: "revision",
		defaultRepoType: RepoTypeModel,
	},
	{
		// transformers pipeline factory: pipeline("task", model="org/model")
		// The first positional arg is the task string — model is always the keyword form.
		// keywordOnly prevents positional[0] ("text-generation") being mistaken for a repo id.
		namePattern:     regexp.MustCompile(`^pipeline$`),
		repoIDArgName:   "model",
		keywordOnly:     true,
		revisionArgName: "revision",
		defaultRepoType: RepoTypeModel,
	},
}

// argValue represents one resolved argument value.
type argValue struct {
	literal   string // non-empty when the value is a string literal
	isDynamic bool   // true when value is non-literal (Name not in const table, f-string, call, etc.)
	isFString bool   // sub-kind of dynamic: f-string (for a more specific reason string)
}

// ParsePythonSource scans a Python source string and returns all discovered HF
// references. filename is used for Location.File in the results.
// constTable allows callers (e.g. a multi-file scanner) to pass in pre-populated
// module-level constants; pass nil and it will be built from src itself.
// root is an optional scan root; when provided, it lets an ambiguous single-slash
// literal (e.g. "output/gpt2-finetuned") be checked against the filesystem to
// decide whether it's confidently local. Omit it when no such root is available.
func ParsePythonSource(src, filename string, constTable map[string]string, root ...string) (discovered []DiscoveredModel, unresolved []UnresolvedSite) {
	if constTable == nil {
		constTable = buildConstTable(src)
	}
	scanRoot := ""
	if len(root) > 0 {
		scanRoot = root[0]
	}
	logicalLines := joinContinuationLines(src)
	for _, ll := range logicalLines {
		d, u := matchLogicalLine(ll.text, ll.startLine, filename, constTable, scanRoot)
		discovered = append(discovered, d...)
		unresolved = append(unresolved, u...)
	}
	return
}

// ---- constant table -------------------------------------------------------

// simpleAssignRe matches: NAME = "literal"  or  NAME = 'literal'
// Anchored to avoid matching mid-expression assignments.
var simpleAssignRe = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']+)["'][ \t]*(?:#.*)?$`)

// anyAssignRe matches any top-level "NAME = <rhs>" or "NAME <op>= <rhs>" (e.g.
// "+=") assignment, regardless of RHS shape (literal, call, expression, ...).
// Used to catch reassignment via a non-literal expression or a compound
// assignment too, e.g. MODEL_ID = os.getenv(...) or MODEL_ID += "-v2"
// overriding a checked-in string literal fallback — simpleAssignRe alone would
// miss both and keep trusting the stale literal as a constant. No lookahead in
// RE2, so '==' is excluded by requiring the char after '=' to not be '=' or EOL.
var anyAssignRe = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\*\*|//|>>|<<|[+\-*/%&|^@])?=(?:[^=]|$)`)

// chainedAssignTargetRe catches the middle/right target(s) of a chained
// assignment, e.g. "MODEL_ID = FALLBACK_ID = \"...\"" — anyAssignRe only sees
// the line-leading NAME, so FALLBACK_ID's own reassignment here would
// otherwise go undetected. Matches "=" + NAME + "=" anywhere on the line;
// the same '==' guard as anyAssignRe applies to the trailing "=".
//
// Doesn't false-positive on chained comparisons ("a == b == c"): the '=' in
// "== b ==" is immediately preceded by another '=' with no space, and the
// character right after "b ==" is itself '=', which the trailing guard
// rejects. Nor on keyword args ("foo(x=1, y=2)"): there's no bare "= NAME ="
// pattern there — args are separated by ", ", not repeated "=".
var chainedAssignTargetRe = regexp.MustCompile(`(?m)=\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?:[^=]|$)`)

// buildConstTable collects module-level single-assignment string constants in
// three passes over src: two to count all top-level assignments to each name
// (anyAssignRe for the line-leading target, chainedAssignTargetRe for any
// chained targets), one to gather literal ones (simpleAssignRe). A name
// assigned more than once anywhere in the module — even via a non-literal,
// compound, or chained expression — is removed (not trusted).
func buildConstTable(src string) map[string]string {
	assignCount := map[string]int{}
	for _, m := range anyAssignRe.FindAllStringSubmatch(src, -1) {
		assignCount[m[1]]++
	}
	for _, m := range chainedAssignTargetRe.FindAllStringSubmatch(src, -1) {
		assignCount[m[1]]++
	}

	table := map[string]string{}
	seen := map[string]bool{}
	for _, m := range simpleAssignRe.FindAllStringSubmatch(src, -1) {
		name, val := m[1], m[2]
		if seen[name] || assignCount[name] > 1 {
			delete(table, name) // reassigned (literal or not) → not constant
			seen[name] = true
			continue
		}
		seen[name] = true
		table[name] = val
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

	flush := func() {
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
			flush()
		} else {
			buf.WriteString(" ")
		}
	}
	flush()
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

// callNameRe matches a function/method name (with optional dotted prefix) immediately
// followed by '('. Used by findCallSpans to locate call sites; the argument string is
// then extracted with depth tracking so nested parens are handled correctly.
var callNameRe = regexp.MustCompile(`((?:[A-Za-z_][A-Za-z0-9_.]*\.)?[A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// callSpan is one call site found by findCallSpans.
type callSpan struct {
	name    string // bare or dotted function name
	argsRaw string // raw argument string between the outermost parens
}

// findCallSpans scans line for function calls and returns each call's name and its
// full argument string. Unlike a simple [^)]* regex, it uses depth tracking so calls
// with nested parentheses in their arguments are captured correctly.
func findCallSpans(line string) []callSpan {
	var spans []callSpan
	for _, loc := range callNameRe.FindAllStringSubmatchIndex(line, -1) {
		// loc: [matchStart, matchEnd, group1Start, group1End]
		name := line[loc[2]:loc[3]]
		openParen := loc[1] - 1 // index of '(' in line
		// Walk forward with depth tracking to find the matching ')'.
		depth := 0
		inSingle, inDouble := false, false
		argsStart := openParen + 1
		end := -1
		for i := openParen; i < len(line); i++ {
			c := line[i]
			if c == '\\' && (inSingle || inDouble) {
				i++
				continue
			}
			switch {
			case c == '\'' && !inDouble:
				inSingle = !inSingle
			case c == '"' && !inSingle:
				inDouble = !inDouble
			case c == '(' && !inSingle && !inDouble:
				depth++
			case c == ')' && !inSingle && !inDouble:
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			continue // unmatched paren — skip
		}
		spans = append(spans, callSpan{name: name, argsRaw: line[argsStart:end]})
	}
	return spans
}

func matchLogicalLine(line string, startLine int, filename string, constTable map[string]string, root string) (discovered []DiscoveredModel, unresolved []UnresolvedSite) {
	// Strip leading whitespace and inline comments for cleaner matching.
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") {
		return
	}

	for _, span := range findCallSpans(line) {
		fullName := span.name
		argsRaw := span.argsRaw
		name := callName(fullName)

		for _, cp := range knownCalls {
			if !cp.namePattern.MatchString(name) {
				continue
			}
			loc := Location{File: filename, Line: startLine}
			d, u := resolveCall(cp, argsRaw, loc, constTable, root)
			discovered = append(discovered, d...)
			unresolved = append(unresolved, u...)
		}
	}
	return
}

// ---- argument resolution --------------------------------------------------

// resolveCall parses the raw argument string for a matched call and produces
// DiscoveredModel or UnresolvedSite entries. root is the scan root, used to check
// the filesystem when a repo_id literal is ambiguous between a local output
// directory and a syntactically valid Hub id (see classifyRepoIDLiteral).
func resolveCall(cp callPattern, argsRaw string, loc Location, constTable map[string]string, root string) (discovered []DiscoveredModel, unresolved []UnresolvedSite) {
	positional, keyword := parseArgs(argsRaw)

	// Resolve repo_id
	var repoIDArg argValue
	repoIDFound := false
	if cp.repoIDArgName != "" {
		if v, ok := keyword[cp.repoIDArgName]; ok {
			repoIDArg = resolveArgValue(v, constTable)
			repoIDFound = true
		} else if !cp.keywordOnly && len(positional) > 0 {
			// keywordOnly=true (e.g. pipeline) suppresses this fallback: positional[0]
			// is the task string ("text-generation"), not a model id.
			repoIDArg = resolveArgValue(positional[0], constTable)
			repoIDFound = true
		}
	} else if len(positional) > 0 {
		repoIDArg = resolveArgValue(positional[0], constTable)
		repoIDFound = true
	}

	if !repoIDFound {
		// No repo_id argument found at all — silently skip.
		// Example: pipeline("text-generation") with no model= kwarg uses a
		// task-default model that cannot be determined statically; emitting an
		// unresolved warning here would be noisy and unhelpful.
		return
	}

	if repoIDArg.literal == "" {
		// Arg is present but non-literal (dynamic variable, f-string, call, etc.)
		// — record as unresolved so the user knows coverage is incomplete.
		reason := "non-literal repo_id"
		if repoIDArg.isFString {
			reason = "f-string repo_id"
		}
		snippet := buildSnippet(argsRaw)
		unresolved = append(unresolved, UnresolvedSite{Location: loc, Snippet: snippet, Reason: reason})
		return
	}

	// A local filesystem path is a valid literal but not a Hub repo id: the model
	// was resolved outside source (e.g. downloaded via `jf hf download` in a prior
	// build step). Report it as an advisory instead of probing curation with a
	// bogus repo id, so the coverage gap is visible.
	switch classifyRepoIDLiteral(repoIDArg.literal, root) {
	case classLocalPath:
		snippet := buildSnippet(argsRaw)
		unresolved = append(unresolved, UnresolvedSite{Location: loc, Snippet: snippet, Reason: "local filesystem path"})
		return
	case classAmbiguousPath:
		// Structurally a valid Hub id (HF's namespace/repo_name grammar permits names
		// like "output/model"), but it also matches a conventional local-output-dir
		// name and no filesystem evidence could confirm or rule out a local directory.
		// Don't guess either way: silently auditing it could probe a bogus repo id,
		// and silently skipping it could hide a real, uncurated Hub reference.
		snippet := buildSnippet(argsRaw)
		unresolved = append(unresolved, UnresolvedSite{Location: loc, Snippet: snippet, Reason: "ambiguous local path or Hub repo id"})
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
			switch rv.literal {
			case "dataset":
				repoType = RepoTypeDataset
			case "model":
				repoType = RepoTypeModel
			default:
				// Dynamic or unsupported repo_type (e.g. "space") — don't guess.
				reason := "non-literal repo_type"
				switch {
				case rv.isFString:
					reason = "f-string repo_type"
				case rv.literal != "":
					reason = "unsupported repo_type"
				}
				snippet := buildSnippet(argsRaw)
				unresolved = append(unresolved, UnresolvedSite{Location: loc, Snippet: snippet, Reason: reason})
				return
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

type quoteState int

const (
	quoteNone quoteState = iota
	quoteSingle
	quoteDouble
	quoteTripleSingle
	quoteTripleDouble
)

// splitArgs splits a comma-separated argument list respecting quoted strings
// and nested parentheses.
func splitArgs(s string) []string {
	var parts []string
	depth := 0
	quote := quoteNone
	start := 0
	for i := 0; i < len(s); i++ {
		if quote == quoteTripleDouble {
			if i+2 < len(s) && s[i:i+3] == `"""` {
				quote = quoteNone
				i += 2
			}
			continue
		}
		if quote == quoteTripleSingle {
			if i+2 < len(s) && s[i:i+3] == "'''" {
				quote = quoteNone
				i += 2
			}
			continue
		}

		c := s[i]
		if c == '\\' && (quote == quoteSingle || quote == quoteDouble) {
			i++
			continue
		}
		switch {
		case quote == quoteNone && i+2 < len(s) && s[i:i+3] == `"""`:
			quote = quoteTripleDouble
			i += 2
		case quote == quoteNone && i+2 < len(s) && s[i:i+3] == "'''":
			quote = quoteTripleSingle
			i += 2
		case c == '\'' && quote == quoteNone:
			quote = quoteSingle
		case c == '"' && quote == quoteNone:
			quote = quoteDouble
		case c == '\'' && quote == quoteSingle:
			quote = quoteNone
		case c == '"' && quote == quoteDouble:
			quote = quoteNone
		case (c == '(' || c == '[' || c == '{') && quote == quoteNone:
			depth++
		case (c == ')' || c == ']' || c == '}') && quote == quoteNone:
			depth--
		case c == ',' && depth == 0 && quote == quoteNone:
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

	if lit, ok := unquotePythonString(s); ok {
		return argValue{literal: lit}
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

// unquotePythonString extracts the value from a Python string literal token,
// including triple-quoted """...""" and ”'...”' forms.
func unquotePythonString(s string) (string, bool) {
	if strings.HasPrefix(s, `"""`) && strings.HasSuffix(s, `"""`) && len(s) >= 6 {
		return s[3 : len(s)-3], true
	}
	if strings.HasPrefix(s, "'''") && strings.HasSuffix(s, "'''") && len(s) >= 6 {
		return s[3 : len(s)-3], true
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1], true
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1], true
	}
	return "", false
}

// isIdentifier returns true if s is a valid Python/Go identifier token.
var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func isIdentifier(s string) bool {
	return identRe.MatchString(s)
}

// winDriveRe matches a Windows drive-letter prefix such as "C:\" or "C:/".
var winDriveRe = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// pathClass is the outcome of classifyRepoIDLiteral.
type pathClass int

const (
	// classHubID means the literal is treated as a Hugging Face Hub repo id.
	classHubID pathClass = iota
	// classLocalPath means the literal is confidently a local filesystem path.
	classLocalPath
	// classAmbiguousPath means the literal is a structurally valid Hub id that also
	// matches a conventional local-output-directory name, with no filesystem
	// evidence to disambiguate.
	classAmbiguousPath
)

// localOutputPrefixes are first-segment names that look like Hub org/model IDs but
// are conventionally local output/checkpoint dirs in ML training scripts (e.g.
// "output/gpt2-finetuned"). A name match alone is a hint, not proof — see
// classifyRepoIDLiteral.
var localOutputPrefixes = []string{
	"output/",
	"outputs/",
	"runs/",
	"checkpoints/",
	"checkpoint/",
	"saved_models/",
	"saved_model/",
	"artifacts/",
	"results/",
	"finetuned/",
	"trained/",
}

// classifyRepoIDLiteral classifies a resolved string literal as a Hub repo id, a
// confidently local filesystem path, or an ambiguous case needing user attention.
// Hub ids are a bare name or "namespace/name"; a leading path marker, backslash,
// drive letter, or more than one slash is unambiguously local.
//
// A single-slash value is structurally indistinguishable from a Hub "namespace/name"
// id. Filesystem evidence (when root is available) takes priority over the
// localOutputPrefixes heuristic; otherwise a prefix match is classAmbiguousPath.
func classifyRepoIDLiteral(s, root string) pathClass {
	if s == "" {
		return classHubID
	}
	switch {
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "./"),
		strings.HasPrefix(s, "../"), strings.HasPrefix(s, "~"):
		return classLocalPath
	case strings.Contains(s, "\\"):
		return classLocalPath
	case winDriveRe.MatchString(s):
		return classLocalPath
	case strings.Count(s, "/") > 1:
		return classLocalPath
	}
	if root != "" {
		if info, err := os.Stat(filepath.Join(root, s)); err == nil && info.IsDir() {
			return classLocalPath
		}
	}
	for _, prefix := range localOutputPrefixes {
		if strings.HasPrefix(s, prefix) {
			return classAmbiguousPath
		}
	}
	return classHubID
}

// buildSnippet renders a call's arguments for the unresolved-reference warning,
// redacting anything that could contain a secret. Bare expressions (variable,
// attribute, call) are shown as-is to help identify the call site; anything
// containing a quote character may embed a string literal and is redacted.
func buildSnippet(argsRaw string) string {
	positional, keyword := parseArgs(argsRaw)
	redact := func(raw string) string {
		if strings.ContainsAny(raw, `'"`) {
			return "<redacted>"
		}
		return strings.TrimSpace(raw)
	}

	parts := make([]string, 0, len(positional)+len(keyword))
	for _, p := range positional {
		parts = append(parts, redact(p))
	}
	names := make([]string, 0, len(keyword))
	for k := range keyword {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		parts = append(parts, k+"="+redact(keyword[k]))
	}
	return strings.Join(parts, ", ")
}
