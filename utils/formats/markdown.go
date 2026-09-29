package formats

import (
	"fmt"
	"strings"
)

// The backslash rule comes first so an input already containing "\|" keeps both characters
// literal instead of yielding an unescaped separator.
var markdownTableCellEscaper = strings.NewReplacer(
	`\`, `\\`,
	`|`, `\|`,
	"\r\n", "<br>",
	"\n", "<br>",
	"\r", "<br>",
)

// EscapeMarkdownTableCell renders value safely inside one GitHub-flavored markdown table cell:
// "|" would open a new cell and a newline would end the row.
func EscapeMarkdownTableCell(value string) string {
	return markdownTableCellEscaper.Replace(value)
}

// The pipe rules are markdownTableCellEscaper's: a table printed to a log still needs its shape,
// or a cell containing "|" reads as a column break. Only the newline rule differs - "<br>" is
// markup a terminal shows verbatim, so a multi-line note renders as one line instead.
var terminalTableCellEscaper = strings.NewReplacer(
	`\`, `\\`,
	`|`, `\|`,
	"\r\n", " ",
	"\n", " ",
	"\r", " ",
)

// EscapeTerminalTableCell renders value inside one table cell that a person reads in a terminal
// rather than a markdown renderer.
func EscapeTerminalTableCell(value string) string {
	return terminalTableCellEscaper.Replace(value)
}

// RenderActionsException returns the line a GitHub Actions curation report carries when the
// command cannot account for every action the job will execute, or "" when nothing needs saying.
// This is the case where either a run is structure-only, or a local action was found in the
// attributed flow.
func RenderActionsException(actions []CuratedActions) string {
	localUses, anyUnattributed := knownLocalCompositeActions(actions)
	switch {
	case len(localUses) == 0 && !anyUnattributed:
		return ""
	case len(localUses) == 0:
		return "\nNot covered: no workflow file was available, so this report cannot tell whether this job reaches a local " +
			"composite action (uses: ./...) which are not curated.\n"
	}

	subject := "a local composite action"
	if len(localUses) > 1 {
		subject = "local composite actions"
	}
	described := make([]string, 0, len(localUses))
	for _, use := range localUses {
		// The declarer matters most for a path a third-party composite action names: it points
		// into this repository, so without it a reader has nowhere to start looking.
		if use.DeclaredBy != "" {
			described = append(described, fmt.Sprintf("%q declared by %s", use.Path, use.DeclaredBy))
			continue
		}
		described = append(described, fmt.Sprintf("%q", use.Path))
	}
	message := fmt.Sprintf("\nNot covered: this job reaches %s (%s). The runner resolves those from the workspace when the step "+
		"runs - after this check read the action cache - so an action reached only that way is not curated here.",
		subject, strings.Join(described, ", "))
	if anyUnattributed {
		// The list is what was found, not what exists. Reporting it without this would claim a
		// completeness that the part of the run with no workflow file cannot support.
		message += " No workflow file was available for part of this report, so there may be others it could not see."
	}
	return message + "\n"
}

// knownLocalCompositeActions returns every local composite action across actions, deduplicated
// in first-seen order, and whether any of them was produced without a workflow file.
//
// anyUnattributed cannot be inferred from the list. An empty list means "attributed, and there
// are genuinely none" or "nothing could be read", and those two have to read differently.
func knownLocalCompositeActions(actions []CuratedActions) (localUses []LocalCompositeAction, anyUnattributed bool) {
	seen := map[LocalCompositeAction]bool{}
	for _, curated := range actions {
		if !curated.Attributed {
			anyUnattributed = true
		}
		for _, use := range curated.LocalCompositeActions {
			if seen[use] {
				continue
			}
			seen[use] = true
			localUses = append(localUses, use)
		}
	}
	return localUses, anyUnattributed
}
