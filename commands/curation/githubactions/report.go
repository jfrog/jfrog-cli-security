package githubactions

import "strings"

// ActionReportRow is one row of the curation report, already resolved from an ActionRef and
// its ActionCurationResult.
type ActionReportRow struct {
	Action string // "owner/repo" (+ " (subpath[, subpath...])" if the action was invoked via one or more subpaths)
	Ref    string // literal, uninterpreted
	Parent string // "" if directly referenced in the job's workflow or parent can not be determined
	Status string
	Notes  string
}

// NewActionReportRow builds a report row from a discovered/cross-referenced ActionRef and its
// curation decision. A monorepo action invoked via more than one subpath (e.g.
// github/codeql-action's init@v3 and analyze@v3) still resolves to a single ActionRef - and
// therefore a single row here - since both invocations share one directory entry in the cache
// and one curation decision; every distinct subpath used is listed so neither is silently lost.
func NewActionReportRow(ref ActionRef, result ActionCurationResult) ActionReportRow {
	action := ref.Owner + "/" + ref.Repo
	if len(ref.Subpaths) > 0 {
		action += " (" + strings.Join(ref.Subpaths, ", ") + ")"
	}
	return ActionReportRow{
		Action: action,
		Ref:    ref.Ref,
		Parent: ref.Parent,
		Status: string(result.Status),
		Notes:  result.Notes,
	}
}

// RenderMarkdownTable renders rows as a GitHub-flavored markdown table.
// withParent controls whether the Parent column appears at all.
//
// Columns:
//
//	withParent:  Action | Ref | Parent | Status | Notes
//	otherwise:   Action | Ref | Status | Notes
func RenderMarkdownTable(rows []ActionReportRow, withParent bool) string {
	var sb strings.Builder
	if withParent {
		sb.WriteString("| Action | Ref | Parent | Status | Notes |\n")
		sb.WriteString("|--------|-----|--------|--------|-------|\n")
	} else {
		sb.WriteString("| Action | Ref | Status | Notes |\n")
		sb.WriteString("|--------|-----|--------|-------|\n")
	}
	for _, row := range rows {
		sb.WriteString("| ")
		sb.WriteString(row.Action)
		sb.WriteString(" | ")
		sb.WriteString(row.Ref)
		if withParent {
			sb.WriteString(" | ")
			sb.WriteString(row.Parent)
		}
		sb.WriteString(" | ")
		sb.WriteString(row.Status)
		sb.WriteString(" | ")
		sb.WriteString(row.Notes)
		sb.WriteString(" |\n")
	}
	return sb.String()
}

// AnyRejected reports whether any row's Status is ActionRejected, for the command's exit-code decision.
func AnyRejected(rows []ActionReportRow) bool {
	for _, row := range rows {
		if row.Status == string(ActionRejected) {
			return true
		}
	}
	return false
}
