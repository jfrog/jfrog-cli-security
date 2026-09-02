package githubactions

import "strings"

// ActionReportRow is one row of the curation report, already resolved from an ActionRef and
// its ActionCurationResult.
type ActionReportRow struct {
	Action string // "owner/repo" (+ "/subpath" if Subpath != "")
	Ref    string // literal, uninterpreted
	Parent string // "" if directly referenced in the job's workflow
	Status string
	Notes  string
}

// NewActionReportRow builds a report row from a discovered/cross-referenced ActionRef and its
// curation decision.
func NewActionReportRow(ref ActionRef, result ActionCurationResult) ActionReportRow {
	action := ref.Owner + "/" + ref.Repo
	if ref.Subpath != "" {
		action += "/" + ref.Subpath
	}
	return ActionReportRow{
		Action: action,
		Ref:    ref.Ref,
		Parent: ref.Parent,
		Status: string(result.Status),
		Notes:  result.Notes,
	}
}

// RenderMarkdownTable renders rows as a GitHub-flavored markdown table:
// Action | Ref | Parent | Status | Notes
func RenderMarkdownTable(rows []ActionReportRow) string {
	var sb strings.Builder
	sb.WriteString("| Action | Ref | Parent | Status | Notes |\n")
	sb.WriteString("|--------|-----|--------|--------|-------|\n")
	for _, row := range rows {
		sb.WriteString("| ")
		sb.WriteString(row.Action)
		sb.WriteString(" | ")
		sb.WriteString(row.Ref)
		sb.WriteString(" | ")
		sb.WriteString(row.Parent)
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
