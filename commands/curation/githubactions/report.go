package githubactions

import (
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
)

// ActionReportRow is one row of the curation report, already resolved from an ActionRef and
// its ActionCurationResult.
type ActionReportRow struct {
	Action string // "owner/repo", plus " (subpath[, subpath...])" when invoked via subpaths
	Ref    string // verbatim from the cache directory name, uninterpreted
	Parent string // "" when directly referenced, or when attribution could not place it
	Status string
	Notes  string
}

// NewActionReportRow builds one report row. A monorepo action invoked via several subpaths
// (codeql-action's init@v3 and analyze@v3) shares one cache entry and one decision, so it is
// one row - every subpath used is listed so neither invocation is silently lost.
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

// RenderMarkdownTable renders rows as a GitHub-flavored markdown table. withParent controls
// whether the Parent column appears at all.
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
		sb.WriteString(formats.EscapeMarkdownTableCell(row.Action))
		sb.WriteString(" | ")
		sb.WriteString(formats.EscapeMarkdownTableCell(row.Ref))
		if withParent {
			sb.WriteString(" | ")
			sb.WriteString(formats.EscapeMarkdownTableCell(row.Parent))
		}
		sb.WriteString(" | ")
		sb.WriteString(formats.EscapeMarkdownTableCell(row.Status))
		sb.WriteString(" | ")
		sb.WriteString(formats.EscapeMarkdownTableCell(row.Notes))
		sb.WriteString(" |\n")
	}
	return sb.String()
}

// NotApproved returns every row whose Status is not exactly ActionApproved, for the command's
// exit-code decision.
//
// An allow-list, deliberately, rather than a test for ActionRejected: ActionCurationStatus is an
// open string type, so a status this code does not recognize - one a later decider introduces, or
// the zero value of a result returned without one - would pass a deny-list while rendering as an
// empty cell. Only an explicit approval may clear a gate whose purpose is to stop whatever it has
// not cleared. This is not part of the mocked seam; the real decider replaces the verdict, not
// the enforcement.
func NotApproved(rows []ActionReportRow) []ActionReportRow {
	var notApproved []ActionReportRow
	for _, row := range rows {
		if row.Status != string(ActionApproved) {
			notApproved = append(notApproved, row)
		}
	}
	return notApproved
}
