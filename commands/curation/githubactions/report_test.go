package githubactions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewActionReportRow(t *testing.T) {
	tests := []struct {
		name   string
		ref    ActionRef
		result ActionCurationResult
		want   ActionReportRow
	}{
		{
			name:   "verify when the action has no subpath then the action cell is owner and repo",
			ref:    ActionRef{Owner: "actions", Repo: "checkout", Ref: "v4"},
			result: ActionCurationResult{Status: ActionApproved},
			want:   ActionReportRow{Action: "actions/checkout", Ref: "v4", Status: "Approved"},
		},
		{
			name:   "verify when the action has one subpath then it is appended to the action cell",
			ref:    ActionRef{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpaths: []string{"analyze"}},
			result: ActionCurationResult{Status: ActionApproved},
			want:   ActionReportRow{Action: "github/codeql-action (analyze)", Ref: "v3", Status: "Approved"},
		},
		{
			// init@v3 and analyze@v3 collapse to one cache entry, so neither invocation may be lost.
			name:   "verify when the action has several subpaths then every one is listed",
			ref:    ActionRef{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpaths: []string{"init", "analyze"}},
			result: ActionCurationResult{Status: ActionApproved},
			want:   ActionReportRow{Action: "github/codeql-action (init, analyze)", Ref: "v3", Status: "Approved"},
		},
		{
			name:   "verify when the decision carries parent and notes then both reach the row",
			ref:    ActionRef{Owner: "some-org", Repo: "transitive-action", Ref: "v1", Parent: "github/codeql-action@v3"},
			result: ActionCurationResult{Status: ActionRejected, Notes: "policy failure"},
			want: ActionReportRow{Action: "some-org/transitive-action", Ref: "v1", Parent: "github/codeql-action@v3",
				Status: "Rejected", Notes: "policy failure"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewActionReportRow(tt.ref, tt.result))
		})
	}
}

func TestRenderMarkdownTable(t *testing.T) {
	tests := []struct {
		name       string
		rows       []ActionReportRow
		withParent bool
		want       string
		// wantPipes is the pipe count the header and every data row must agree on, or the table
		// renders broken.
		wantPipes int
	}{
		{
			name: "verify when the run was attributed then the table carries a Parent column",
			rows: []ActionReportRow{
				{Action: "actions/checkout", Ref: "v4", Status: "Approved"},
				{Action: "some-org/transitive-action", Ref: "v1", Parent: "github/codeql-action@v3", Status: "Rejected", Notes: "policy failure"},
			},
			withParent: true,
			want: "| Action | Ref | Parent | Status | Notes |\n" +
				"|--------|-----|--------|--------|-------|\n" +
				"| actions/checkout | v4 |  | Approved |  |\n" +
				"| some-org/transitive-action | v1 | github/codeql-action@v3 | Rejected | policy failure |\n",
			wantPipes: 6,
		},
		{
			// Present-and-blank would read as "nothing pulled in transitively".
			name: "verify when the run was structure-only then the Parent column is omitted",
			rows: []ActionReportRow{
				{Action: "actions/checkout", Ref: "v4", Status: "Approved"},
				{Action: "some-org/some-action", Ref: "v1", Status: "Rejected", Notes: "policy failure"},
			},
			withParent: false,
			want: "| Action | Ref | Status | Notes |\n" +
				"|--------|-----|--------|-------|\n" +
				"| actions/checkout | v4 | Approved |  |\n" +
				"| some-org/some-action | v1 | Rejected | policy failure |\n",
			wantPipes: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderMarkdownTable(tt.rows, tt.withParent)

			assert.Equal(t, tt.want, got)
			for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
				assert.Equal(t, tt.wantPipes, strings.Count(line, "|"), "row %q has the wrong cell count", line)
			}
		})
	}
}

func TestNotApproved(t *testing.T) {
	tests := []struct {
		name string
		rows []ActionReportRow
		want []string // the Ref of each row that must not clear the gate
	}{
		{name: "verify when every action is approved then none is withheld", rows: []ActionReportRow{{Ref: "v4", Status: "Approved"}}},
		{name: "verify when no action was decided then none is withheld", rows: nil},
		{
			name: "verify when an action is rejected then it is withheld",
			rows: []ActionReportRow{{Ref: "v4", Status: "Approved"}, {Ref: "v1", Status: "Rejected"}},
			want: []string{"v1"},
		},
		{
			// A deny-list would let these through while rendering an empty or unfamiliar cell: the
			// zero value of a result returned without a status, and a status a later decider adds.
			name: "verify when a status is blank or unrecognized then it is withheld",
			rows: []ActionReportRow{{Ref: "v4", Status: "Approved"}, {Ref: "v9"}, {Ref: "v2", Status: "NeedsReview"}},
			want: []string{"v9", "v2"},
		},
		{
			// Case matters: only the exact constant approves.
			name: "verify when a status differs only in case then it is withheld",
			rows: []ActionReportRow{{Ref: "v4", Status: "approved"}},
			want: []string{"v4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, row := range NotApproved(tt.rows) {
				got = append(got, row.Ref)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRenderMarkdownTable_CellsThatWouldReshapeTheTableAreEscaped(t *testing.T) {
	// Ref is a directory name the runner created and "|" is legal in a git refname; Notes comes
	// from the decision service. Unescaped, either would add a column or split the row, so the
	// table would report a status against the wrong action.
	rows := []ActionReportRow{
		{Action: "some-org/some-action", Ref: "feature|v2", Parent: "org/wrap|per@v1", Status: "Rejected", Notes: "blocked:\nCVE-2024-0001"},
	}

	got := RenderMarkdownTable(rows, true)

	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if assert.Len(t, lines, 3, "header, separator, one data row") {
		assert.Equal(t, 6, strings.Count(lines[2], "|")-strings.Count(lines[2], `\|`),
			"the data row must still have exactly the header's cell count")
	}
	assert.Contains(t, got, `feature\|v2`)
	assert.Contains(t, got, `org/wrap\|per@v1`)
	assert.Contains(t, got, "blocked:<br>CVE-2024-0001")
	assert.NotContains(t, got, "\nCVE-2024-0001", "a newline in Notes must never end the row early")
}
