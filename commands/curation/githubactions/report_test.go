package githubactions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewActionReportRow(t *testing.T) {
	ref := ActionRef{Owner: "github", Repo: "codeql-action", Ref: "v3", Subpath: "analyze", Parent: ""}
	result := ActionCurationResult{Status: ActionApproved}

	row := NewActionReportRow(ref, result)

	assert.Equal(t, ActionReportRow{Action: "github/codeql-action/analyze", Ref: "v3", Status: "Approved"}, row)
}

func TestRenderMarkdownTable(t *testing.T) {
	rows := []ActionReportRow{
		{Action: "actions/checkout", Ref: "v4", Status: "Approved"},
		{Action: "some-org/transitive-action", Ref: "v1", Parent: "github/codeql-action@v3", Status: "Rejected", Notes: "policy failure"},
	}

	want := "" +
		"| Action | Ref | Parent | Status | Notes |\n" +
		"|--------|-----|--------|--------|-------|\n" +
		"| actions/checkout | v4 |  | Approved |  |\n" +
		"| some-org/transitive-action | v1 | github/codeql-action@v3 | Rejected | policy failure |\n"

	assert.Equal(t, want, RenderMarkdownTable(rows))
}

func TestAnyRejected(t *testing.T) {
	assert.False(t, AnyRejected([]ActionReportRow{{Status: "Approved"}}))
	assert.True(t, AnyRejected([]ActionReportRow{{Status: "Approved"}, {Status: "Rejected"}}))
	assert.False(t, AnyRejected(nil))
}
