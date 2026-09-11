package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/stretchr/testify/assert"
)

// writeSummaryDataFile writes a recorded ScanCommandResultSummary to a temp file, mirroring
// what commandsummary.CommandSummary.Record produces on disk, so loadContent can read it back.
func writeSummaryDataFile(t *testing.T, content ScanCommandResultSummary) string {
	t.Helper()
	data, err := json.Marshal(content)
	assert.NoError(t, err)
	filePath := filepath.Join(t.TempDir(), string(content.ResultType)+".json")
	assert.NoError(t, os.WriteFile(filePath, data, 0600))
	return filePath
}

func TestGenerateActionsCurationSectionMarkdown_NoData(t *testing.T) {
	markdown, err := GenerateActionsCurationSectionMarkdown(nil)
	assert.NoError(t, err)
	assert.Empty(t, markdown)
}

func TestGenerateActionsCurationSectionMarkdown_ApprovedAndRejected(t *testing.T) {
	data := []formats.ResultsSummary{
		{Scans: []formats.ScanSummary{{
			Target: ".github/workflows/ci.yml",
			CuratedActions: &formats.CuratedActions{
				Attributed: true,
				Actions: []formats.CuratedAction{
					{Action: "actions/checkout", Ref: "v4", Status: "Approved"},
					{Action: "some-org/transitive-action", Ref: "v1", Parent: "github/codeql-action@v3", Status: "Rejected", Notes: "policy failure"},
				},
			},
		}}},
	}

	markdown, err := GenerateActionsCurationSectionMarkdown(data)
	assert.NoError(t, err)
	assert.Contains(t, markdown, "GitHub Actions Curation")
	assert.Contains(t, markdown, "| Action | Ref | Parent | Status | Notes |")
	assert.Contains(t, markdown, "actions/checkout")
	assert.Contains(t, markdown, "Approved")
	assert.Contains(t, markdown, "some-org/transitive-action")
	assert.Contains(t, markdown, "github/codeql-action@v3")
	assert.Contains(t, markdown, "Rejected")
	assert.Contains(t, markdown, "policy failure")
}

func TestNewCurationActionsSummary(t *testing.T) {
	summary := NewCurationActionsSummary([]formats.CuratedAction{{Action: "actions/checkout", Ref: "v4", Status: "Approved"}}, "ci.yml", true)

	assert.Equal(t, "curate_gh_actions", string(summary.ResultType))
	if assert.Len(t, summary.Summary.Scans, 1) {
		assert.Equal(t, "ci.yml", summary.Summary.Scans[0].Target)
		assert.True(t, summary.Summary.Scans[0].HasCuratedActions())
	}
}

func TestSecurityJobSummary_GenerateMarkdownFromFiles_CombinesCurationAndActions(t *testing.T) {
	curationFile := writeSummaryDataFile(t, NewCurationSummary(formats.ResultsSummary{Scans: []formats.ScanSummary{{
		Target:          "npm-project",
		CuratedPackages: &formats.CuratedPackages{PackageCount: 1},
	}}}))
	actionsFile := writeSummaryDataFile(t, NewCurationActionsSummary([]formats.CuratedAction{{Action: "actions/checkout", Ref: "v4", Status: "Approved"}}, "ci.yml", true))

	js := &SecurityJobSummary{}
	markdown, err := js.GenerateMarkdownFromFiles([]string{curationFile, actionsFile})
	assert.NoError(t, err)
	assert.Contains(t, markdown, "Curation Audit")
	assert.Contains(t, markdown, "GitHub Actions Curation")
	assert.True(t, strings.Index(markdown, "Curation Audit") < strings.Index(markdown, "GitHub Actions Curation"))
}

func TestGenerateActionsCurationSectionMarkdown_StructureOnlyOmitsParentColumn(t *testing.T) {
	// Attributed: false - curation ran against the action cache structure alone, so there is
	// no parent attribution to render and the column must not appear.
	data := []formats.ResultsSummary{
		{Scans: []formats.ScanSummary{{
			Target: "/home/runner/work/_actions",
			CuratedActions: &formats.CuratedActions{
				Attributed: false,
				Actions: []formats.CuratedAction{
					{Action: "actions/checkout", Ref: "v4", Status: "Approved"},
					{Action: "some-org/some-action", Ref: "v1", Status: "Rejected", Notes: "policy failure"},
				},
			},
		}}},
	}

	markdown, err := GenerateActionsCurationSectionMarkdown(data)
	assert.NoError(t, err)
	assert.Contains(t, markdown, "GitHub Actions Curation")
	assert.Contains(t, markdown, "| Action | Ref | Status | Notes |")
	assert.NotContains(t, markdown, "Parent")
	assert.Contains(t, markdown, "actions/checkout")
	assert.Contains(t, markdown, "policy failure")
}

func TestGenerateActionsCurationSectionMarkdown_MixedAttributionDropsParentColumn(t *testing.T) {
	// One unattributed scan is enough: a single table cannot honestly caption both, so the
	// column goes rather than showing blanks for the scans that were never attributed.
	data := []formats.ResultsSummary{
		{Scans: []formats.ScanSummary{
			{
				Target: "ci.yml",
				CuratedActions: &formats.CuratedActions{
					Attributed: true,
					Actions:    []formats.CuratedAction{{Action: "a/b", Ref: "v1", Parent: "c/d@v2", Status: "Approved"}},
				},
			},
			{
				Target: "_actions",
				CuratedActions: &formats.CuratedActions{
					Attributed: false,
					Actions:    []formats.CuratedAction{{Action: "e/f", Ref: "v3", Status: "Approved"}},
				},
			},
		}},
	}

	markdown, err := GenerateActionsCurationSectionMarkdown(data)
	assert.NoError(t, err)
	assert.Contains(t, markdown, "| Action | Ref | Status | Notes |")
	assert.NotContains(t, markdown, "c/d@v2", "an attributed parent must not leak into a table with no Parent column")
}

func TestSecurityJobSummary_GenerateMarkdownFromFiles_CurationAuditOnlyIsUnchanged(t *testing.T) {
	// curate-gh-actions shares the "security" command-summary manager with curation-audit and
	// appends to the same markdown. A run where only curation-audit executed must therefore be
	// byte-for-byte what it was before the actions section existed - no stray heading, no
	// trailing newline, nothing.
	curationOnly := writeSummaryDataFile(t, NewCurationSummary(formats.ResultsSummary{Scans: []formats.ScanSummary{{
		Target:          "npm-project",
		CuratedPackages: &formats.CuratedPackages{PackageCount: 3},
	}}}))

	js := &SecurityJobSummary{}
	combined, err := js.GenerateMarkdownFromFiles([]string{curationOnly})
	assert.NoError(t, err)

	// The curation section rendered on its own, which is what the pipeline produced before.
	curationData, _, err := loadContent([]string{curationOnly}, utils.Curation)
	assert.NoError(t, err)
	expected, err := GenerateSecuritySectionMarkdown(curationData)
	assert.NoError(t, err)

	assert.Equal(t, expected, combined, "a curation-audit-only run must gain nothing from the actions section")
	assert.NotContains(t, combined, "GitHub Actions Curation")
}

func TestGenerateActionsCurationSectionMarkdown_NoActionsDataAddsNothing(t *testing.T) {
	// The append is only safe because this returns the empty string, not a newline or an empty
	// collapsible block, when no curate-gh-actions run contributed data.
	for _, data := range [][]formats.ResultsSummary{
		nil,
		{},
		{{Scans: []formats.ScanSummary{{Target: "npm-project", CuratedPackages: &formats.CuratedPackages{PackageCount: 1}}}}},
	} {
		markdown, err := GenerateActionsCurationSectionMarkdown(data)
		assert.NoError(t, err)
		assert.Equal(t, "", markdown)
	}
}
