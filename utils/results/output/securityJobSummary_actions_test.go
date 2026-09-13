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

func TestGenerateActionsCurationSectionMarkdown(t *testing.T) {
	actions := func(attributed bool, entries ...formats.CuratedAction) *formats.CuratedActions {
		return &formats.CuratedActions{Attributed: attributed, Actions: entries}
	}
	tests := []struct {
		name string
		data []formats.ResultsSummary
		// wantEmpty covers the cases the append in GenerateMarkdownFromFiles depends on: they must
		// return the empty string, not a newline and not an empty collapsible block.
		wantEmpty       bool
		wantContains    []string
		wantNotContains []string
	}{
		{name: "verify when there is no data then nothing is rendered", data: nil, wantEmpty: true},
		{name: "verify when the result set is empty then nothing is rendered", data: []formats.ResultsSummary{}, wantEmpty: true},
		{
			name: "verify when only package-curation data is present then nothing is rendered",
			data: []formats.ResultsSummary{{Scans: []formats.ScanSummary{
				{Target: "npm-project", CuratedPackages: &formats.CuratedPackages{PackageCount: 1}},
			}}},
			wantEmpty: true,
		},
		{
			name: "verify when every scan was attributed then the Parent column is rendered",
			data: []formats.ResultsSummary{{Scans: []formats.ScanSummary{{
				Target: ".github/workflows/ci.yml",
				CuratedActions: actions(true,
					formats.CuratedAction{Action: "actions/checkout", Ref: "v4", Status: "Approved"},
					formats.CuratedAction{Action: "some-org/transitive-action", Ref: "v1", Parent: "github/codeql-action@v3", Status: "Rejected", Notes: "policy failure"},
				),
			}}}},
			wantContains: []string{
				"GitHub Actions Curation", "| Action | Ref | Parent | Status | Notes |",
				"actions/checkout", "Approved",
				"some-org/transitive-action", "github/codeql-action@v3", "Rejected", "policy failure",
			},
		},
		{
			name: "verify when no scan was attributed then the Parent column is omitted",
			data: []formats.ResultsSummary{{Scans: []formats.ScanSummary{{
				Target: "/home/runner/work/_actions",
				CuratedActions: actions(false,
					formats.CuratedAction{Action: "actions/checkout", Ref: "v4", Status: "Approved"},
					formats.CuratedAction{Action: "some-org/some-action", Ref: "v1", Status: "Rejected", Notes: "policy failure"},
				),
			}}}},
			wantContains:    []string{"GitHub Actions Curation", "| Action | Ref | Status | Notes |", "actions/checkout", "policy failure"},
			wantNotContains: []string{"Parent"},
		},
		{
			// Two recorded runs, which is the shape loadContent produces - one summary per data
			// file, each carrying the single scan NewCurationActionsSummary emits. One
			// unattributed run is enough: a single table cannot honestly caption both.
			name: "verify when attribution is mixed then the Parent column is dropped for the whole table",
			data: []formats.ResultsSummary{
				{Scans: []formats.ScanSummary{{Target: "ci.yml", CuratedActions: actions(true, formats.CuratedAction{Action: "a/b", Ref: "v1", Parent: "c/d@v2", Status: "Approved"})}}},
				{Scans: []formats.ScanSummary{{Target: "_actions", CuratedActions: actions(false, formats.CuratedAction{Action: "e/f", Ref: "v3", Status: "Approved"})}}},
			},
			wantContains:    []string{"| Action | Ref | Status | Notes |"},
			wantNotContains: []string{"c/d@v2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			markdown, err := GenerateActionsCurationSectionMarkdown(tt.data)
			assert.NoError(t, err)

			if tt.wantEmpty {
				assert.Equal(t, "", markdown)
				return
			}
			for _, want := range tt.wantContains {
				assert.Contains(t, markdown, want)
			}
			for _, notWant := range tt.wantNotContains {
				assert.NotContains(t, markdown, notWant)
			}
		})
	}
}

func TestNewCurationActionsSummary(t *testing.T) {
	summary := NewCurationActionsSummary([]formats.CuratedAction{{Action: "actions/checkout", Ref: "v4", Status: "Approved"}}, true)

	assert.Equal(t, "curate_gh_actions", string(summary.ResultType))
	if assert.Len(t, summary.Summary.Scans, 1) {
		assert.Empty(t, summary.Summary.Scans[0].Target,
			"Target names a scanned path; this command curates the runner's action cache, which no renderer shows")
		assert.True(t, summary.Summary.Scans[0].HasCuratedActions())
	}
}

func TestSecurityJobSummary_GenerateMarkdownFromFiles_CombinesCurationAndActions(t *testing.T) {
	curationFile := writeSummaryDataFile(t, NewCurationSummary(formats.ResultsSummary{Scans: []formats.ScanSummary{{
		Target:          "npm-project",
		CuratedPackages: &formats.CuratedPackages{PackageCount: 1},
	}}}))
	actionsFile := writeSummaryDataFile(t, NewCurationActionsSummary([]formats.CuratedAction{{Action: "actions/checkout", Ref: "v4", Status: "Approved"}}, true))

	js := &SecurityJobSummary{}
	markdown, err := js.GenerateMarkdownFromFiles([]string{curationFile, actionsFile})
	assert.NoError(t, err)
	assert.Contains(t, markdown, "Curation Audit")
	assert.Contains(t, markdown, "GitHub Actions Curation")
	assert.True(t, strings.Index(markdown, "Curation Audit") < strings.Index(markdown, "GitHub Actions Curation"))
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

func TestGenerateActionsCurationSectionMarkdown_CellsThatWouldReshapeTheTableAreEscaped(t *testing.T) {
	// Same contract as RenderMarkdownTable's console output: the job summary is rendered by
	// GitHub, so an unescaped "|" or newline reshapes the table a reviewer actually reads.
	data := []formats.ResultsSummary{
		{Scans: []formats.ScanSummary{{
			Target: ".github/workflows/ci.yml",
			CuratedActions: &formats.CuratedActions{
				Attributed: true,
				Actions: []formats.CuratedAction{
					{Action: "some-org/some-action", Ref: "feature|v2", Parent: "org/wrap|per@v1", Status: "Rejected", Notes: "blocked:\nCVE-2024-0001"},
				},
			},
		}}},
	}

	markdown, err := GenerateActionsCurationSectionMarkdown(data)
	assert.NoError(t, err)

	assert.Contains(t, markdown, `feature\|v2`)
	assert.Contains(t, markdown, `org/wrap\|per@v1`)
	assert.Contains(t, markdown, "blocked:<br>CVE-2024-0001")
	for _, line := range strings.Split(markdown, "\n") {
		if !strings.HasPrefix(line, "| some-org/some-action") {
			continue
		}
		assert.Equal(t, 6, strings.Count(line, "|")-strings.Count(line, `\|`),
			"the data row must keep the header's cell count")
	}
}
