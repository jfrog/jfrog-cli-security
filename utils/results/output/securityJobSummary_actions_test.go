package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	assert.Contains(t, markdown, "actions/checkout")
	assert.Contains(t, markdown, "Approved")
	assert.Contains(t, markdown, "some-org/transitive-action")
	assert.Contains(t, markdown, "github/codeql-action@v3")
	assert.Contains(t, markdown, "Rejected")
	assert.Contains(t, markdown, "policy failure")
}

func TestNewCurationActionsSummary(t *testing.T) {
	summary := NewCurationActionsSummary([]formats.CuratedAction{{Action: "actions/checkout", Ref: "v4", Status: "Approved"}}, "ci.yml")

	assert.Equal(t, "curation_actions", string(summary.ResultType))
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
	actionsFile := writeSummaryDataFile(t, NewCurationActionsSummary([]formats.CuratedAction{{Action: "actions/checkout", Ref: "v4", Status: "Approved"}}, "ci.yml"))

	js := &SecurityJobSummary{}
	markdown, err := js.GenerateMarkdownFromFiles([]string{curationFile, actionsFile})
	assert.NoError(t, err)
	assert.Contains(t, markdown, "Curation Audit")
	assert.Contains(t, markdown, "GitHub Actions Curation")
	assert.True(t, strings.Index(markdown, "Curation Audit") < strings.Index(markdown, "GitHub Actions Curation"))
}
