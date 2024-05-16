package utils

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jfrog/jfrog-cli-core/v2/commandsummary"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const (
	Build   SecuritySummarySection = "Builds"
	Binary  SecuritySummarySection = "Binaries"
	Modules SecuritySummarySection = "Modules"
)

type SecuritySummarySection string

type ScanCommandSummaryResult struct {
	Section SecuritySummarySection `json:"section"`
	Results formats.SummaryResults `json:"results"`
}

type SecurityCommandsSummary struct {
	BuildScanCommands []formats.SummaryResults `json:"buildScanCommands"`
	ScanCommands      []formats.SummaryResults `json:"scanCommands"`
	AuditCommands     []formats.SummaryResults `json:"auditCommands"`
}

// Manage the job summary for security commands
func SecurityCommandsJobSummary() (js *commandsummary.CommandSummary, err error) {
	return commandsummary.NewCommandSummary(&SecurityCommandsSummary{
		BuildScanCommands: []formats.SummaryResults{},
		ScanCommands:      []formats.SummaryResults{},
		AuditCommands:     []formats.SummaryResults{},
	})
}

// Record the security command output
func RecordSecurityCommandOutput(content ScanCommandSummaryResult) (err error) {
	manager, err := SecurityCommandsJobSummary()
	if err != nil || manager == nil {
		return
	}
	return manager.CreateMarkdown(content)
}

func (scs *SecurityCommandsSummary) CreateMarkdown(content any) error {
	return commandsummary.CreateMarkdown(content, "security", scs.RenderContentToMarkdown)
}

func (scs *SecurityCommandsSummary) RenderContentToMarkdown(dataFilePaths []string) (markdown string, err error) {
	// Unmarshal the data into an array of build info objects
	if err = loadContentFromFiles(dataFilePaths, scs); err != nil {
		return "", fmt.Errorf("failed while creating security markdown: %w", err)
	}
	return ConvertSummaryToString(*scs)
}

func loadContentFromFiles(dataFilePaths []string, scs *SecurityCommandsSummary) (err error) {
	for _, dataFilePath := range dataFilePaths {
		// Load file content
		var content []byte
		if content, err = os.ReadFile(dataFilePath); errorutils.CheckError(err) != nil {
			return fmt.Errorf("failed while reading '%s': %w", dataFilePath, err)
		}
		var cmdResults ScanCommandSummaryResult
		if err = errorutils.CheckError(json.Unmarshal(content, &cmdResults)); err != nil {
			return fmt.Errorf("failed while Unmarshal '%s': %w", dataFilePath, err)
		}
		// Append the new data
		switch cmdResults.Section {
		case Build:
			scs.BuildScanCommands = append(scs.BuildScanCommands, cmdResults.Results)
		case Binary:
			scs.ScanCommands = append(scs.ScanCommands, cmdResults.Results)
		case Modules:
			scs.AuditCommands = append(scs.AuditCommands, cmdResults.Results)
		}
	}
	return
}

func (scs *SecurityCommandsSummary) GetOrderedSectionsWithContent() (sections []SecuritySummarySection) {
	if len(scs.BuildScanCommands) > 0 {
		sections = append(sections, Build)
	}
	if len(scs.ScanCommands) > 0 {
		sections = append(sections, Binary)
	}
	if len(scs.AuditCommands) > 0 {
		sections = append(sections, Modules)
	}
	return

}

func (scs *SecurityCommandsSummary) GetSectionSummaries(section SecuritySummarySection) (summaries []formats.SummaryResults) {
	switch section {
	case Build:
		summaries = scs.BuildScanCommands
	case Binary:
		summaries = scs.ScanCommands
	case Modules:
		summaries = scs.AuditCommands
	}
	return
}

func ConvertSummaryToString(results SecurityCommandsSummary) (summary string, err error) {
	sectionsWithContent := results.GetOrderedSectionsWithContent()
	addSectionTitle := len(sectionsWithContent) > 1
	var sectionSummary string
	for i, section := range sectionsWithContent {
		if sectionSummary, err = convertScanSectionToString(results.GetSectionSummaries(section)...); err != nil {
			return
		}
		if addSectionTitle {
			if i > 0 {
				summary += "\n"
			}
			summary += fmt.Sprintf("#### %s\n", section)
		}
		summary += sectionSummary
	}
	return
}

func convertScanSectionToString(results ...formats.SummaryResults) (summary string, err error) {
	if len(results) == 0 {
		return
	}
	content, err := GetSummaryString(results...)
	if err != nil {
		return
	}
	summary = fmt.Sprintf("```\n%s\n```", content)
	return
}
