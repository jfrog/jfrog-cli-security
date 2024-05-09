package utils

import (
	"encoding/json"
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/githubsummaries"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	Build   SecuritySummarySection = "Builds"
	Binary  SecuritySummarySection = "Binaries"
	Modules SecuritySummarySection = "Modules"
)

type SecuritySummarySection string

type ScanCommandSummaryResult struct {
	Section SecuritySummarySection
	Results formats.SummaryResults
}

type SecurityCommandsSummary struct {
	BuildScanCommands []formats.SummaryResults `json:"buildScanCommands,omitempty"`
	ScanCommands      []formats.SummaryResults `json:"scanCommands,omitempty"`
	AuditCommands     []formats.SummaryResults `json:"auditCommands,omitempty"`
}

type B []ScanCommandSummaryResult

func SecurityCommandsGitHubSummary() *githubsummaries.GitHubActionSummaryImpl {
	return githubsummaries.NewGitHubActionSummaryImpl(&SecurityCommandsSummary{
        BuildScanCommands: []formats.SummaryResults{},
        ScanCommands: []formats.SummaryResults{},
        AuditCommands: []formats.SummaryResults{},
    }) 
}

func RecordSecurityCommandOutput(manager *githubsummaries.GitHubActionSummaryImpl, content ScanCommandSummaryResult) error {
	return manager.RecordResult(content, githubsummaries.SecuritySection)
}

func (scs *SecurityCommandsSummary) GetSectionTitle() string {
	return "Security"
}

func (scs *SecurityCommandsSummary) AppendResultObject(output interface{}, previousObjects []byte) ([]byte, error) {
	// Unmarshal the aggregated data
	var aggregated SecurityCommandsSummary
	if len(previousObjects) > 0 {
		err := json.Unmarshal(previousObjects, &aggregated)
		if err != nil {
			return nil, err
		}
	}
	// Append the new data
	data := output.(ScanCommandSummaryResult)
	switch data.Section {
	case Build:
		aggregated.BuildScanCommands = append(aggregated.BuildScanCommands, data.Results)
	case Binary:
		aggregated.ScanCommands = append(aggregated.ScanCommands, data.Results)
	case Modules:
		aggregated.AuditCommands = append(aggregated.AuditCommands, data.Results)
	}
	return json.Marshal(aggregated)
}

func (scs *SecurityCommandsSummary) RenderContentToMarkdown(content []byte) (markdown string, err error) {
	// Unmarshal the data into an array of build info objects
	if err = json.Unmarshal(content, &scs); err != nil {
		log.Error("Failed to unmarshal data: ", err)
		return
	}
	markdown = ConvertSummaryToString(*scs)
	return
}

func (scs *SecurityCommandsSummary) GetSectionCount() (count int) {
	if len(scs.BuildScanCommands) > 0 {
		count++
	}
	if len(scs.ScanCommands) > 0 {
		count++
	}
	if len(scs.AuditCommands) > 0 {
		count++
	}
	return
}

func ConvertSummaryToString(results SecurityCommandsSummary) (summary string) {
	addSectionTitle := results.GetSectionCount() > 1

	// Build-Scan Section
	summary += convertScanSectionToString(addSectionTitle, Build, results.BuildScanCommands...)
	// Binary-Scan Section
	summary += convertScanSectionToString(addSectionTitle, Binary, results.ScanCommands...)
	// Audit Section
	summary += convertScanSectionToString(addSectionTitle, Binary, results.AuditCommands...)

	return
}

func convertScanSectionToString(addSectionTitle bool, title SecuritySummarySection, results ...formats.SummaryResults) (summary string) {
	if len(results) == 0 {
		return
	}
	if addSectionTitle {
		summary += fmt.Sprintf("### %s\n", title)
	}
	summary += fmt.Sprintf("```\n%s\n```", GetSummaryString(results...))
	return
}
