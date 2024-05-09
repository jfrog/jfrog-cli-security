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
	buildScanCommands []formats.SummaryResults
	scanCommands      []formats.SummaryResults
	auditCommands     []formats.SummaryResults
}

type B []ScanCommandSummaryResult

func SecurityCommandsGitHubSummary() *githubsummaries.GitHubActionSummaryImpl {
	return &githubsummaries.GitHubActionSummaryImpl{}
}

// func NewGitHubActionSummaryImpl(userImpl *githubsummaries.GithubSummaryInterface) *githubsummaries.GitHubActionSummaryImpl {
	// return &githubsummaries.GitHubActionSummaryImpl{userMethods: userImpl}
// }

func RecordSecurityCommandOutput(manager *githubsummaries.GitHubActionSummaryImpl, content ScanCommandSummaryResult) error {
	return githubsummaries.GithubSummaryRecordResult(content, githubsummaries.SecuritySection)
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
		aggregated.buildScanCommands = append(aggregated.buildScanCommands, data.Results)
	case Binary:
		aggregated.scanCommands = append(aggregated.scanCommands, data.Results)
	case Modules:
		aggregated.auditCommands = append(aggregated.auditCommands, data.Results)
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
	if len(scs.buildScanCommands) > 0 {
		count++
	}
	if len(scs.scanCommands) > 0 {
		count++
	}
	if len(scs.auditCommands) > 0 {
		count++
	}
	return
}

func ConvertSummaryToString(results SecurityCommandsSummary) (summary string) {
	addSectionTitle := results.GetSectionCount() > 1

	// Build-Scan Section
	summary += convertScanSectionToString(addSectionTitle, Build, results.buildScanCommands...)
	// Binary-Scan Section
	summary += convertScanSectionToString(addSectionTitle, Binary, results.scanCommands...)
	// Audit Section
	summary += convertScanSectionToString(addSectionTitle, Binary, results.auditCommands...)

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
