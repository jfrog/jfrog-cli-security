package utils

import (
	"encoding/json"
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/jobsummaries"
	"github.com/jfrog/jfrog-cli-security/formats"
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

func SecurityCommandsJobSummary() (js *jobsummaries.JobSummary, err error) {
	return jobsummaries.NewJobSummaryImpl(&SecurityCommandsSummary{
		BuildScanCommands: []formats.SummaryResults{},
		ScanCommands:      []formats.SummaryResults{},
		AuditCommands:     []formats.SummaryResults{},
	})
}

func RecordSecurityCommandOutput(content ScanCommandSummaryResult) (err error) {
	manager, err := SecurityCommandsJobSummary()
	if err != nil || manager == nil {
		return
	}
	return manager.RecordResult(content, jobsummaries.SecuritySection)
}

func (scs *SecurityCommandsSummary) GetSectionTitle() string {
	return "🛡️ Security scans preformed by this job"
}

func (scs *SecurityCommandsSummary) AppendResultObject(output interface{}, previousObjects []byte) (result []byte, err error) {
	// Unmarshal the aggregated data
	var aggregated SecurityCommandsSummary
	if len(previousObjects) > 0 {
		if err = json.Unmarshal(previousObjects, &aggregated); err != nil {
			return
		}
	}
	// Append the new data
	data, ok := output.(ScanCommandSummaryResult)
	if !ok {
		err = fmt.Errorf("failed to cast output to ScanCommandSummaryResult")
		return
	}
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
		return "", fmt.Errorf("failed while creating security markdown: %w", err)
	}
	return ConvertSummaryToString(*scs)
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

func ConvertSummaryToString(results SecurityCommandsSummary) (summary string, err error) {
	addSectionTitle := results.GetSectionCount() > 1

	// Build-Scan Section
	buildSummary, err := convertScanSectionToString(addSectionTitle, Build, results.BuildScanCommands...)
	if err != nil {
		return
	}
	summary += buildSummary
	// Binary-Scan Section
	binarySummary, err := convertScanSectionToString(addSectionTitle, Binary, results.ScanCommands...)
	if err != nil {
		return
	}
	summary += binarySummary
	// Audit Section
	modulesSummary, err := convertScanSectionToString(addSectionTitle, Modules, results.AuditCommands...)
	if err != nil {
		return
	}
	summary += modulesSummary

	return
}

func convertScanSectionToString(addSectionTitle bool, title SecuritySummarySection, results ...formats.SummaryResults) (summary string, err error) {
	if len(results) == 0 {
		return
	}
	content, err := GetSummaryString(results...)
	if err != nil {
		return
	}
	if addSectionTitle {
		summary += fmt.Sprintf("\n#### %s\n", title)
	}
	summary += fmt.Sprintf("```\n%s\n```", content)
	return
}
