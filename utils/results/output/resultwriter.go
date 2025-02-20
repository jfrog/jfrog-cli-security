package output

import (
	"fmt"
	"os"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type ResultsWriter struct {
	// The scan commandResults.
	commandResults *results.SecurityCommandResults
	// PlatformUrl  The JFrog platform URL to generate GH analysis links.
	platformUrl string
	// Format  The output format.
	format format.OutputFormat
	// For build-scan where always we expect violations, to override the default behavior.
	showViolations bool
	// IsMultipleRoots  multipleRoots is set to true, in case the given results array contains (or may contain) results of several projects (like in binary scan).
	isMultipleRoots *bool
	// PrintExtended, If true, show extended results.
	printExtended bool
	// For table format - show table only for the given subScansPerformed
	subScansPerformed []utils.SubScanType
	// Messages - Option array of messages, to be displayed if the format is Table
	messages []string
}

func NewResultsWriter(scanResults *results.SecurityCommandResults) *ResultsWriter {
	return &ResultsWriter{commandResults: scanResults}
}

func (rw *ResultsWriter) SetOutputFormat(f format.OutputFormat) *ResultsWriter {
	rw.format = f
	return rw
}

func (rw *ResultsWriter) SetPlatformUrl(platformUrl string) *ResultsWriter {
	rw.platformUrl = platformUrl
	return rw
}

func (rw *ResultsWriter) SetIsMultipleRootProject(isMultipleRootProject bool) *ResultsWriter {
	rw.isMultipleRoots = &isMultipleRootProject
	return rw
}

func (rw *ResultsWriter) SetSubScansPerformed(subScansPerformed []utils.SubScanType) *ResultsWriter {
	rw.subScansPerformed = subScansPerformed
	return rw
}

func (rw *ResultsWriter) SetHasViolationContext(violationContext bool) *ResultsWriter {
	rw.showViolations = violationContext
	return rw
}

func (rw *ResultsWriter) SetPrintExtendedTable(extendedTable bool) *ResultsWriter {
	rw.printExtended = extendedTable
	return rw
}

func (rw *ResultsWriter) SetExtraMessages(messages []string) *ResultsWriter {
	rw.messages = messages
	return rw
}

func printMessages(messages []string) {
	if len(messages) > 0 {
		log.Output()
	}
	for _, m := range messages {
		printMessage(m)
	}
}

func printMessage(message string) {
	log.Output("💬" + message)
}

func isPrettyOutputSupported() bool {
	return log.IsStdOutTerminal() && log.IsColorsSupported() || os.Getenv("GITLAB_CI") != ""
}

// PrintScanResults prints the scan results in the specified format.
// Note that errors are printed only with SimpleJson format.
func (rw *ResultsWriter) PrintScanResults() error {
	if rw.commandResults.GetErrors() != nil && !rw.commandResults.HasInformation() {
		// Don't print if there are no results and only errors.
		return nil
	}
	// Helper for Debugging purposes, print the raw results to the log
	if err := rw.printRawResultsLog(); err != nil {
		return err
	}

	switch rw.format {
	case format.Table:
		return rw.printTables()
	case format.SimpleJson:
		// Helper for Debugging purposes, print the raw results to the log
		if err := rw.printRawResultsLog(); err != nil {
			return err
		}
		simpleJson, err := rw.createResultsConvertor(false).ConvertToSimpleJson(rw.commandResults)
		if err != nil {
			return err
		}
		return PrintJson(simpleJson)
	case format.Json:
		return PrintJson(rw.commandResults.GetScaScansXrayResults())
	case format.Sarif:
		// Helper for Debugging purposes, print the raw results to the log
		if err := rw.printRawResultsLog(); err != nil {
			return err
		}
		return rw.printSarif()
	}
	return nil
}

func (rw *ResultsWriter) createResultsConvertor(pretty bool) *conversion.CommandResultsConvertor {
	return conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		PlatformUrl:            rw.platformUrl,
		IsMultipleRoots:        rw.isMultipleRoots,
		IncludeLicenses:        rw.commandResults.IncludesLicenses(),
		IncludeVulnerabilities: rw.commandResults.IncludesVulnerabilities(),
		HasViolationContext:    rw.commandResults.HasViolationContext(),
		RequestedScans:         rw.subScansPerformed,
		Pretty:                 pretty,
	})
}

func (rw *ResultsWriter) printSarif() error {
	sarifContent, err := rw.createResultsConvertor(false).ConvertToSarif(rw.commandResults)
	if err != nil {
		return err
	}
	sarifFile, err := WriteSarifResultsAsString(sarifContent, false)
	if err != nil {
		return err
	}
	callback := log.SetAllowEmojiFlagWithCallback(true)
	log.Output(sarifFile)
	callback()
	return nil
}

func PrintJson(output interface{}) (err error) {
	results, err := utils.GetAsJsonString(output, true, true)
	if err != nil {
		return
	}
	log.Output(results)
	return nil
}

// Log (Debug) the inner results.SecurityCommandResults object object as a JSON string.
func (rw *ResultsWriter) printRawResultsLog() (err error) {
	if !rw.commandResults.HasInformation() {
		log.Debug("No information to print")
		return
	}
	// Print the raw results to console.
	var msg string
	if msg, err = utils.GetAsJsonString(rw.commandResults, false, true); err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Raw scan results:\n%s", msg))
	return
}

func (rw *ResultsWriter) printTables() (err error) {
	tableContent, err := rw.createResultsConvertor(isPrettyOutputSupported()).ConvertToTable(rw.commandResults)
	if err != nil {
		return
	}
	printMessages(rw.messages)
	if err = rw.printScaTablesIfNeeded(tableContent); err != nil {
		return
	}
	if err = rw.printJasTablesIfNeeded(tableContent, utils.SecretsScan, jasutils.Secrets); err != nil {
		return
	}
	if rw.shouldPrintSecretValidationExtraMessage() {
		log.Output("This table contains multiple secret types, such as tokens, generic password, ssh keys and more, token validation is only supported on tokens.")
	}
	if err = rw.printJasTablesIfNeeded(tableContent, utils.MaliciousCodeScan, jasutils.MaliciousCode); err != nil {
		return
	}
	if err = rw.printJasTablesIfNeeded(tableContent, utils.IacScan, jasutils.IaC); err != nil {
		return
	}
	return rw.printJasTablesIfNeeded(tableContent, utils.SastScan, jasutils.Sast)
}

func (rw *ResultsWriter) printScaTablesIfNeeded(tableContent formats.ResultsTables) (err error) {
	if !utils.IsScanRequested(rw.commandResults.CmdType, utils.ScaScan, rw.subScansPerformed...) {
		return
	}
	if rw.showViolations || rw.commandResults.HasViolationContext() {
		if err = PrintViolationsTable(tableContent, rw.commandResults.CmdType, rw.printExtended); err != nil {
			return
		}
	}
	if rw.commandResults.IncludesVulnerabilities() {
		if err = PrintVulnerabilitiesTable(tableContent, rw.commandResults.CmdType, len(rw.commandResults.GetTechnologies()) > 0, rw.printExtended); err != nil {
			return
		}
	}
	if !rw.commandResults.IncludesLicenses() {
		return
	}
	return PrintLicensesTable(tableContent, rw.printExtended, rw.commandResults.CmdType)
}

func (rw *ResultsWriter) printJasTablesIfNeeded(tableContent formats.ResultsTables, subScan utils.SubScanType, scanType jasutils.JasScanType) (err error) {
	if !utils.IsScanRequested(rw.commandResults.CmdType, subScan, rw.subScansPerformed...) {
		return
	}
	if rw.showViolations || rw.commandResults.HasViolationContext() {
		if err = PrintJasTable(tableContent, rw.commandResults.EntitledForJas, scanType, true); err != nil {
			return
		}
	}
	if !rw.commandResults.IncludesVulnerabilities() {
		return
	}
	return PrintJasTable(tableContent, rw.commandResults.EntitledForJas, scanType, false)
}

func (rw *ResultsWriter) shouldPrintSecretValidationExtraMessage() bool {
	return rw.commandResults.SecretValidation && utils.IsScanRequested(rw.commandResults.CmdType, utils.SecretsScan, rw.subScansPerformed...)
}

// PrintVulnerabilitiesTable prints the vulnerabilities in a table.
// Set printExtended to true to print fields with 'extended' tag.
// If the scan argument is set to true, print the scan tables.
func PrintVulnerabilitiesTable(tables formats.ResultsTables, cmdType utils.CommandType, techDetected, printExtended bool) error {
	// Space before the tables
	log.Output()
	if cmdType.IsTargetBinary() {
		return coreutils.PrintTable(formats.ConvertSecurityTableRowToScanTableRow(tables.SecurityVulnerabilitiesTable),
			"Vulnerable Components",
			"✨ No vulnerable components were found ✨",
			printExtended,
		)
	}
	emptyTableMessage := "✨ No vulnerable dependencies were found ✨"
	if !techDetected {
		emptyTableMessage = coreutils.PrintYellow("🔧 Couldn't determine a package manager or build tool used by this project 🔧")
	}
	return coreutils.PrintTable(tables.SecurityVulnerabilitiesTable, "Vulnerable Dependencies", emptyTableMessage, printExtended)
}

// PrintViolationsTable prints the violations in 4 tables: security violations, license compliance violations, operational risk violations and ignore rule URLs.
// Set printExtended to true to print fields with 'extended' tag.
// If the scan argument is set to true, print the scan tables.
func PrintViolationsTable(tables formats.ResultsTables, cmdType utils.CommandType, printExtended bool) (err error) {
	// Space before the tables
	log.Output()
	if cmdType.IsTargetBinary() {
		err = coreutils.PrintTable(formats.ConvertSecurityTableRowToScanTableRow(tables.SecurityViolationsTable), "Security Violations", "No security violations were found", printExtended)
		if err != nil {
			return err
		}
		err = coreutils.PrintTable(formats.ConvertLicenseViolationTableRowToScanTableRow(tables.LicenseViolationsTable), "License Compliance Violations", "No license compliance violations were found", printExtended)
		if err != nil {
			return err
		}
		return coreutils.PrintTable(formats.ConvertOperationalRiskTableRowToScanTableRow(tables.OperationalRiskViolationsTable), "Operational Risk Violations", "No operational risk violations were found", printExtended)
	}
	err = coreutils.PrintTable(tables.SecurityViolationsTable, "Security Violations", "No security violations were found", printExtended)
	if err != nil {
		return err
	}
	err = coreutils.PrintTable(tables.LicenseViolationsTable, "License Compliance Violations", "No license compliance violations were found", printExtended)
	if err != nil {
		return err
	}
	return coreutils.PrintTable(tables.OperationalRiskViolationsTable, "Operational Risk Violations", "No operational risk violations were found", printExtended)
}

// PrintLicensesTable prints the licenses in a table.
// Set multipleRoots to true in case the given licenses array contains (or may contain) results of several projects or files (like in binary scan).
// In case multipleRoots is true, the field Component will show the root of each impact path, otherwise it will show the root's child.
// Set printExtended to true to print fields with 'extended' tag.
// If the scan argument is set to true, print the scan tables.
func PrintLicensesTable(tables formats.ResultsTables, printExtended bool, cmdType utils.CommandType) error {
	// Space before the tables
	log.Output()
	if cmdType.IsTargetBinary() {
		return coreutils.PrintTable(formats.ConvertLicenseTableRowToScanTableRow(tables.LicensesTable), "Licenses", "No licenses were found", printExtended)
	}
	return coreutils.PrintTable(tables.LicensesTable, "Licenses", "No licenses were found", printExtended)
}

func PrintJasTable(tables formats.ResultsTables, entitledForJas bool, scanType jasutils.JasScanType, violations bool) error {
	if !entitledForJas {
		return nil
	}
	// Space before the tables
	log.Output()
	switch scanType {
	case jasutils.Secrets:
		if violations {
			return coreutils.PrintTable(tables.SecretsViolationsTable, "Secret Violations",
				"✨ No violations were found ✨", false)
		} else {
			return coreutils.PrintTable(tables.SecretsVulnerabilitiesTable, "Secret Detection",
				"✨ No secrets were found ✨", false)
		}
	case jasutils.IaC:
		if violations {
			return coreutils.PrintTable(tables.IacViolationsTable, "Infrastructure as Code Violations",
				"✨ No Infrastructure as Code violations were found ✨", false)
		} else {
			return coreutils.PrintTable(tables.IacVulnerabilitiesTable, "Infrastructure as Code Vulnerabilities",
				"✨ No Infrastructure as Code vulnerabilities were found ✨", false)
		}
	case jasutils.Sast:
		if violations {
			return coreutils.PrintTable(tables.SastViolationsTable, "Static Application Security Testing (SAST) Violations",
				"✨ No Static Application Security Testing violations were found ✨", false)
		} else {
			return coreutils.PrintTable(tables.SastVulnerabilitiesTable, "Static Application Security Testing (SAST)",
				"✨ No Static Application Security Testing vulnerabilities were found ✨", false)
		}
	case jasutils.MaliciousCode:
		if violations {
			return coreutils.PrintTable(tables.MaliciousViolationsTable, "Malicious Code Violations",
				"✨ No Malicious Code violations were found ✨", false)
		} else {
			return coreutils.PrintTable(tables.MaliciousVulnerabilitiesTable, "Malicious Code Detection",
				"✨ No Malicious Code vulnerabilities were found ✨", false)
		}
	}
	return nil
}

func WriteJsonResults(results *results.SecurityCommandResults) (resultsPath string, err error) {
	out, err := fileutils.CreateTempFile()
	if errorutils.CheckError(err) != nil {
		return
	}
	defer func() {
		e := out.Close()
		if err == nil {
			err = e
		}
	}()
	content, err := utils.GetAsJsonBytes(results, true, true)
	if err != nil {
		return
	}
	_, err = out.Write(content)
	if errorutils.CheckError(err) != nil {
		return
	}
	resultsPath = out.Name()
	return
}

func WriteSarifResultsAsString(report *sarif.Report, escape bool) (sarifStr string, err error) {
	return utils.GetAsJsonString(report, escape, true)
}
