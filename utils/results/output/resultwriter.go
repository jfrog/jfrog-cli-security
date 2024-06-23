package output

import (
	"bytes"
	"encoding/json"
	"os"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

// const (
// 	securityViolationTitle := "Security Violations"
// 	noSecurityViolationMessage := "No security violations were found"
// 	licenseViolationTitle := "License Compliance Violations"
// 	noLicenseViolationMessage := "No license compliance violations were found"
// 	operationalRiskViolationTitle := "Operational Risk Violations"
// 	noOperationalRiskViolationMessage := "No operational risk violations were found"
// )

type ResultsWriter struct {
	// The scan commandResults.
	commandResults *results.ScanCommandResults
	// Format  The output format.
	format format.OutputFormat
	// IncludeVulnerabilities  If true, include all vulnerabilities as part of the output. Else, include violations only.
	includeVulnerabilities bool
	// IncludeLicenses  If true, also include license violations as part of the output.
	includeLicenses bool
	// PrintExtended, If true, show extended results.
	printExtended bool
	// The scanType (binary,dependency)
	scanType services.ScanType
	// Messages - Option array of messages, to be displayed if the format is Table
	messages []string
}

func NewResultsWriter(scanResults *results.ScanCommandResults) *ResultsWriter {
	return &ResultsWriter{commandResults: scanResults}
}

func (rw *ResultsWriter) SetOutputFormat(f format.OutputFormat) *ResultsWriter {
	rw.format = f
	return rw
}

func (rw *ResultsWriter) SetScanType(scanType services.ScanType) *ResultsWriter {
	rw.scanType = scanType
	return rw
}

func (rw *ResultsWriter) SetIncludeVulnerabilities(includeVulnerabilities bool) *ResultsWriter {
	rw.includeVulnerabilities = includeVulnerabilities
	return rw
}

func (rw *ResultsWriter) SetIncludeLicenses(licenses bool) *ResultsWriter {
	rw.includeLicenses = licenses
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
	switch rw.format {
	case format.Table:
		return rw.printTables()
	case format.SimpleJson:
		simpleJson, err := rw.createResultsConvertor(false).ConvertToSimpleJson(rw.commandResults)
		if err != nil {
			return err
		}
		return PrintJson(simpleJson)
	case format.Json:
		if rw.printExtended {
			return PrintJson(rw.commandResults)
		}
		return PrintJson(rw.commandResults.GetScaScansXrayResults())
	case format.Sarif:
		return rw.printSarif()
	}
	return nil
}

func (rw *ResultsWriter) createResultsConvertor(pretty bool) *conversion.CommandResultsConvertor {
	return conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeLicenses:              rw.includeLicenses,
		IncludeVulnerabilities:       rw.includeVulnerabilities,
		Pretty:                       pretty,
		AllowResultsWithoutLocations: true,
	})
}

func (rw *ResultsWriter) printSarif() error {
	sarifContent, err := rw.createResultsConvertor(false).ConvertToSarif(rw.commandResults)
	if err != nil {
		return err
	}
	sarifFile, err := sarifutils.ConvertSarifReportToString(sarifContent)
	if err != nil {
		return err
	}
	log.Output(sarifFile)
	return nil
}

func PrintJson(output interface{}) (err error) {
	results, err := utils.GetAsJsonString(output)
	if err != nil {
		return
	}
	log.Output(results)
	return nil
}

func (rw *ResultsWriter) printTables() (err error) {
	tableContent, err := rw.createResultsConvertor(isPrettyOutputSupported()).ConvertToTable(rw.commandResults)
	if err != nil {
		return
	}
	printMessages(rw.messages)
	if rw.commandResults.HasInformation() {
		var resultsPath string
		if resultsPath, err = writeJsonResults(rw.commandResults); err != nil {
			return
		}
		printMessage(coreutils.PrintTitle("The full scan results are available here: ") + coreutils.PrintLink(resultsPath))
	}
	log.Output()
	if rw.includeVulnerabilities {
		err = PrintVulnerabilitiesTable(tableContent, rw.scanType, len(rw.commandResults.GetTechnologies()) > 0, rw.printExtended)
	} else {
		err = PrintViolationsTable(tableContent, rw.scanType, rw.printExtended)
	}
	if err != nil {
		return
	}
	if rw.includeLicenses {
		if err = PrintLicensesTable(tableContent, rw.printExtended, rw.scanType); err != nil {
			return
		}
	}
	if err = PrintJasTable(tableContent, rw.commandResults.EntitledForJas, jasutils.Secrets); err != nil {
		return
	}
	if err = PrintJasTable(tableContent, rw.commandResults.EntitledForJas, jasutils.IaC); err != nil {
		return
	}
	return PrintJasTable(tableContent, rw.commandResults.EntitledForJas, jasutils.Sast)
}

// PrintVulnerabilitiesTable prints the vulnerabilities in a table.
// Set printExtended to true to print fields with 'extended' tag.
// If the scan argument is set to true, print the scan tables.
func PrintVulnerabilitiesTable(tables formats.ResultsTables, scanType services.ScanType, techDetected, printExtended bool) error {
	if scanType == services.Binary {
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
func PrintViolationsTable(tables formats.ResultsTables, scanType services.ScanType, printExtended bool) (err error) {
	if scanType == services.Binary {
		err = coreutils.PrintTable(formats.ConvertSecurityTableRowToScanTableRow(tables.SecurityVulnerabilitiesTable), "Security Violations", "No security violations were found", printExtended)
		if err != nil {
			return err
		}
		err = coreutils.PrintTable(formats.ConvertLicenseViolationTableRowToScanTableRow(tables.LicenseViolationsTable), "License Compliance Violations", "No license compliance violations were found", printExtended)
		if err != nil {
			return err
		}
		if len(tables.OperationalRiskViolationsTable) > 0 {
			return coreutils.PrintTable(formats.ConvertOperationalRiskTableRowToScanTableRow(tables.OperationalRiskViolationsTable), "Operational Risk Violations", "No operational risk violations were found", printExtended)
		}
	} else {
		err = coreutils.PrintTable(tables.SecurityVulnerabilitiesTable, "Security Violations", "No security violations were found", printExtended)
		if err != nil {
			return err
		}
		err = coreutils.PrintTable(tables.LicenseViolationsTable, "License Compliance Violations", "No license compliance violations were found", printExtended)
		if err != nil {
			return err
		}
		if len(tables.OperationalRiskViolationsTable) > 0 {
			return coreutils.PrintTable(tables.OperationalRiskViolationsTable, "Operational Risk Violations", "No operational risk violations were found", printExtended)
		}
	}
	return nil
}

// PrintLicensesTable prints the licenses in a table.
// Set multipleRoots to true in case the given licenses array contains (or may contain) results of several projects or files (like in binary scan).
// In case multipleRoots is true, the field Component will show the root of each impact path, otherwise it will show the root's child.
// Set printExtended to true to print fields with 'extended' tag.
// If the scan argument is set to true, print the scan tables.
func PrintLicensesTable(tables formats.ResultsTables, printExtended bool, scanType services.ScanType) error {
	if scanType == services.Binary {
		return coreutils.PrintTable(formats.ConvertLicenseTableRowToScanTableRow(tables.LicensesTable), "Licenses", "No licenses were found", printExtended)
	}
	return coreutils.PrintTable(tables.LicensesTable, "Licenses", "No licenses were found", printExtended)
}

func PrintJasTable(tables formats.ResultsTables, entitledForJas bool, scanType jasutils.JasScanType) error {
	if !entitledForJas {
		return nil
	}
	log.Output()
	switch scanType {
	case jasutils.Secrets:
		return coreutils.PrintTable(tables.SecretsTable, "Secret Detection",
			"✨ No secrets were found ✨", false)
	case jasutils.IaC:
		return coreutils.PrintTable(tables.IacTable, "Infrastructure as Code Vulnerabilities",
			"✨ No Infrastructure as Code vulnerabilities were found ✨", false)
	case jasutils.Sast:
		return coreutils.PrintTable(tables.SastTable, "Static Application Security Testing (SAST)",
			"✨ No Static Application Security Testing vulnerabilities were found ✨", false)
	}
	return nil
}

func writeJsonResults(results *results.ScanCommandResults) (resultsPath string, err error) {
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
	bytesRes, err := json.Marshal(&results)
	if errorutils.CheckError(err) != nil {
		return
	}
	var content bytes.Buffer
	err = json.Indent(&content, bytesRes, "", "  ")
	if errorutils.CheckError(err) != nil {
		return
	}
	_, err = out.Write(content.Bytes())
	if errorutils.CheckError(err) != nil {
		return
	}
	resultsPath = out.Name()
	return
}
