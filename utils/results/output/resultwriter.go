package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/slices"
)

const (
	BaseDocumentationURL = "https://docs.jfrog-applications.jfrog.io/jfrog-security-features/"
)

const MissingCveScore = "0"
const maxPossibleCve = 10.0

type ResultsWriter struct {
	// The scan commandResults.
	commandResults *results.ScanCommandResults
	// SimpleJsonError  Errors to be added to output of the SimpleJson format.
	simpleJsonError []formats.SimpleJsonError
	// Format  The output format.
	format format.OutputFormat
	// IncludeVulnerabilities  If true, include all vulnerabilities as part of the output. Else, include violations only.
	includeVulnerabilities bool
	// IncludeLicenses  If true, also include license violations as part of the output.
	includeLicenses bool
	// IsMultipleRoots  multipleRoots is set to true, in case the given results array contains (or may contain) results of several projects (like in binary scan).
	isMultipleRoots bool
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

// TODO: use in all commands, get from results? so no need any more after handling files base on scan type (Binary -> target, SourceCode -> descriptor)
func (rw *ResultsWriter) SetSimpleJsonError(jsonErrors []formats.SimpleJsonError) *ResultsWriter {
	rw.simpleJsonError = jsonErrors
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

func (rw *ResultsWriter) SetIsMultipleRootProject(isMultipleRootProject bool) *ResultsWriter {
	rw.isMultipleRoots = isMultipleRootProject
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

// PrintScanResults prints the scan results in the specified format.
// Note that errors are printed only with SimpleJson format.
func (rw *ResultsWriter) PrintScanResults() error {
	switch rw.format {
	case format.Table:
		return rw.printScanResultsTables()
	case format.SimpleJson:
		jsonTable, err := rw.convertScanToSimpleJson()
		if err != nil {
			return err
		}
		return PrintJson(jsonTable)
	case format.Json:
		return PrintJson(rw.commandResults.GetScaScansXrayResults())
	case format.Sarif:
		return PrintSarif(rw.commandResults, rw.isMultipleRoots, rw.includeLicenses)
	}
	return nil
}
func (rw *ResultsWriter) printScanResultsTables() (err error) {
	printMessages(rw.messages)
	violations, vulnerabilities, licenses := SplitScaScanResults(rw.commandResults)// SplitScanResults(rw.results.ScaResults)
	if rw.commandResults.HasInformation() { //IsIssuesFound() {
		var resultsPath string
		if resultsPath, err = writeJsonResults(rw.commandResults); err != nil {
			return
		}
		printMessage(coreutils.PrintTitle("The full scan results are available here: ") + coreutils.PrintLink(resultsPath))
	}
	log.Output()
	if rw.includeVulnerabilities {
		err = conversion.PrintVulnerabilitiesTable(vulnerabilities, rw.commandResults, rw.isMultipleRoots, rw.printExtended, rw.scanType)
	} else {
		err = conversion.PrintViolationsTable(violations, rw.commandResults, rw.isMultipleRoots, rw.printExtended, rw.scanType)
	}
	if err != nil {
		return
	}
	if rw.includeLicenses {
		if err = conversion.PrintLicensesTable(licenses, rw.printExtended, rw.scanType); err != nil {
			return
		}
	}
	if err = conversion.PrintSecretsTable(rw.commandResults.GetJasScansResults(jasutils.Secrets), rw.commandResults.EntitledForJas); err != nil {
		return
	}
	if err = conversion.PrintIacTable(rw.commandResults.GetJasScansResults(jasutils.IaC), rw.commandResults.EntitledForJas); err != nil {
		return
	}
	return conversion.PrintSastTable(rw.commandResults.GetJasScansResults(jasutils.Sast), rw.commandResults.EntitledForJas)

	// if err = PrintSecretsTable(rw.results.ExtendedScanResults.SecretsScanResults, rw.results.ExtendedScanResults.EntitledForJas); err != nil {
	// 	return
	// }
	// if err = PrintIacTable(rw.results.ExtendedScanResults.IacScanResults, rw.results.ExtendedScanResults.EntitledForJas); err != nil {
	// 	return
	// }
	// return PrintSastTable(rw.results.ExtendedScanResults.SastScanResults, rw.results.ExtendedScanResults.EntitledForJas)
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

func ConvertSarifReportToString(report *sarif.Report) (sarifStr string, err error) {
	out, err := json.Marshal(report)
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	return clientUtils.IndentJson(out), nil
}

func (rw *ResultsWriter) convertScanToSimpleJson() (formats.SimpleJsonResults, error) {
	jsonTable, err := ConvertXrayScanToSimpleJson(rw.commandResults, rw.isMultipleRoots, rw.includeLicenses, false, nil)
	if err != nil {
		return formats.SimpleJsonResults{}, err
	}
	
	if len(rw.commandResults.GetJasScansResults(jasutils.Secrets)) > 0 {
		jsonTable.Secrets = conversion.PrepareSecrets(rw.commandResults.GetJasScansResults(jasutils.Secrets))
	}
	if len(rw.commandResults.GetJasScansResults(jasutils.IaC)) > 0 {
		jsonTable.Iacs = conversion.PrepareIacs(rw.commandResults.GetJasScansResults(jasutils.IaC))
	}
	if len(rw.commandResults.GetJasScansResults(jasutils.Sast)) > 0 {
		jsonTable.Sast = conversion.PrepareSast(rw.commandResults.GetJasScansResults(jasutils.Sast))
	}
	jsonTable.Errors = rw.simpleJsonError

	return jsonTable, nil
}

func GetIssueIdentifier(cvesRow []formats.CveRow, issueId string) string {
	var identifier string
	if len(cvesRow) != 0 {
		var cvesBuilder strings.Builder
		for _, cve := range cvesRow {
			cvesBuilder.WriteString(cve.Id + ", ")
		}
		identifier = strings.TrimSuffix(cvesBuilder.String(), ", ")
	}
	if identifier == "" {
		identifier = issueId
	}

	return identifier
}

func getXrayIssueSarifRuleId(depName, version, key string) string {
	return fmt.Sprintf("%s_%s_%s", key, depName, version)
}

func getXrayIssueSarifHeadline(depName, version, key string) string {
	return fmt.Sprintf("[%s] %s %s", key, depName, version)
}

func getXrayLicenseSarifHeadline(depName, version, key string) string {
	return fmt.Sprintf("License violation [%s] %s %s", key, depName, version)
}

func getLicenseViolationSummary(depName, version, key string) string {
	return fmt.Sprintf("Dependency %s version %s is using a license (%s) that is not allowed.", depName, version, key)
}

func getLicenseViolationMarkdown(depName, version, key, formattedDirectDependencies string) string {
	return fmt.Sprintf("**The following direct dependencies are utilizing the `%s %s` dependency with `%s` license violation:**\n%s", depName, version, key, formattedDirectDependencies)
}

func getDirectDependenciesFormatted(directDependencies []formats.ComponentRow) (string, error) {
	var formattedDirectDependencies strings.Builder
	for _, dependency := range directDependencies {
		if _, err := formattedDirectDependencies.WriteString(fmt.Sprintf("`%s %s`<br/>", dependency.Name, dependency.Version)); err != nil {
			return "", err
		}
	}
	return strings.TrimSuffix(formattedDirectDependencies.String(), "<br/>"), nil
}

func getSarifTableDescription(formattedDirectDependencies, maxCveScore, applicable string, fixedVersions []string) string {
	descriptionFixVersions := "No fix available"
	if len(fixedVersions) > 0 {
		descriptionFixVersions = strings.Join(fixedVersions, ", ")
	}
	if applicable == jasutils.NotScanned.String() {
		return fmt.Sprintf("| Severity Score | Direct Dependencies | Fixed Versions     |\n| :---:        |    :----:   |          :---: |\n| %s      | %s       | %s   |",
			maxCveScore, formattedDirectDependencies, descriptionFixVersions)
	}
	return fmt.Sprintf("| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| %s      | %s       | %s       | %s   |",
		maxCveScore, applicable, formattedDirectDependencies, descriptionFixVersions)
}

func findMaxCVEScore(cves []formats.CveRow) (string, error) {
	maxCve := 0.0
	for _, cve := range cves {
		if cve.CvssV3 == "" {
			continue
		}
		floatCve, err := strconv.ParseFloat(cve.CvssV3, 32)
		if err != nil {
			return "", err
		}
		if floatCve > maxCve {
			maxCve = floatCve
		}
		// if found maximum possible cve score, no need to keep iterating
		if maxCve == maxPossibleCve {
			break
		}
	}
	strCve := fmt.Sprintf("%.1f", maxCve)

	return strCve, nil
}



// // Splits scan responses into aggregated lists of violations, vulnerabilities and licenses.
// func SplitScanResults(results []ScaScanResult) ([]services.Violation, []services.Vulnerability, []services.License) {
// 	var violations []services.Violation
// 	var vulnerabilities []services.Vulnerability
// 	var licenses []services.License
// 	for _, scan := range results {
// 		for _, result := range scan.XrayResults {
// 			violations = append(violations, result.Violations...)
// 			vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)
// 			licenses = append(licenses, result.Licenses...)
// 		}
// 	}
// 	return violations, vulnerabilities, licenses
// }

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

func PrintJson(output interface{}) error {
	results, err := json.Marshal(output)
	if err != nil {
		return errorutils.CheckError(err)
	}
	log.Output(clientUtils.IndentJson(results))
	return nil
}

func PrintSarif(results *results.ScanCommandResults, isMultipleRoots, includeLicenses bool) error {
	sarifReport, err := GenerateSarifReportFromResults(results, isMultipleRoots, includeLicenses, nil)
	if err != nil {
		return err
	}
	sarifFile, err := ConvertSarifReportToString(sarifReport)
	if err != nil {
		return err
	}
	log.Output(sarifFile)
	return nil
}

func CheckIfFailBuild(results []services.ScanResponse) bool {
	for _, result := range results {
		for _, violation := range result.Violations {
			if violation.FailBuild {
				return true
			}
		}
	}
	return false
}

func IsEmptyScanResponse(results []services.ScanResponse) bool {
	for _, result := range results {
		if len(result.Violations) > 0 || len(result.Vulnerabilities) > 0 || len(result.Licenses) > 0 {
			return false
		}
	}
	return true
}

func NewFailBuildError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeVulnerableBuild, ErrorMsg: "One or more of the violations found are set to fail builds that include them"}
}
