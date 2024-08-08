package utils

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
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
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
	// The scan results.
	results *Results
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
	// For table format - show table only for the given subScansPreformed
	subScansPreformed []SubScanType
	// Messages - Option array of messages, to be displayed if the format is Table
	messages []string
}

func NewResultsWriter(scanResults *Results) *ResultsWriter {
	return &ResultsWriter{results: scanResults}
}

func GetScaScanFileName(r *Results) string {
	if len(r.ScaResults) > 0 {
		return r.ScaResults[0].Target
	}
	return ""
}

func (rw *ResultsWriter) SetOutputFormat(f format.OutputFormat) *ResultsWriter {
	rw.format = f
	return rw
}

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

func (rw *ResultsWriter) SetSubScansPreformed(subScansPreformed []SubScanType) *ResultsWriter {
	rw.subScansPreformed = subScansPreformed
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
		return PrintJson(rw.results.GetScaScansXrayResults())
	case format.Sarif:
		return PrintSarif(rw.results, rw.isMultipleRoots, rw.includeLicenses)
	}
	return nil
}

func (rw *ResultsWriter) printScanResultsTables() (err error) {
	printMessages(rw.messages)
	violations, vulnerabilities, licenses := SplitScanResults(rw.results.ScaResults)
	if rw.results.IsIssuesFound() {
		var resultsPath string
		if resultsPath, err = writeJsonResults(rw.results); err != nil {
			return
		}
		printMessage(coreutils.PrintTitle("The full scan results are available here: ") + coreutils.PrintLink(resultsPath))
	}
	log.Output()
	if shouldPrintTable(rw.subScansPreformed, ScaScan, rw.results.ResultType) {
		if rw.includeVulnerabilities {
			err = PrintVulnerabilitiesTable(vulnerabilities, rw.results, rw.isMultipleRoots, rw.printExtended, rw.results.ResultType)
		} else {
			err = PrintViolationsTable(violations, rw.results, rw.isMultipleRoots, rw.printExtended)
		}
		if err != nil {
			return
		}
		if rw.includeLicenses {
			if err = PrintLicensesTable(licenses, rw.printExtended, rw.results.ResultType); err != nil {
				return
			}
		}
	}
	if shouldPrintTable(rw.subScansPreformed, SecretsScan, rw.results.ResultType) {
		if err = PrintSecretsTable(rw.results.ExtendedScanResults.SecretsScanResults, rw.results.ExtendedScanResults.EntitledForJas); err != nil {
			return
		}
	}
	if shouldPrintTable(rw.subScansPreformed, IacScan, rw.results.ResultType) {
		if err = PrintIacTable(rw.results.ExtendedScanResults.IacScanResults, rw.results.ExtendedScanResults.EntitledForJas); err != nil {
			return
		}
	}
	if !shouldPrintTable(rw.subScansPreformed, SastScan, rw.results.ResultType) {
		return nil
	}
	return PrintSastTable(rw.results.ExtendedScanResults.SastScanResults, rw.results.ExtendedScanResults.EntitledForJas)
}

func shouldPrintTable(requestedScans []SubScanType, subScan SubScanType, scanType CommandType) bool {
	if (scanType == Binary || scanType == DockerImage) && (subScan == IacScan || subScan == SastScan) {
		return false
	}
	return len(requestedScans) == 0 || slices.Contains(requestedScans, subScan)
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

func GenerateSarifReportFromResults(results *Results, isMultipleRoots, includeLicenses bool, allowedLicenses []string) (report *sarif.Report, err error) {
	report, err = sarifutils.NewReport()
	if err != nil {
		return
	}
	xrayRun, err := convertXrayResponsesToSarifRun(results, isMultipleRoots, includeLicenses, allowedLicenses)
	if err != nil {
		return
	}

	report.Runs = append(report.Runs, xrayRun)
	report.Runs = append(report.Runs, patchRunsToPassIngestionRules(results.ExtendedScanResults.ApplicabilityScanResults)...)
	report.Runs = append(report.Runs, patchRunsToPassIngestionRules(results.ExtendedScanResults.IacScanResults)...)
	report.Runs = append(report.Runs, patchRunsToPassIngestionRules(results.ExtendedScanResults.SecretsScanResults)...)
	report.Runs = append(report.Runs, patchRunsToPassIngestionRules(results.ExtendedScanResults.SastScanResults)...)

	return
}

func patchRunsToPassIngestionRules(runs []*sarif.Run) []*sarif.Run {
	for _, run := range runs {
		for _, rule := range run.Tool.Driver.Rules {
			// Github code scanning ingestion rules rejects rules without help content, transfer fullDescription if not exists
			if rule.Help == nil && rule.FullDescription != nil {
				rule.Help = rule.FullDescription
			}
		}
		// Github code scanning ingestion rules rejects results without locations, remove them
		results := []*sarif.Result{}
		for _, result := range run.Results {
			if len(result.Locations) == 0 {
				continue
			}
			results = append(results, result)
		}
		run.Results = results
	}
	// Since we run in temp directories files should be relative
	convertToRelativePath(runs)
	return runs
}

func convertToRelativePath(runs []*sarif.Run) {
	for _, run := range runs {
		for _, result := range run.Results {
			for _, location := range result.Locations {
				sarifutils.SetLocationFileName(location, sarifutils.GetRelativeLocationFileName(location, run.Invocations))
			}
			for _, flows := range result.CodeFlows {
				for _, flow := range flows.ThreadFlows {
					for _, location := range flow.Locations {
						sarifutils.SetLocationFileName(location.Location, sarifutils.GetRelativeLocationFileName(location.Location, run.Invocations))
					}
				}
			}
		}
	}
}

func convertXrayResponsesToSarifRun(results *Results, isMultipleRoots, includeLicenses bool, allowedLicenses []string) (run *sarif.Run, err error) {
	xrayJson, err := ConvertXrayScanToSimpleJson(results, isMultipleRoots, includeLicenses, true, allowedLicenses)
	if err != nil {
		return
	}
	xrayRun := sarif.NewRunWithInformationURI("JFrog Xray SCA", BaseDocumentationURL+"sca")
	xrayRun.Tool.Driver.Version = &results.XrayVersion
	if len(xrayJson.Vulnerabilities) > 0 || len(xrayJson.SecurityViolations) > 0 || len(xrayJson.LicensesViolations) > 0 {
		if err = extractXrayIssuesToSarifRun(xrayRun, xrayJson); err != nil {
			return
		}
	}
	run = xrayRun
	return
}

func extractXrayIssuesToSarifRun(run *sarif.Run, xrayJson formats.SimpleJsonResults) error {
	for _, vulnerability := range xrayJson.Vulnerabilities {
		if err := addXrayCveIssueToSarifRun(vulnerability, run); err != nil {
			return err
		}
	}
	for _, violation := range xrayJson.SecurityViolations {
		if err := addXrayCveIssueToSarifRun(violation, run); err != nil {
			return err
		}
	}
	for _, license := range xrayJson.LicensesViolations {
		if err := addXrayLicenseViolationToSarifRun(license, run); err != nil {
			return err
		}
	}
	return nil
}

func addXrayCveIssueToSarifRun(issue formats.VulnerabilityOrViolationRow, run *sarif.Run) (err error) {
	maxCveScore, err := findMaxCVEScore(issue.Cves)
	if err != nil {
		return
	}
	location, err := getXrayIssueLocationIfValidExists(issue.Technology, run)
	if err != nil {
		return
	}
	formattedDirectDependencies, err := getDirectDependenciesFormatted(issue.Components)
	if err != nil {
		return
	}
	cveId := GetIssueIdentifier(issue.Cves, issue.IssueId)
	markdownDescription := getSarifTableDescription(formattedDirectDependencies, maxCveScore, issue.Applicable, issue.FixedVersions)
	addXrayIssueToSarifRun(
		cveId,
		issue.ImpactedDependencyName,
		issue.ImpactedDependencyVersion,
		severityutils.GetSeverity(issue.Severity),
		maxCveScore,
		issue.Summary,
		getXrayIssueSarifHeadline(issue.ImpactedDependencyName, issue.ImpactedDependencyVersion, cveId),
		markdownDescription,
		issue.Components,
		location,
		run,
	)
	return
}

func addXrayLicenseViolationToSarifRun(license formats.LicenseRow, run *sarif.Run) (err error) {
	formattedDirectDependencies, err := getDirectDependenciesFormatted(license.Components)
	if err != nil {
		return
	}
	addXrayIssueToSarifRun(
		license.LicenseKey,
		license.ImpactedDependencyName,
		license.ImpactedDependencyVersion,
		severityutils.GetSeverity(license.Severity),
		MissingCveScore,
		getLicenseViolationSummary(license.ImpactedDependencyName, license.ImpactedDependencyVersion, license.LicenseKey),
		getXrayLicenseSarifHeadline(license.ImpactedDependencyName, license.ImpactedDependencyVersion, license.LicenseKey),
		getLicenseViolationMarkdown(license.ImpactedDependencyName, license.ImpactedDependencyVersion, license.LicenseKey, formattedDirectDependencies),
		license.Components,
		getXrayIssueLocation(""),
		run,
	)
	return
}

func addXrayIssueToSarifRun(issueId, impactedDependencyName, impactedDependencyVersion string, severity severityutils.Severity, severityScore, summary, title, markdownDescription string, components []formats.ComponentRow, location *sarif.Location, run *sarif.Run) {
	// Add rule if not exists
	ruleId := getXrayIssueSarifRuleId(impactedDependencyName, impactedDependencyVersion, issueId)
	if rule, _ := run.GetRuleById(ruleId); rule == nil {
		addXrayRule(ruleId, title, severityScore, summary, markdownDescription, run)
	}
	// Add result for each component

	for _, directDependency := range components {
		msg := getXrayIssueSarifHeadline(directDependency.Name, directDependency.Version, issueId)
		if result := run.CreateResultForRule(ruleId).WithMessage(sarif.NewTextMessage(msg)).WithLevel(severityutils.SeverityToSarifSeverityLevel(severity).String()); location != nil {
			result.AddLocation(location)
		}
	}

}

func getDescriptorFullPath(tech techutils.Technology, run *sarif.Run) (string, error) {
	descriptors := tech.GetPackageDescriptor()
	if len(descriptors) == 1 {
		// Generate the full path
		return sarifutils.GetFullLocationFileName(strings.TrimSpace(descriptors[0]), run.Invocations), nil
	}
	for _, descriptor := range descriptors {
		// If multiple options return first to match
		absolutePath := sarifutils.GetFullLocationFileName(strings.TrimSpace(descriptor), run.Invocations)
		if exists, err := fileutils.IsFileExists(absolutePath, false); err != nil {
			return "", err
		} else if exists {
			return absolutePath, nil
		}
	}
	return "", nil
}

// Get the descriptor location with the Xray issues if exists.
func getXrayIssueLocationIfValidExists(tech techutils.Technology, run *sarif.Run) (location *sarif.Location, err error) {
	descriptorPath, err := getDescriptorFullPath(tech, run)
	if err != nil {
		return
	}
	return getXrayIssueLocation(descriptorPath), nil
}

func getXrayIssueLocation(filePath string) *sarif.Location {
	if strings.TrimSpace(filePath) == "" {
		filePath = "Package-Descriptor"
	}
	return sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://" + filePath)))
}

func addXrayRule(ruleId, ruleDescription, maxCveScore, summary, markdownDescription string, run *sarif.Run) {
	rule := run.AddRule(ruleId)

	if maxCveScore != MissingCveScore {
		cveRuleProperties := sarif.NewPropertyBag()
		cveRuleProperties.Add(severityutils.SarifSeverityRuleProperty, maxCveScore)
		rule.WithProperties(cveRuleProperties.Properties)
	}

	rule.WithDescription(ruleDescription)
	rule.WithHelp(&sarif.MultiformatMessageString{
		Text:     &summary,
		Markdown: &markdownDescription,
	})
}

func ConvertXrayScanToSimpleJson(results *Results, isMultipleRoots, includeLicenses, simplifiedOutput bool, allowedLicenses []string) (formats.SimpleJsonResults, error) {
	violations, vulnerabilities, licenses := SplitScanResults(results.ScaResults)
	jsonTable := formats.SimpleJsonResults{}
	if len(vulnerabilities) > 0 {
		vulJsonTable, err := PrepareVulnerabilities(vulnerabilities, results, isMultipleRoots, simplifiedOutput)
		if err != nil {
			return formats.SimpleJsonResults{}, err
		}
		jsonTable.Vulnerabilities = vulJsonTable
	}
	if includeLicenses || len(allowedLicenses) > 0 {
		licJsonTable, err := PrepareLicenses(licenses)
		if err != nil {
			return formats.SimpleJsonResults{}, err
		}
		if includeLicenses {
			jsonTable.Licenses = licJsonTable
		}
		jsonTable.LicensesViolations = GetViolatedLicenses(allowedLicenses, licJsonTable)
	}
	if len(violations) > 0 {
		secViolationsJsonTable, licViolationsJsonTable, opRiskViolationsJsonTable, err := PrepareViolations(violations, results, isMultipleRoots, simplifiedOutput)
		if err != nil {
			return formats.SimpleJsonResults{}, err
		}
		jsonTable.SecurityViolations = secViolationsJsonTable
		jsonTable.LicensesViolations = licViolationsJsonTable
		jsonTable.OperationalRiskViolations = opRiskViolationsJsonTable
	}
	jsonTable.MultiScanId = results.MultiScanId
	return jsonTable, nil
}

func GetViolatedLicenses(allowedLicenses []string, licenses []formats.LicenseRow) (violatedLicenses []formats.LicenseRow) {
	if len(allowedLicenses) == 0 {
		return
	}
	for _, license := range licenses {
		if !slices.Contains(allowedLicenses, license.LicenseKey) {
			violatedLicenses = append(violatedLicenses, license)
		}
	}
	return
}

func (rw *ResultsWriter) convertScanToSimpleJson() (formats.SimpleJsonResults, error) {
	jsonTable, err := ConvertXrayScanToSimpleJson(rw.results, rw.isMultipleRoots, rw.includeLicenses, false, nil)
	if err != nil {
		return formats.SimpleJsonResults{}, err
	}
	if len(rw.results.ExtendedScanResults.SecretsScanResults) > 0 {
		jsonTable.Secrets = PrepareSecrets(rw.results.ExtendedScanResults.SecretsScanResults)
	}
	if len(rw.results.ExtendedScanResults.IacScanResults) > 0 {
		jsonTable.Iacs = PrepareIacs(rw.results.ExtendedScanResults.IacScanResults)
	}
	if len(rw.results.ExtendedScanResults.SastScanResults) > 0 {
		jsonTable.Sast = PrepareSast(rw.results.ExtendedScanResults.SastScanResults)
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

// Splits scan responses into aggregated lists of violations, vulnerabilities and licenses.
func SplitScanResults(results []*ScaScanResult) ([]services.Violation, []services.Vulnerability, []services.License) {
	var violations []services.Violation
	var vulnerabilities []services.Vulnerability
	var licenses []services.License
	for _, scan := range results {
		for _, result := range scan.XrayResults {
			violations = append(violations, result.Violations...)
			vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)
			licenses = append(licenses, result.Licenses...)
		}
	}
	return violations, vulnerabilities, licenses
}

func writeJsonResults(results *Results) (resultsPath string, err error) {
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
	bytesRes, err := JSONMarshal(&results)
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

func JSONMarshal(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}

func PrintJson(output interface{}) error {
	results, err := JSONMarshal(output)
	if err != nil {
		return errorutils.CheckError(err)
	}
	log.Output(clientUtils.IndentJson(results))
	return nil
}

func PrintSarif(results *Results, isMultipleRoots, includeLicenses bool) error {
	sarifReport, err := GenerateSarifReportFromResults(results, isMultipleRoots, includeLicenses, nil)
	if err != nil {
		return err
	}
	sarifFile, err := sarifutils.ConvertSarifReportToString(sarifReport)
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
