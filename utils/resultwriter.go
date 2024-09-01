package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
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
	BaseDocumentationURL           = "https://docs.jfrog-applications.jfrog.io/jfrog-security-features/"
	CurrentWorkflowNameEnvVar      = "GITHUB_WORKFLOW"
	CurrentWorkflowRunNumberEnvVar = "GITHUB_RUN_NUMBER"

	MissingCveScore = "0"
	maxPossibleCve  = 10.0

	patchedBinarySecretScannerToolName = "JFrog Binary Secrets Scanner"
	jfrogFingerprintAlgorithmName      = "jfrogFingerprintHash"
)

var (
	GithubBaseWorkflowDir         = filepath.Join(".github", "workflows")
	dockerJasLocationPathPattern  = regexp.MustCompile(`.*[\\/](?P<algorithm>[^\\/]+)[\\/](?P<hash>[0-9a-fA-F]+)[\\/](?P<relativePath>.*)`)
	dockerScaComponentNamePattern = regexp.MustCompile(`(?P<algorithm>[^__]+)__(?P<hash>[0-9a-fA-F]+)\.tar`)
)

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

	report.Runs = append(report.Runs, patchRunsToPassIngestionRules(ScaScan, results, xrayRun)...)
	report.Runs = append(report.Runs, patchRunsToPassIngestionRules(IacScan, results, results.ExtendedScanResults.IacScanResults...)...)
	report.Runs = append(report.Runs, patchRunsToPassIngestionRules(SecretsScan, results, results.ExtendedScanResults.SecretsScanResults...)...)
	report.Runs = append(report.Runs, patchRunsToPassIngestionRules(SastScan, results, results.ExtendedScanResults.SastScanResults...)...)

	return
}

func convertXrayResponsesToSarifRun(results *Results, isMultipleRoots, includeLicenses bool, allowedLicenses []string) (run *sarif.Run, err error) {
	xrayJson, err := ConvertXrayScanToSimpleJson(results, isMultipleRoots, includeLicenses, true, allowedLicenses)
	if err != nil {
		return
	}
	xrayRun := sarif.NewRunWithInformationURI("JFrog Xray Scanner", BaseDocumentationURL+"sca")
	xrayRun.Tool.Driver.Version = &results.XrayVersion
	if len(xrayJson.Vulnerabilities) > 0 || len(xrayJson.SecurityViolations) > 0 || len(xrayJson.LicensesViolations) > 0 {
		if err = extractXrayIssuesToSarifRun(results, xrayRun, xrayJson); err != nil {
			return
		}
	}
	run = xrayRun
	return
}

func extractXrayIssuesToSarifRun(results *Results, run *sarif.Run, xrayJson formats.SimpleJsonResults) error {
	for _, vulnerability := range xrayJson.Vulnerabilities {
		if err := addXrayCveIssueToSarifRun(results, vulnerability, run); err != nil {
			return err
		}
	}
	for _, violation := range xrayJson.SecurityViolations {
		if err := addXrayCveIssueToSarifRun(results, violation, run); err != nil {
			return err
		}
	}
	for _, license := range xrayJson.LicensesViolations {
		if err := addXrayLicenseViolationToSarifRun(results, license, run); err != nil {
			return err
		}
	}
	return nil
}

func addXrayCveIssueToSarifRun(results *Results, issue formats.VulnerabilityOrViolationRow, run *sarif.Run) (err error) {
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
		results.ResultType,
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

func addXrayLicenseViolationToSarifRun(results *Results, license formats.LicenseRow, run *sarif.Run) (err error) {
	formattedDirectDependencies, err := getDirectDependenciesFormatted(license.Components)
	if err != nil {
		return
	}
	addXrayIssueToSarifRun(
		results.ResultType,
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

func addXrayIssueToSarifRun(resultType CommandType, issueId, impactedDependencyName, impactedDependencyVersion string, severity severityutils.Severity, severityScore, summary, title, markdownDescription string, components []formats.ComponentRow, location *sarif.Location, run *sarif.Run) {
	// Add rule if not exists
	ruleId := getXrayIssueSarifRuleId(impactedDependencyName, impactedDependencyVersion, issueId)
	if rule, _ := run.GetRuleById(ruleId); rule == nil {
		addXrayRule(ruleId, title, severityScore, summary, markdownDescription, run)
	}
	// Add result for each component
	for _, directDependency := range components {
		msg := getXrayIssueSarifHeadline(directDependency.Name, directDependency.Version, issueId)
		if result := run.CreateResultForRule(ruleId).WithMessage(sarif.NewTextMessage(msg)).WithLevel(severityutils.SeverityToSarifSeverityLevel(severity).String()); location != nil {
			if resultType == DockerImage {
				algorithm, layer := getLayerContentFromComponentId(directDependency.Name)
				if layer != "" {
					logicalLocation := sarifutils.NewLogicalLocation(layer, "layer")
					if algorithm != "" {
						logicalLocation.Properties = map[string]interface{}{"algorithm": algorithm}
					}
					location.LogicalLocations = append(location.LogicalLocations, logicalLocation)
				}
			}
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
	return strings.TrimSpace(fmt.Sprintf("[%s] %s %s", key, depName, version))
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

func patchRules(subScanType SubScanType, cmdResults *Results, rules ...*sarif.ReportingDescriptor) (patched []*sarif.ReportingDescriptor) {
	patched = []*sarif.ReportingDescriptor{}
	for _, rule := range rules {
		// Github code scanning ingestion rules rejects rules without help content.
		// Patch by transferring the full description to the help field.
		if rule.Help == nil && rule.FullDescription != nil {
			rule.Help = rule.FullDescription
		}
		// SARIF1001 - if both 'id' and 'name' are present, they must be different. If they are identical, the tool must omit the 'name' property.
		if rule.Name != nil && rule.ID == *rule.Name {
			rule.Name = nil
		}
		if cmdResults.ResultType.IsTargetBinary() && subScanType == SecretsScan {
			// Patch the rule name in case of binary scan
			sarifutils.SetRuleShortDescriptionText(fmt.Sprintf("[Secret in Binary found] %s", sarifutils.GetRuleShortDescriptionText(rule)), rule)
		}
		patched = append(patched, rule)
	}
	return
}

func patchResults(subScanType SubScanType, cmdResults *Results, run *sarif.Run, results ...*sarif.Result) (patched []*sarif.Result) {
	patched = []*sarif.Result{}
	for _, result := range results {
		if len(result.Locations) == 0 {
			// Github code scanning ingestion rules rejects results without locations.
			// Patch by removing results without locations.
			log.Debug(fmt.Sprintf("[%s] Removing result [ruleId=%s] without locations: %s", subScanType.String(), sarifutils.GetResultRuleId(result), sarifutils.GetResultMsgText(result)))
			continue
		}
		if cmdResults.ResultType.IsTargetBinary() {
			var markdown string
			if subScanType == SecretsScan {
				markdown = getSecretInBinaryMarkdownMsg(cmdResults, result)
			} else {
				markdown = getScaInBinaryMarkdownMsg(cmdResults, result)
			}
			sarifutils.SetResultMsgMarkdown(markdown, result)
			// For Binary scans, override the physical location if applicable (after data already used for markdown)
			convertBinaryPhysicalLocations(cmdResults, run, result)
			// Calculate the fingerprints if not exists
			if !sarifutils.IsFingerprintsExists(result) {
				if err := calculateResultFingerprints(cmdResults, run, result); err != nil {
					log.Warn(fmt.Sprintf("Failed to calculate the fingerprint for result [ruleId=%s]: %s", sarifutils.GetResultRuleId(result), err.Error()))
				}
			}
		}
		patched = append(patched, result)
	}
	return patched
}

func patchRunsToPassIngestionRules(subScanType SubScanType, cmdResults *Results, runs ...*sarif.Run) []*sarif.Run {
	// Since we run in temp directories files should be relative
	// Patch by converting the file paths to relative paths according to the invocations
	convertPaths(cmdResults.ResultType, subScanType, runs...)
	for _, run := range runs {
		if cmdResults.ResultType.IsTargetBinary() && subScanType == SecretsScan {
			// Patch the tool name in case of binary scan
			sarifutils.SetRunToolName(patchedBinarySecretScannerToolName, run)
		}
		run.Tool.Driver.Rules = patchRules(subScanType, cmdResults, run.Tool.Driver.Rules...)
		run.Results = patchResults(subScanType, cmdResults, run, run.Results...)
	}
	return runs
}

func convertPaths(commandType CommandType, subScanType SubScanType, runs ...*sarif.Run) {
	// Convert base on invocation for source code
	sarifutils.ConvertRunsPathsToRelative(runs...)
	if subScanType != SecretsScan {
		return
	}
	for _, run := range runs {
		for _, result := range run.Results {
			if commandType == DockerImage {
				// For Docker secret scan, patch the logical location if not exists
				patchDockerSecretLocations(result)
			}
		}
	}
}

// Patch the URI to be the file path from sha<number>/<hash>/
// Extract the layer from the location URI, adds it as a logical location kind "layer"
func patchDockerSecretLocations(result *sarif.Result) {
	for _, location := range result.Locations {
		algorithm, layerHash, relativePath := getLayerContentFromPath(sarifutils.GetLocationFileName(location))
		if layerHash != "" {
			// Set Logical location kind "layer" with the layer hash
			logicalLocation := sarifutils.NewLogicalLocation(layerHash, "layer")
			if algorithm != "" {
				logicalLocation.Properties = sarif.Properties(map[string]interface{}{"algorithm": algorithm})
			}
			location.LogicalLocations = append(location.LogicalLocations, logicalLocation)
		}
		if relativePath != "" {
			sarifutils.SetLocationFileName(location, relativePath)
		}
	}
}

func convertBinaryPhysicalLocations(cmdResults *Results, run *sarif.Run, result *sarif.Result) {
	if patchedLocation := getPatchedBinaryLocation(cmdResults, run); patchedLocation != "" {
		for _, location := range result.Locations {
			// Patch the location - Reset the uri and region
			location.PhysicalLocation = sarifutils.NewPhysicalLocation(patchedLocation)
		}
	}
}

func getPatchedBinaryLocation(cmdResults *Results, run *sarif.Run) (patchedLocation string) {
	if cmdResults.ResultType == DockerImage {
		if patchedLocation = getDockerfileLocationIfExists(run); patchedLocation != "" {
			return
		}
	}
	return getWorkflowFileLocationIfExists()
}

func getDockerfileLocationIfExists(run *sarif.Run) string {
	potentialLocations := []string{filepath.Clean("Dockerfile"), sarifutils.GetFullLocationFileName("Dockerfile", run.Invocations)}
	for _, location := range potentialLocations {
		if exists, err := fileutils.IsFileExists(location, false); err == nil && exists {
			log.Debug(fmt.Sprintf("Dockerfile found in %s, replacing the location", location))
			return location
		}
	}
	return ""
}

func getWorkflowFileLocationIfExists() string {
	workflowName := os.Getenv(CurrentWorkflowNameEnvVar)
	// Check if exists in the .github/workflows directory as file name or in the content, return the file path or empty string
	if files, err := fileutils.ListFiles(GithubBaseWorkflowDir, false); err == nil && len(files) > 0 {
		for _, file := range files {
			if strings.Contains(file, workflowName) {
				log.Debug(fmt.Sprintf("Found workflow file %s at %s, replacing the location", workflowName, file))
				return file
			}
		}
		for _, file := range files {
			if content, err := fileutils.ReadFile(file); err == nil && strings.Contains(string(content), workflowName) {
				log.Debug(fmt.Sprintf("Found workflow name %s in %s, replacing the location", workflowName, file))
				return file
			}
		}
	}
	return ""
}

func getSecretInBinaryMarkdownMsg(cmdResults *Results, result *sarif.Result) string {
	if cmdResults.ResultType != Binary && cmdResults.ResultType != DockerImage {
		return ""
	}
	content := "🔒 Found Secrets in Binary"
	if cmdResults.ResultType == DockerImage {
		content += " docker"
	}
	content += " scanning:"
	return content + getBaseBinaryDescriptionMarkdown(SecretsScan, cmdResults, result)
}

func getScaInBinaryMarkdownMsg(cmdResults *Results, result *sarif.Result) string {
	return sarifutils.GetResultMsgText(result) + getBaseBinaryDescriptionMarkdown(ScaScan, cmdResults, result)
}

func getBaseBinaryDescriptionMarkdown(subScanType SubScanType, cmdResults *Results, result *sarif.Result) (content string) {
	// If in github action, add the workflow name and run number
	if os.Getenv(CurrentWorkflowNameEnvVar) != "" {
		content += fmt.Sprintf("\nGithub Actions Workflow: %s", os.Getenv(CurrentWorkflowNameEnvVar))
	}
	if os.Getenv(CurrentWorkflowRunNumberEnvVar) != "" {
		content += fmt.Sprintf("\nRun: %s", os.Getenv(CurrentWorkflowRunNumberEnvVar))
	}
	// If is docker image, add the image tag
	if cmdResults.ResultType == DockerImage {
		if imageTag := getDockerImageTag(cmdResults); imageTag != "" {
			content += fmt.Sprintf("\nImage: %s", imageTag)
		}
	}
	var location *sarif.Location
	if len(result.Locations) > 0 {
		location = result.Locations[0]
	}
	return content + getBinaryLocationMarkdownString(cmdResults.ResultType, subScanType, location)
}

func getDockerImageTag(cmdResults *Results) string {
	if cmdResults.ResultType != DockerImage || len(cmdResults.ScaResults) == 0 {
		return ""
	}
	for _, scaResults := range cmdResults.ScaResults {
		if scaResults.Name != "" {
			return scaResults.Name
		}
	}
	return filepath.Base(cmdResults.ScaResults[0].Target)
}

// If command is docker prepare the markdown string for the location:
// * Layer: <HASH>
// * Filepath: <PATH>
// * Evidence: <Snippet>
func getBinaryLocationMarkdownString(commandType CommandType, subScanType SubScanType, location *sarif.Location) (content string) {
	if location == nil {
		return ""
	}
	if commandType == DockerImage {
		if layer, algorithm := getDockerLayer(commandType, location); layer != "" {
			if algorithm != "" {
				content += fmt.Sprintf("\nLayer (%s): %s", algorithm, layer)
			} else {
				content += fmt.Sprintf("\nLayer: %s", layer)
			}
		}
	}
	if subScanType != SecretsScan {
		return
	}
	if locationFilePath := sarifutils.GetLocationFileName(location); locationFilePath != "" {
		content += fmt.Sprintf("\nFilepath: %s", locationFilePath)
	}
	if snippet := sarifutils.GetLocationSnippet(location); snippet != "" {
		content += fmt.Sprintf("\nEvidence: %s", snippet)
	}
	return
}

func getDockerLayer(commandType CommandType, location *sarif.Location) (layer, algorithm string) {
	// If location has logical location with kind "layer" return it
	if logicalLocation := sarifutils.GetLogicalLocation("layer", location); logicalLocation != nil && logicalLocation.Name != nil {
		layer = *logicalLocation.Name
		if algorithmValue, ok := logicalLocation.Properties["algorithm"].(string); ok {
			algorithm = algorithmValue
		}
		return
	}
	return
}

// Match: <?><filepath.Separator><algorithm><filepath.Separator><hash><filepath.Separator><RelativePath>
// Extract algorithm, hash and relative path
func getLayerContentFromPath(content string) (algorithm string, layerHash string, relativePath string) {
	matches := dockerJasLocationPathPattern.FindStringSubmatch(content)
	if len(matches) == 0 {
		return
	}
	algorithm = matches[dockerJasLocationPathPattern.SubexpIndex("algorithm")]
	layerHash = matches[dockerJasLocationPathPattern.SubexpIndex("hash")]
	relativePath = matches[dockerJasLocationPathPattern.SubexpIndex("relativePath")]
	return
}

// Match: <?>://<algorithm>:<hash>/<?>
// Extract algorithm and hash
func getLayerContentFromComponentId(componentId string) (algorithm string, layerHash string) {
	matches := dockerScaComponentNamePattern.FindStringSubmatch(componentId)
	if len(matches) == 0 {
		return
	}
	algorithm = matches[dockerScaComponentNamePattern.SubexpIndex("algorithm")]
	layerHash = matches[dockerScaComponentNamePattern.SubexpIndex("hash")]
	return
}

// According to the SARIF specification:
// To determine whether a result from a subsequent run is logically the same as a result from the baseline,
// there must be a way to use information contained in the result to construct a stable identifier for the result. We refer to this identifier as a fingerprint.
// A result management system SHOULD construct a fingerprint by using information contained in the SARIF file such as:
// The name of the tool that produced the result, the rule id, the file system path to the analysis target...
func calculateResultFingerprints(cmdResults *Results, run *sarif.Run, result *sarif.Result) error {
	if cmdResults.ResultType != DockerImage {
		// Currently, we support only DockerImage scan
		return nil
	}
	ids := sarifutils.GetResultFileLocations(result)
	ids = append(ids, sarifutils.GetRunToolName(run), sarifutils.GetResultRuleId(result))
	ids = append(ids, sarifutils.GetResultLocationSnippets(result)...)
	// Calculate the hash value and set the fingerprint to the result
	hashValue, err := Md5Hash(ids...)
	if err != nil {
		return err
	}
	sarifutils.SetResultFingerprint(jfrogFingerprintAlgorithmName, hashValue, result)
	return nil
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
	bytesRes, err := JSONMarshalNotEscaped(&results)
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

func WriteSarifResultsAsString(report *sarif.Report, escape bool) (sarifStr string, err error) {
	var out []byte
	if escape {
		out, err = json.Marshal(report)
	} else {
		out, err = JSONMarshalNotEscaped(report)
	}
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	return clientUtils.IndentJson(out), nil
}

func JSONMarshalNotEscaped(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}

func PrintJson(output interface{}) error {
	results, err := JSONMarshalNotEscaped(output)
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
	sarifFile, err := WriteSarifResultsAsString(sarifReport, false)
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

func ToSummary(cmdResult *Results, includeVulnerabilities, includeViolations bool) (summary formats.ResultsSummary) {
	if len(cmdResult.ScaResults) <= 1 {
		summary.Scans = GetScanSummaryByTargets(cmdResult, includeVulnerabilities, includeViolations)
		return
	}
	for _, scaScan := range cmdResult.ScaResults {
		summary.Scans = append(summary.Scans, GetScanSummaryByTargets(cmdResult, includeVulnerabilities, includeViolations, scaScan.Target)...)
	}
	return
}

func GetScanSummaryByTargets(r *Results, includeVulnerabilities, includeViolations bool, targets ...string) (summaries []formats.ScanSummary) {
	if len(targets) == 0 {
		// No filter, one scan summary for all targets
		summaries = append(summaries, getScanSummary(includeVulnerabilities, includeViolations, r.ExtendedScanResults, r.ScaResults...))
		return
	}
	for _, target := range targets {
		// Get target sca results
		targetScaResults := []*ScaScanResult{}
		if targetScaResult := r.getScaScanResultByTarget(target); targetScaResult != nil {
			targetScaResults = append(targetScaResults, targetScaResult)
		}
		// Get target extended results
		targetExtendedResults := r.ExtendedScanResults
		if targetExtendedResults != nil {
			targetExtendedResults = targetExtendedResults.GetResultsForTarget(target)
		}
		summaries = append(summaries, getScanSummary(includeVulnerabilities, includeViolations, targetExtendedResults, targetScaResults...))
	}
	return
}

func getScanSummary(includeVulnerabilities, includeViolations bool, extendedScanResults *ExtendedScanResults, scaResults ...*ScaScanResult) (summary formats.ScanSummary) {
	if len(scaResults) == 1 {
		summary.Target = scaResults[0].Target
	}
	if includeViolations {
		summary.Violations = getScanViolationsSummary(extendedScanResults, scaResults...)
	}
	if includeVulnerabilities {
		summary.Vulnerabilities = getScanSecurityVulnerabilitiesSummary(extendedScanResults, scaResults...)
	}
	return
}

func getScanViolationsSummary(extendedScanResults *ExtendedScanResults, scaResults ...*ScaScanResult) (violations *formats.ScanViolationsSummary) {
	watches := datastructures.MakeSet[string]()
	parsed := datastructures.MakeSet[string]()
	failBuild := false
	scanIds := []string{}
	moreInfoUrls := []string{}
	violationsUniqueFindings := map[ViolationIssueType]formats.ResultSummary{}
	// Parse unique findings
	for _, scaResult := range scaResults {
		for _, xrayResult := range scaResult.XrayResults {
			if xrayResult.ScanId != "" {
				scanIds = append(scanIds, xrayResult.ScanId)
			}
			if xrayResult.XrayDataUrl != "" {
				moreInfoUrls = append(moreInfoUrls, xrayResult.XrayDataUrl)
			}
			for _, violation := range xrayResult.Violations {
				watches.Add(violation.WatchName)
				failBuild = failBuild || violation.FailBuild
				key := violation.IssueId + violation.WatchName
				if parsed.Exists(key) {
					continue
				}
				parsed.Add(key)
				severity := severityutils.GetSeverity(violation.Severity).String()
				violationType := ViolationIssueType(violation.ViolationType)
				if _, ok := violationsUniqueFindings[violationType]; !ok {
					violationsUniqueFindings[violationType] = formats.ResultSummary{}
				}
				if _, ok := violationsUniqueFindings[violationType][severity]; !ok {
					violationsUniqueFindings[violationType][severity] = map[string]int{}
				}
				if violationType == ViolationTypeSecurity {
					applicableRuns := []*sarif.Run{}
					if extendedScanResults != nil {
						applicableRuns = append(applicableRuns, extendedScanResults.ApplicabilityScanResults...)
					}
					violationsUniqueFindings[violationType][severity] = mergeMaps(violationsUniqueFindings[violationType][severity], getSecuritySummaryFindings(violation.Cves, violation.IssueId, violation.Components, applicableRuns...))
				} else {
					// License, Operational Risk
					violationsUniqueFindings[violationType][severity][formats.NoStatus] += 1
				}
			}
		}
	}
	violations = &formats.ScanViolationsSummary{
		Watches:   watches.ToSlice(),
		FailBuild: failBuild,
		ScanResultSummary: formats.ScanResultSummary{ScaResults: &formats.ScaScanResultSummary{
			ScanIds:         scanIds,
			MoreInfoUrls:    moreInfoUrls,
			Security:        violationsUniqueFindings[ViolationTypeSecurity],
			License:         violationsUniqueFindings[ViolationTypeLicense],
			OperationalRisk: violationsUniqueFindings[ViolationTypeOperationalRisk],
		},
		}}
	return
}

func getScanSecurityVulnerabilitiesSummary(extendedScanResults *ExtendedScanResults, scaResults ...*ScaScanResult) (vulnerabilities *formats.ScanResultSummary) {
	vulnerabilities = &formats.ScanResultSummary{}
	parsed := datastructures.MakeSet[string]()
	for _, scaResult := range scaResults {
		for _, xrayResult := range scaResult.XrayResults {
			if vulnerabilities.ScaResults == nil {
				vulnerabilities.ScaResults = &formats.ScaScanResultSummary{Security: formats.ResultSummary{}}
			}
			if xrayResult.ScanId != "" {
				vulnerabilities.ScaResults.ScanIds = append(vulnerabilities.ScaResults.ScanIds, xrayResult.ScanId)
			}
			if xrayResult.XrayDataUrl != "" {
				vulnerabilities.ScaResults.MoreInfoUrls = append(vulnerabilities.ScaResults.MoreInfoUrls, xrayResult.XrayDataUrl)
			}
			for _, vulnerability := range xrayResult.Vulnerabilities {
				if parsed.Exists(vulnerability.IssueId) {
					continue
				}
				parsed.Add(vulnerability.IssueId)
				severity := severityutils.GetSeverity(vulnerability.Severity).String()
				applicableRuns := []*sarif.Run{}
				if extendedScanResults != nil {
					applicableRuns = append(applicableRuns, extendedScanResults.ApplicabilityScanResults...)
				}
				vulnerabilities.ScaResults.Security[severity] = mergeMaps(vulnerabilities.ScaResults.Security[severity], getSecuritySummaryFindings(vulnerability.Cves, vulnerability.IssueId, vulnerability.Components, applicableRuns...))
			}
		}
	}
	if extendedScanResults == nil {
		return
	}
	vulnerabilities.IacResults = getJasSummaryFindings(extendedScanResults.IacScanResults...)
	vulnerabilities.SecretsResults = getJasSummaryFindings(extendedScanResults.SecretsScanResults...)
	vulnerabilities.SastResults = getJasSummaryFindings(extendedScanResults.SastScanResults...)
	return
}

func getSecuritySummaryFindings(cves []services.Cve, issueId string, components map[string]services.Component, applicableRuns ...*sarif.Run) map[string]int {
	uniqueFindings := map[string]int{}
	for _, cve := range cves {
		applicableStatus := jasutils.NotScanned
		if applicableInfo := getCveApplicabilityField(getCveId(cve, issueId), applicableRuns, components); applicableInfo != nil {
			applicableStatus = jasutils.ConvertToApplicabilityStatus(applicableInfo.Status)
		}
		uniqueFindings[applicableStatus.String()] += 1
	}
	if len(cves) == 0 {
		// XRAY-ID, no scanners for them
		uniqueFindings[jasutils.NotCovered.String()] += 1
	}
	return uniqueFindings
}

func getCveId(cve services.Cve, defaultIssueId string) string {
	if cve.Id == "" {
		return defaultIssueId
	}
	return cve.Id
}

func mergeMaps(m1, m2 map[string]int) map[string]int {
	if m1 == nil {
		return m2
	}
	for k, v := range m2 {
		m1[k] += v
	}
	return m1
}

func getJasSummaryFindings(runs ...*sarif.Run) *formats.ResultSummary {
	if len(runs) == 0 {
		return nil
	}
	summary := formats.ResultSummary{}
	for _, run := range runs {
		for _, result := range run.Results {
			resultLevel := sarifutils.GetResultLevel(result)
			severity, err := severityutils.ParseSeverity(resultLevel, true)
			if err != nil {
				log.Warn(fmt.Sprintf("Failed to parse Sarif level %s. %s", resultLevel, err.Error()))
				severity = severityutils.Unknown
			}
			if _, ok := summary[severity.String()]; !ok {
				summary[severity.String()] = map[string]int{}
			}
			summary[severity.String()][formats.NoStatus] += len(result.Locations)
		}
	}
	return &summary
}
