package sarifformat

import (
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type CmdResultsSarifConverter struct {
	current *sarif.Report
	entitledForJas bool
}

func NewCmdResultsSarifConverter() *CmdResultsSarifConverter {
	return &CmdResultsSarifConverter{}
}

func (sc *CmdResultsSarifConverter) Get() *sarif.Report {
	if sjc.current == nil {
		return formats.SimpleJsonResults{}
	}
	return *sjc.current
}

func (sc *CmdResultsSarifConverter) Reset(multiScanId, _ string, entitledForJas bool) error {
	sjc.current = &formats.SimpleJsonResults{MultiScanId: multiScanId}
	sjc.entitledForJas = entitledForJas
	return nil
}

func (sc *CmdResultsSarifConverter) ParseNewScanResultsMetadata(target string, errors error) error {
	return nil
}

func (sc *CmdResultsSarifConverter) ParseViolations(target string, tech techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) error {
	return nil
}

func (sc *CmdResultsSarifConverter) ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) error {
	return nil
}

func (sc *CmdResultsSarifConverter) ParseLicenses(target string, tech techutils.Technology, licenses []services.License) error {
	return nil
}

func (sc *CmdResultsSarifConverter) ParseSecrets(target string, secrets ...*sarif.Run) error {
	return nil
}

func (sc *CmdResultsSarifConverter) ParseIacs(target string, iacs ...*sarif.Run) error {
	return nil
}

func (sc *CmdResultsSarifConverter) ParseSast(target string, sast ...*sarif.Run) error {
	return nil
}

func GenerateSarifReportFromResults(commandResults *results.ScanCommandResults, isMultipleRoots, includeLicenses bool, allowedLicenses []string) (report *sarif.Report, err error) {
	report, err = sarifutils.NewReport()
	if err != nil {
		return
	}
	xrayRun, err := convertXrayResponsesToSarifRun(commandResults, isMultipleRoots, includeLicenses, allowedLicenses)
	if err != nil {
		return
	}

	report.Runs = append(report.Runs, xrayRun)
	report.Runs = append(report.Runs, commandResults.GetJasScansResults(jasutils.Applicability)...)
	report.Runs = append(report.Runs, commandResults.GetJasScansResults(jasutils.IaC)...)
	report.Runs = append(report.Runs, commandResults.GetJasScansResults(jasutils.Secrets)...)
	report.Runs = append(report.Runs, commandResults.GetJasScansResults(jasutils.Sast)...)

	return
}

func convertXrayResponsesToSarifRun(results *results.ScanCommandResults, isMultipleRoots, includeLicenses bool, allowedLicenses []string) (run *sarif.Run, err error) {
	// TODO: artifactLocation.uri: could be the path to the package descriptor or the target (binary scan)
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
	// TODO: Add to location the following
	// https://sarifweb.azurewebsites.net/Validation 
	// "logicalLocations": [
    //         {
    //           "fullyQualifiedName": "pkg:maven/org.xerial.snappy/snappy-java@1.1.10.1"
    //         }
    //       ]
	addXrayIssueToSarifRun(
		cveId,
		issue.ImpactedDependencyName,
		issue.ImpactedDependencyVersion,
		issue.Severity,
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
		license.Severity,
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

func addXrayIssueToSarifRun(issueId, impactedDependencyName, impactedDependencyVersion, severity, severityScore, summary, title, markdownDescription string, components []formats.ComponentRow, location *sarif.Location, run *sarif.Run) {
	// Add rule if not exists
	ruleId := getXrayIssueSarifRuleId(impactedDependencyName, impactedDependencyVersion, issueId)
	if rule, _ := run.GetRuleById(ruleId); rule == nil {
		addXrayRule(ruleId, title, severityScore, summary, markdownDescription, run)
	}
	// Add result for each component
	for _, directDependency := range components {
		// directDependency.Location
		msg := getXrayIssueSarifHeadline(directDependency.Name, directDependency.Version, issueId)
		if result := run.CreateResultForRule(ruleId).WithMessage(sarif.NewTextMessage(msg)).WithLevel(sarifutils.ConvertToSarifLevel(severity)); location != nil {
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
		cveRuleProperties.Add("security-severity", maxCveScore)
		rule.WithProperties(cveRuleProperties.Properties)
	}

	rule.WithDescription(ruleDescription)
	rule.WithHelp(&sarif.MultiformatMessageString{
		Text:     &summary,
		Markdown: &markdownDescription,
	})
}