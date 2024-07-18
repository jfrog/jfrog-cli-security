package sarifparser

import (
	"fmt"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	FixedVersionSarifPropertyKey = "fixedVersion"
	WatchSarifPropertyKey		= "watch"

	ScaToolName               = "JFrog Xray SCA"
	SastToolName              = "USAF"
	IacToolName               = "JFrog Terraform scanner"
	SecretsToolName           = "JFrog Secrets scanner"
	ContexualAnalysisToolName = "JFrog Applicability Scanner"
)

type CmdResultsSarifConverter struct {
	// Add contextual analysis results to the Sarif report
	withContextualAnalysis bool
	// Pretty print the output text for Github Issues support
	pretty bool
	// Current stream parse cache information
	current               *sarif.Report
	scaCurrentRun         *sarif.Run
	currentApplicableRuns *datastructures.Set[*sarif.Run]
	// General information on the current command results
	entitledForJas bool
	xrayVersion    string
}

func NewCmdResultsSarifConverter(pretty, withContextualAnalysis bool) *CmdResultsSarifConverter {
	return &CmdResultsSarifConverter{pretty: pretty, withContextualAnalysis: withContextualAnalysis}
}

func (sc *CmdResultsSarifConverter) Get() (*sarif.Report, error) {
	// Return the current report
	if sc.current == nil {
		return sarifutils.NewReport()
	}
	// Flush the current run
	if err := sc.ParseNewScanResultsMetadata("", nil); err != nil {
		return sarifutils.NewReport()
	}
	return sc.current, nil
}

func (sc *CmdResultsSarifConverter) Reset(_, xrayVersion string, entitledForJas bool) (err error) {
	sc.current, err = sarifutils.NewReport()
	if err != nil {
		return
	}
	sc.currentApplicableRuns = datastructures.MakeSet[*sarif.Run]()
	sc.scaCurrentRun = nil

	sc.xrayVersion = xrayVersion
	sc.entitledForJas = entitledForJas
	return
}

func (sc *CmdResultsSarifConverter) ParseNewScanResultsMetadata(target string, _ ...error) (err error) {
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.scaCurrentRun != nil {
		sc.current.Runs = append(sc.current.Runs, sc.scaCurrentRun)
		if sc.withContextualAnalysis {
			sc.current.Runs = append(sc.current.Runs, sc.currentApplicableRuns.ToSlice()...)
		}
	}
	sc.scaCurrentRun = sarif.NewRunWithInformationURI(ScaToolName, utils.BaseDocumentationURL+"sca")
	sc.scaCurrentRun.Tool.Driver.Version = &sc.xrayVersion
	return
}

func (sc *CmdResultsSarifConverter) ParseViolations(target string, tech techutils.Technology, violations []services.Violation, applicabilityRuns ...*sarif.Run) (err error) {
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.scaCurrentRun == nil {
		return results.ConvertorNewScanErr
	}
	sarifResults, sarifRules, err := PrepareSarifScaViolations(target, sc.scaCurrentRun, sc.pretty, sc.entitledForJas, violations, applicabilityRuns...)
	if err != nil || len(sarifRules) == 0 || len(sarifResults) == 0 {
		return
	}
	sc.addScaResultsToCurrentRun(sarifRules, sarifResults...)
	if !sc.entitledForJas {
		return
	}
	for _, run := range applicabilityRuns {
		sc.currentApplicableRuns.Add(run)
	}
	return
}

func (sc *CmdResultsSarifConverter) ParseVulnerabilities(target string, tech techutils.Technology, vulnerabilities []services.Vulnerability, applicabilityRuns ...*sarif.Run) (err error) {
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	if sc.scaCurrentRun == nil {
		return results.ConvertorNewScanErr
	}
	sarifResults, sarifRules, err := PrepareSarifScaVulnerabilities(target, vulnerabilities, sc.pretty, sc.entitledForJas, applicabilityRuns...)
	if err != nil || len(sarifRules) == 0 || len(sarifResults) == 0 {
		return
	}
	sc.addScaResultsToCurrentRun(sarifRules, sarifResults...)
	if !sc.entitledForJas {
		return
	}
	for _, run := range applicabilityRuns {
		sc.currentApplicableRuns.Add(run)
	}
	return
}

func (sc *CmdResultsSarifConverter) ParseLicenses(target string, tech techutils.Technology, licenses []services.License) (err error) {
	// Not supported in Sarif format
	return
}

func (sc *CmdResultsSarifConverter) ParseSecrets(_ string, secrets ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	sc.current.Runs = append(sc.current.Runs, secrets...)
	return
}

func (sc *CmdResultsSarifConverter) ParseIacs(_ string, iacs ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	sc.current.Runs = append(sc.current.Runs, iacs...)
	return
}

func (sc *CmdResultsSarifConverter) ParseSast(_ string, sast ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ConvertorResetErr
	}
	sc.current.Runs = append(sc.current.Runs, sast...)
	return
}

func (sc *CmdResultsSarifConverter) addScaResultsToCurrentRun(rules map[string]*sarif.ReportingDescriptor, results ...*sarif.Result) {
	for _, rule := range rules {
		// This method will add the rule only if it doesn't exist
		sc.scaCurrentRun.Tool.Driver.AddRule(rule)
	}
	for _, result := range results {
		sc.scaCurrentRun.AddResult(result)
	}
}

func PrepareSarifScaViolations(target string, run *sarif.Run, pretty, entitledForJas bool, violations []services.Violation, applicabilityRuns ...*sarif.Run) ([]*sarif.Result, map[string]*sarif.ReportingDescriptor, error) {
	sarifResults := []*sarif.Result{}
	rules := map[string]*sarif.ReportingDescriptor{}
	err := results.PrepareScaViolations(
		target,
		violations,
		pretty,
		entitledForJas,
		applicabilityRuns,
		addSarifScaSecurityViolation(&sarifResults, &rules),
		addSarifScaLicenseViolation(&sarifResults, &rules),
		// Operational risks violations are not supported in Sarif format
		nil,
	)
	return sarifResults, rules, err
}

func PrepareSarifScaVulnerabilities(target string, vulnerabilities []services.Vulnerability, pretty, entitledForJas bool, applicabilityRuns ...*sarif.Run) ([]*sarif.Result, map[string]*sarif.ReportingDescriptor, error) {
	sarifResults := []*sarif.Result{}
	rules := map[string]*sarif.ReportingDescriptor{}
	err := results.PrepareScaVulnerabilities(
		target,
		vulnerabilities,
		pretty,
		entitledForJas,
		applicabilityRuns,
		addSarifScaVulnerability(&sarifResults, &rules),
	)
	return sarifResults, rules, err
}

func addSarifScaVulnerability(sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) results.PrepareScaVulnerabilityFunc {
	return func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersions []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		maxCveScore, err := results.FindMaxCVEScore(severity, applicabilityStatus, cves)
		if err != nil {
			return err
		}
		markdownDescription, err := getScaIssueMarkdownDescription(directComponents, maxCveScore, applicabilityStatus, fixedVersions)
		if err != nil {
			return err
		}
		currentResults, currentRule := parseScaToSarifFormat(vulnerability.IssueId, vulnerability.Summary, markdownDescription, maxCveScore, getScaIssueSarifHeadline, cves, severity, applicabilityStatus, impactedPackagesName, impactedPackagesVersion, fixedVersions, directComponents)
		cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, results.GetIssueIdentifier(cves, vulnerability.IssueId, "_"))
		if _, ok := (*rules)[cveImpactedComponentRuleId]; !ok {
			// New Rule
			(*rules)[cveImpactedComponentRuleId] = currentRule
		}
		*sarifResults = append(*sarifResults, currentResults...)
		return nil
	}
}

func addSarifScaSecurityViolation(sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) results.PrepareScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersions []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		maxCveScore, err := results.FindMaxCVEScore(severity, applicabilityStatus, cves)
		if err != nil {
			return err
		}
		markdownDescription, err := getScaIssueMarkdownDescription(directComponents, maxCveScore, applicabilityStatus, fixedVersions)
		if err != nil {
			return err
		}
		currentResults, currentRule := parseScaToSarifFormat(violation.IssueId, violation.Summary, markdownDescription, maxCveScore, getScaIssueSarifHeadline, cves, severity, applicabilityStatus, impactedPackagesName, impactedPackagesVersion, fixedVersions, directComponents)
		cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, results.GetIssueIdentifier(cves, violation.IssueId, "_"))
		if _, ok := (*rules)[cveImpactedComponentRuleId]; !ok {
			// New Rule
			(*rules)[cveImpactedComponentRuleId] = currentRule
		}
		*sarifResults = append(*sarifResults, currentResults...)
		return nil
	}
}

func addSarifScaLicenseViolation(sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) results.PrepareScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersions []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		maxCveScore, err := results.FindMaxCVEScore(severity, applicabilityStatus, cves)
		if err != nil {
			return err
		}
		markdownDescription, err := getScaLicenseViolationMarkdown(impactedPackagesName, impactedPackagesVersion, violation.LicenseKey, directComponents)
		if err != nil {
			return err
		}
		currentResults, currentRule := parseScaToSarifFormat(
			violation.LicenseKey,
			getLicenseViolationSummary(impactedPackagesName, impactedPackagesVersion, violation.LicenseKey),
			markdownDescription,
			maxCveScore,
			getXrayLicenseSarifHeadline,
			cves,
			severity,
			applicabilityStatus,
			impactedPackagesName,
			impactedPackagesVersion,
			fixedVersions,
			directComponents,
		)
		cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, results.GetIssueIdentifier(cves, violation.LicenseKey, "_"))
		if _, ok := (*rules)[cveImpactedComponentRuleId]; !ok {
			// New Rule
			(*rules)[cveImpactedComponentRuleId] = currentRule
		}
		*sarifResults = append(*sarifResults, currentResults...)
		return nil
	}
}

func parseScaToSarifFormat(xrayId, summary, markdownDescription, cveScore string, generateTitleFunc func(depName string, version string, issueId string) string, cves []formats.CveRow, severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus, impactedPackagesName, impactedPackagesVersion string, fixedVersions []string, directComponents []formats.ComponentRow, watches ...string) (sarifResults []*sarif.Result, rule *sarif.ReportingDescriptor) {
	// General information
	issueId := results.GetIssueIdentifier(cves, xrayId, "_")
	cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, issueId)
	level := severityutils.SeverityToSarifSeverityLevel(severity)
	// Add rule fpr the cve if not exists
	rule = getScaIssueSarifRule(
		cveImpactedComponentRuleId,
		generateTitleFunc(impactedPackagesName, impactedPackagesVersion, issueId),
		cveScore,
		summary,
		markdownDescription,
	)
	for _, directDependency := range directComponents {
		// Create result for each direct dependency
		issueResult := sarif.NewRuleResult(cveImpactedComponentRuleId).
			WithMessage(sarif.NewTextMessage(generateTitleFunc(directDependency.Name, directDependency.Version, issueId))).
			WithLevel(level.String())
		// Add properties
		resultsProperties := sarif.NewPropertyBag()
		if applicabilityStatus != jasutils.NotScanned {
			resultsProperties.Add(jasutils.ApplicabilitySarifPropertyKey, applicabilityStatus.String())
		}
		if len(watches) > 0 {
			resultsProperties.Add(WatchSarifPropertyKey, strings.Join(watches, ", "))
		}
		resultsProperties.Add(FixedVersionSarifPropertyKey, getFixedVersionString(fixedVersions))
		issueResult.AttachPropertyBag(resultsProperties)
		// Add location
		issueLocation := getComponentSarifLocation(directDependency)
		if issueLocation != nil {
			issueResult.AddLocation(issueLocation)
		}
		sarifResults = append(sarifResults, issueResult)
	}
	return
}

func getScaIssueSarifRule(ruleId, ruleDescription, maxCveScore, summary, markdownDescription string) *sarif.ReportingDescriptor {
	cveRuleProperties := sarif.NewPropertyBag()
	cveRuleProperties.Add(severityutils.SarifSeverityRuleProperty, maxCveScore)
	return sarif.NewRule(ruleId).
		WithDescription(ruleDescription).
		WithHelp(sarif.NewMultiformatMessageString(summary).WithMarkdown(markdownDescription)).
		WithProperties(cveRuleProperties.Properties)
}

func getComponentSarifLocation(component formats.ComponentRow) *sarif.Location {
	filePath := ""
	if component.Location != nil {
		filePath = component.Location.File
	}
	if strings.TrimSpace(filePath) == "" {
		// For tech that we don't support fetching the package descriptor related to the component
		filePath = "Package-Descriptor"
	}
	// TODO: Add to location the following
	// https://sarifweb.azurewebsites.net/Validation
	// "logicalLocations": [
	//         {
	//           "fullyQualifiedName": "pkg:maven/org.xerial.snappy/snappy-java@1.1.10.1"
	//         }
	//       ]
	return sarif.NewLocation().
		WithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://" + filePath)))
}

func getScaIssueMarkdownDescription(directDependencies []formats.ComponentRow, cveScore string, applicableStatus jasutils.ApplicabilityStatus, fixedVersions []string) (string, error) {
	formattedDirectDependencies, err := getDirectDependenciesFormatted(directDependencies)
	if err != nil {
		return "", err
	}
	descriptionFixVersions := getFixedVersionString(fixedVersions)
	if applicableStatus == jasutils.NotScanned {
		return fmt.Sprintf("| Severity Score | Direct Dependencies | Fixed Versions     |\n| :---:        |    :----:   |          :---: |\n| %s      | %s       | %s   |",
			cveScore, formattedDirectDependencies, descriptionFixVersions), nil
	}
	return fmt.Sprintf("| Severity Score | Contextual Analysis | Direct Dependencies | Fixed Versions     |\n|  :---:  |  :---:  |  :---:  |  :---:  |\n| %s      | %s       | %s       | %s   |",
		cveScore, applicableStatus.String(), formattedDirectDependencies, descriptionFixVersions), nil
}

func getFixedVersionString(fixedVersions []string) string {
	if len(fixedVersions) == 0 {
		return "No fix available"
	}
	return strings.Join(fixedVersions, ", ")
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

func getScaIssueSarifHeadline(depName, version, issueId string) string {
	return fmt.Sprintf("[%s] %s %s", issueId, depName, version)
}

func getXrayLicenseSarifHeadline(depName, version, key string) string {
	return fmt.Sprintf("License violation [%s] %s %s", key, depName, version)
}

func getLicenseViolationSummary(depName, version, key string) string {
	return fmt.Sprintf("Dependency %s version %s is using a license (%s) that is not allowed.", depName, version, key)
}

func getScaLicenseViolationMarkdown(depName, version, key string, directDependencies []formats.ComponentRow) (string, error) {
	formattedDirectDependencies, err := getDirectDependenciesFormatted(directDependencies)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("**The following direct dependencies are utilizing the `%s %s` dependency with `%s` license violation:**\n%s", depName, version, key, formattedDirectDependencies), nil
}
