package sarifparser

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	CurrentWorkflowNameEnvVar      = "GITHUB_WORKFLOW"
	CurrentWorkflowRunNumberEnvVar = "GITHUB_RUN_NUMBER"
	CurrentWorkflowWorkspaceEnvVar = "GITHUB_WORKSPACE"

	fixedVersionSarifPropertyKey  = "fixedVersion"
	jfrogFingerprintAlgorithmName = "jfrogFingerprintHash"
	MissingCveScore               = "0"
	maxPossibleCve                = 10.0

	// #nosec G101 -- Not credentials.
	BinarySecretScannerToolName = "JFrog Binary Secrets Scanner"
	ScaScannerToolName          = "JFrog Xray Scanner"
)

var (
	GithubBaseWorkflowDir         = filepath.Join(".github", "workflows")
	dockerJasLocationPathPattern  = regexp.MustCompile(`.*[\\/](?P<algorithm>[^\\/]+)[\\/](?P<hash>[0-9a-fA-F]+)[\\/](?P<relativePath>.*)`)
	dockerScaComponentNamePattern = regexp.MustCompile(`(?P<algorithm>[^__]+)__(?P<hash>[0-9a-fA-F]+)\.tar`)
)

type CmdResultsSarifConverter struct {
	baseJfrogUrl string
	// Include vulnerabilities/violations in the output
	includeVulnerabilities bool
	hasViolationContext    bool
	// If we are running on Github actions, we need to add/change information to the output
	patchBinaryPaths bool
	// Current stream parse cache information
	current                    *sarif.Report
	currentTargetConvertedRuns *currentTargetRuns
	// General information on the current command results
	entitledForJas bool
	xrayVersion    string
	currentCmdType utils.CommandType
}

type currentTargetRuns struct {
	currentTarget results.ScanTarget
	// Current run cache information, we combine vulnerabilities and violations in the same run
	scaCurrentRun       *sarif.Run
	secretsCurrentRun   *sarif.Run
	iacCurrentRun       *sarif.Run
	sastCurrentRun      *sarif.Run
	maliciousCurrentRun *sarif.Run
}

// Parse parameters for the SCA result
type scaParseParams struct {
	CmdType                 utils.CommandType
	IssueId                 string
	Summary                 string
	MarkdownDescription     string
	CveScore                string
	ImpactedPackagesName    string
	ImpactedPackagesVersion string
	Watch                   string
	GenerateTitleFunc       func(depName string, version string, issueId string, watch string) string
	Cves                    []formats.CveRow
	Severity                severityutils.Severity
	ApplicabilityStatus     jasutils.ApplicabilityStatus
	FixedVersions           []string
	DirectComponents        []formats.ComponentRow
	Violation               *violationContext
}

// holds the violation context for the results
type violationContext struct {
	Watch    string
	Policies []string
}

func NewCmdResultsSarifConverter(baseUrl string, includeVulnerabilities, hasViolationContext, patchBinaryPaths bool) *CmdResultsSarifConverter {
	return &CmdResultsSarifConverter{baseJfrogUrl: baseUrl, includeVulnerabilities: includeVulnerabilities, hasViolationContext: hasViolationContext, patchBinaryPaths: patchBinaryPaths}
}

func (sc *CmdResultsSarifConverter) Get() (*sarif.Report, error) {
	if sc.current == nil {
		return sarifutils.NewReport()
	}
	// Flush the current run
	if err := sc.ParseNewTargetResults(results.ScanTarget{}, nil); err != nil {
		return sarifutils.NewReport()
	}
	return sc.current, nil
}

func (sc *CmdResultsSarifConverter) Reset(cmdType utils.CommandType, _, xrayVersion string, entitledForJas, _ bool, _ error) (err error) {
	sc.current, err = sarifutils.NewReport()
	if err != nil {
		return
	}
	// Reset the current stream general information
	sc.currentCmdType = cmdType
	sc.xrayVersion = xrayVersion
	sc.entitledForJas = entitledForJas
	// Reset the current stream cache information
	sc.currentTargetConvertedRuns = nil
	return
}

func (sc *CmdResultsSarifConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	sc.flush()
	// Reset the current stream cache information
	sc.currentTargetConvertedRuns = &currentTargetRuns{currentTarget: target}
	if sc.hasViolationContext || sc.includeVulnerabilities {
		sc.currentTargetConvertedRuns.scaCurrentRun = sc.createScaRun(target, len(errors))
	}
	return
}

func (sc *CmdResultsSarifConverter) flush() {
	if sc.currentTargetConvertedRuns == nil {
		return
	}
	// Flush Sca if needed
	if sc.currentTargetConvertedRuns.scaCurrentRun != nil {
		sc.current.Runs = append(sc.current.Runs, patchRunsToPassIngestionRules(sc.baseJfrogUrl, sc.currentCmdType, utils.ScaScan, sc.patchBinaryPaths, false, sc.currentTargetConvertedRuns.currentTarget, sc.currentTargetConvertedRuns.scaCurrentRun)...)
	}
	// Flush secrets if needed
	if sc.currentTargetConvertedRuns.secretsCurrentRun != nil {
		sc.current.Runs = append(sc.current.Runs, sc.currentTargetConvertedRuns.secretsCurrentRun)
	}
	// Flush iac if needed
	if sc.currentTargetConvertedRuns.iacCurrentRun != nil {
		sc.current.Runs = append(sc.current.Runs, sc.currentTargetConvertedRuns.iacCurrentRun)
	}
	// Flush sast if needed
	if sc.currentTargetConvertedRuns.sastCurrentRun != nil {
		sc.current.Runs = append(sc.current.Runs, sc.currentTargetConvertedRuns.sastCurrentRun)
	}
	// Flush malicious if needed
	if sc.currentTargetConvertedRuns.maliciousCurrentRun != nil {
		sc.current.Runs = append(sc.current.Runs, sc.currentTargetConvertedRuns.maliciousCurrentRun)
	}
	sc.currentTargetConvertedRuns = nil
}

func (sc *CmdResultsSarifConverter) createScaRun(target results.ScanTarget, errorCount int) *sarif.Run {
	run := sarif.NewRunWithInformationURI(ScaScannerToolName, utils.BaseDocumentationURL+"sca")
	run.Tool.Driver.Version = &sc.xrayVersion
	wd := target.Target
	if sc.currentCmdType.IsTargetBinary() {
		// For binary, the target is a file and not a directory
		wd = filepath.Dir(wd)
	}
	run.Invocations = append(run.Invocations, sarif.NewInvocation().
		WithWorkingDirectory(sarif.NewSimpleArtifactLocation(wd)).
		WithExecutionSuccess(errorCount == 0),
	)
	return run
}

// validateBeforeParse checks if the parser is initialized to parse results (checks if Reset and at least one ParseNewTargetResults was called before)
func (sc *CmdResultsSarifConverter) validateBeforeParse() (err error) {
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	if sc.currentTargetConvertedRuns == nil {
		return results.ErrNoTargetConvertor
	}
	return
}

func (sc *CmdResultsSarifConverter) ParseScaIssues(target results.ScanTarget, violations bool, scaResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if violations {
		if err = sc.parseScaViolations(target, scaResponse, applicableScan...); err != nil {
			return
		}
		return
	}
	if err = sc.parseScaVulnerabilities(target, scaResponse, applicableScan...); err != nil {
		return
	}
	return
}

func (sc *CmdResultsSarifConverter) parseScaViolations(target results.ScanTarget, scanResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.currentTargetConvertedRuns.scaCurrentRun == nil {
		return
	}
	// Parse violations
	sarifResults, sarifRules, err := PrepareSarifScaViolations(sc.currentCmdType, target, scanResponse.Scan.Violations, sc.entitledForJas, results.ScanResultsToRuns(applicableScan)...)
	if err != nil || len(sarifRules) == 0 || len(sarifResults) == 0 {
		return
	}
	sc.addScaResultsToCurrentRun(sarifRules, sarifResults...)
	return
}

func (sc *CmdResultsSarifConverter) parseScaVulnerabilities(target results.ScanTarget, scanResponse results.ScanResult[services.ScanResponse], applicableScan ...results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.currentTargetConvertedRuns.scaCurrentRun == nil {
		return
	}
	sarifResults, sarifRules, err := PrepareSarifScaVulnerabilities(sc.currentCmdType, target, scanResponse.Scan.Vulnerabilities, sc.entitledForJas, results.ScanResultsToRuns(applicableScan)...)
	if err != nil || len(sarifRules) == 0 || len(sarifResults) == 0 {
		return
	}
	sc.addScaResultsToCurrentRun(sarifRules, sarifResults...)
	return
}

func (sc *CmdResultsSarifConverter) ParseLicenses(_ results.ScanTarget, _ results.ScanResult[services.ScanResponse]) (err error) {
	// Not supported in Sarif format
	return
}

func (sc *CmdResultsSarifConverter) ParseSecrets(target results.ScanTarget, violations bool, secrets []results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || !sc.entitledForJas {
		return
	}
	sc.currentTargetConvertedRuns.secretsCurrentRun = combineJasRunsToCurrentRun(sc.currentTargetConvertedRuns.secretsCurrentRun, patchRunsToPassIngestionRules(sc.baseJfrogUrl, sc.currentCmdType, utils.SecretsScan, sc.patchBinaryPaths, violations, target, results.ScanResultsToRuns(secrets)...)...)
	return
}

func (sc *CmdResultsSarifConverter) ParseMalicious(target results.ScanTarget, violations bool, maliciousFindings []results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || !sc.entitledForJas {
		return
	}
	sc.currentTargetConvertedRuns.maliciousCurrentRun = combineJasRunsToCurrentRun(sc.currentTargetConvertedRuns.maliciousCurrentRun, patchRunsToPassIngestionRules(sc.baseJfrogUrl, sc.currentCmdType, utils.MaliciousCodeScan, sc.patchBinaryPaths, violations, target, results.ScanResultsToRuns(maliciousFindings)...)...)
	return
}

func (sc *CmdResultsSarifConverter) ParseIacs(target results.ScanTarget, violations bool, iacs []results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || !sc.entitledForJas {
		return
	}
	sc.currentTargetConvertedRuns.iacCurrentRun = combineJasRunsToCurrentRun(sc.currentTargetConvertedRuns.iacCurrentRun, patchRunsToPassIngestionRules(sc.baseJfrogUrl, sc.currentCmdType, utils.IacScan, sc.patchBinaryPaths, violations, target, results.ScanResultsToRuns(iacs)...)...)
	return
}

func (sc *CmdResultsSarifConverter) ParseSast(target results.ScanTarget, violations bool, sast []results.ScanResult[[]*sarif.Run]) (err error) {
	if err = sc.validateBeforeParse(); err != nil || !sc.entitledForJas {
		return
	}
	sc.currentTargetConvertedRuns.sastCurrentRun = combineJasRunsToCurrentRun(sc.currentTargetConvertedRuns.sastCurrentRun, patchRunsToPassIngestionRules(sc.baseJfrogUrl, sc.currentCmdType, utils.SastScan, sc.patchBinaryPaths, violations, target, results.ScanResultsToRuns(sast)...)...)
	return
}

func (sc *CmdResultsSarifConverter) addScaResultsToCurrentRun(rules map[string]*sarif.ReportingDescriptor, results ...*sarif.Result) {
	for _, rule := range rules {
		// This method will add the rule only if it doesn't exist
		sc.currentTargetConvertedRuns.scaCurrentRun.Tool.Driver.AddRule(rule)
	}
	for _, result := range results {
		sc.currentTargetConvertedRuns.scaCurrentRun.AddResult(result)
	}
}

// For JAS scanners results we get a separate runs for vulnerabilities and violations, we need to combine them to a single run
// This allows us to have a single run for each scan type in the SARIF report for the ingestion rules and the users to view
func combineJasRunsToCurrentRun(destination *sarif.Run, runs ...*sarif.Run) *sarif.Run {
	for _, run := range runs {
		if destination == nil {
			// First run, set as the destination
			destination = run
			continue
		} else if destination.Tool.Driver.Name != run.Tool.Driver.Name {
			log.Warn(fmt.Sprintf("Skipping JAS run (%s) as it doesn't match the current run (%s)", run.Tool.Driver.Name, destination.Tool.Driver.Name))
			continue
		}
		// Combine the rules and results of the run to the destination
		for _, rule := range run.Tool.Driver.Rules {
			// This method will add the rule only if it doesn't exist
			destination.Tool.Driver.AddRule(rule)
		}
		for _, result := range run.Results {
			destination.AddResult(result)
		}
	}
	return destination
}

func PrepareSarifScaViolations(cmdType utils.CommandType, target results.ScanTarget, violations []services.Violation, entitledForJas bool, applicabilityRuns ...*sarif.Run) ([]*sarif.Result, map[string]*sarif.ReportingDescriptor, error) {
	sarifResults := []*sarif.Result{}
	rules := map[string]*sarif.ReportingDescriptor{}
	_, _, err := results.ApplyHandlerToScaViolations(
		target,
		violations,
		entitledForJas,
		applicabilityRuns,
		addSarifScaSecurityViolation(cmdType, &sarifResults, &rules),
		addSarifScaLicenseViolation(cmdType, &sarifResults, &rules),
		// Operational risks violations are not supported in Sarif format
		nil,
	)
	return sarifResults, rules, err
}

func PrepareSarifScaVulnerabilities(cmdType utils.CommandType, target results.ScanTarget, vulnerabilities []services.Vulnerability, entitledForJas bool, applicabilityRuns ...*sarif.Run) ([]*sarif.Result, map[string]*sarif.ReportingDescriptor, error) {
	sarifResults := []*sarif.Result{}
	rules := map[string]*sarif.ReportingDescriptor{}
	err := results.ApplyHandlerToScaVulnerabilities(
		target,
		vulnerabilities,
		entitledForJas,
		applicabilityRuns,
		addSarifScaVulnerability(cmdType, &sarifResults, &rules),
	)
	return sarifResults, rules, err
}

func addSarifScaVulnerability(cmdType utils.CommandType, sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) results.ParseScaVulnerabilityFunc {
	return func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersions []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		maxCveScore, err := results.FindMaxCVEScore(severity, applicabilityStatus, cves)
		if err != nil {
			return err
		}
		markdownDescription, err := getScaIssueMarkdownDescription(directComponents, maxCveScore, applicabilityStatus, fixedVersions)
		if err != nil {
			return err
		}
		currentResults, currentRule := parseScaToSarifFormat(scaParseParams{
			CmdType:                 cmdType,
			IssueId:                 vulnerability.IssueId,
			Summary:                 vulnerability.Summary,
			MarkdownDescription:     markdownDescription,
			CveScore:                maxCveScore,
			GenerateTitleFunc:       getScaVulnerabilitySarifHeadline,
			Cves:                    cves,
			Severity:                severity,
			ApplicabilityStatus:     applicabilityStatus,
			ImpactedPackagesName:    impactedPackagesName,
			ImpactedPackagesVersion: impactedPackagesVersion,
			FixedVersions:           fixedVersions,
			DirectComponents:        directComponents,
		})
		cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, results.GetIssueIdentifier(cves, vulnerability.IssueId, "_"))
		if _, ok := (*rules)[cveImpactedComponentRuleId]; !ok {
			// New Rule
			(*rules)[cveImpactedComponentRuleId] = currentRule
		}
		*sarifResults = append(*sarifResults, currentResults...)
		return nil
	}
}

func addSarifScaSecurityViolation(cmdType utils.CommandType, sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) results.ParseScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersions []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		maxCveScore, err := results.FindMaxCVEScore(severity, applicabilityStatus, cves)
		if err != nil {
			return err
		}
		markdownDescription, err := getScaIssueMarkdownDescription(directComponents, maxCveScore, applicabilityStatus, fixedVersions)
		if err != nil {
			return err
		}
		currentResults, currentRule := parseScaToSarifFormat(scaParseParams{
			CmdType:                 cmdType,
			IssueId:                 violation.IssueId,
			Watch:                   violation.WatchName,
			Summary:                 violation.Summary,
			MarkdownDescription:     markdownDescription,
			CveScore:                maxCveScore,
			GenerateTitleFunc:       getScaSecurityViolationSarifHeadline,
			Cves:                    cves,
			Severity:                severity,
			ApplicabilityStatus:     applicabilityStatus,
			ImpactedPackagesName:    impactedPackagesName,
			ImpactedPackagesVersion: impactedPackagesVersion,
			FixedVersions:           fixedVersions,
			DirectComponents:        directComponents,
			Violation: &violationContext{
				Watch:    violation.WatchName,
				Policies: results.ConvertPolicesToString(violation.Policies),
			},
		})
		cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, results.GetIssueIdentifier(cves, violation.IssueId, "_"))
		if _, ok := (*rules)[cveImpactedComponentRuleId]; !ok {
			// New Rule
			(*rules)[cveImpactedComponentRuleId] = currentRule
		}
		*sarifResults = append(*sarifResults, currentResults...)
		return nil
	}
}

func addSarifScaLicenseViolation(cmdType utils.CommandType, sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) results.ParseScaViolationFunc {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersions []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		maxCveScore, err := results.FindMaxCVEScore(severity, applicabilityStatus, cves)
		if err != nil {
			return err
		}
		markdownDescription, err := getScaLicenseViolationMarkdown(impactedPackagesName, impactedPackagesVersion, violation.LicenseKey, directComponents)
		if err != nil {
			return err
		}
		currentResults, currentRule := parseScaToSarifFormat(scaParseParams{
			CmdType:                 cmdType,
			Watch:                   violation.WatchName,
			IssueId:                 violation.LicenseKey,
			Summary:                 getLicenseViolationSummary(impactedPackagesName, impactedPackagesVersion, violation.LicenseKey),
			MarkdownDescription:     markdownDescription,
			CveScore:                maxCveScore,
			GenerateTitleFunc:       getXrayLicenseSarifHeadline,
			Cves:                    cves,
			Severity:                severity,
			ApplicabilityStatus:     applicabilityStatus,
			ImpactedPackagesName:    impactedPackagesName,
			ImpactedPackagesVersion: impactedPackagesVersion,
			FixedVersions:           fixedVersions,
			DirectComponents:        directComponents,
			Violation: &violationContext{
				Watch:    violation.WatchName,
				Policies: results.ConvertPolicesToString(violation.Policies),
			},
		})
		cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, results.GetIssueIdentifier(cves, violation.LicenseKey, "_"))
		if _, ok := (*rules)[cveImpactedComponentRuleId]; !ok {
			// New Rule
			(*rules)[cveImpactedComponentRuleId] = currentRule
		}
		*sarifResults = append(*sarifResults, currentResults...)
		return nil
	}
}

func parseScaToSarifFormat(params scaParseParams) (sarifResults []*sarif.Result, rule *sarif.ReportingDescriptor) {
	// General information
	issueId := results.GetIssueIdentifier(params.Cves, params.IssueId, "_")
	cveImpactedComponentRuleId := results.GetScaIssueId(params.ImpactedPackagesName, params.ImpactedPackagesVersion, issueId)
	level := severityutils.SeverityToSarifSeverityLevel(params.Severity)
	// Add rule for the cve if not exists
	rule = getScaIssueSarifRule(
		cveImpactedComponentRuleId,
		params.GenerateTitleFunc(params.ImpactedPackagesName, params.ImpactedPackagesVersion, issueId, params.Watch),
		params.CveScore,
		params.Summary,
		params.MarkdownDescription,
	)
	for _, directDependency := range params.DirectComponents {
		// Create result for each direct dependency
		issueResult := sarif.NewRuleResult(cveImpactedComponentRuleId).
			WithMessage(sarif.NewTextMessage(params.GenerateTitleFunc(directDependency.Name, directDependency.Version, issueId, params.Watch))).
			WithLevel(level.String())
		// Add properties
		resultsProperties := sarif.NewPropertyBag()
		if params.ApplicabilityStatus != jasutils.NotScanned {
			resultsProperties.Add(jasutils.ApplicabilitySarifPropertyKey, params.ApplicabilityStatus.String())
		}
		if params.Violation != nil {
			// Add violation context
			if params.Violation.Watch != "" {
				resultsProperties.Add(sarifutils.WatchSarifPropertyKey, params.Violation.Watch)
			}
			if len(params.Violation.Policies) > 0 {
				resultsProperties.Add(sarifutils.PoliciesSarifPropertyKey, strings.Join(params.Violation.Policies, ","))
			}
		}
		resultsProperties.Add(fixedVersionSarifPropertyKey, getFixedVersionString(params.FixedVersions))
		issueResult.AttachPropertyBag(resultsProperties)
		// Add location
		issueLocation := getComponentSarifLocation(params.CmdType, directDependency)
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

func getComponentSarifLocation(cmtType utils.CommandType, component formats.ComponentRow) *sarif.Location {
	filePath := ""
	if component.Location != nil {
		filePath = component.Location.File
	}
	if strings.TrimSpace(filePath) == "" {
		// For tech that we don't support fetching the package descriptor related to the component
		filePath = "Package-Descriptor"
	}
	var logicalLocations []*sarif.LogicalLocation
	if cmtType == utils.DockerImage {
		// Docker image - extract layer hash from component name
		algorithm, layer := getLayerContentFromComponentId(component.Name)
		if layer != "" {
			logicalLocation := sarifutils.NewLogicalLocation(layer, "layer")
			if algorithm != "" {
				logicalLocation.Properties = map[string]interface{}{"algorithm": algorithm}
			}
			logicalLocations = append(logicalLocations, logicalLocation)
		}
	}
	return sarif.NewLocation().
		WithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithUri("file://" + filePath))).WithLogicalLocations(logicalLocations)
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

func getScaVulnerabilitySarifHeadline(depName, version, issueId, watch string) string {
	headline := fmt.Sprintf("[%s] %s %s", issueId, depName, version)
	if watch != "" {
		headline = fmt.Sprintf("%s (%s)", headline, watch)
	}
	return headline
}

func getScaSecurityViolationSarifHeadline(depName, version, key, watch string) string {
	headline := getScaVulnerabilitySarifHeadline(depName, version, key, watch)
	if watch == "" {
		return fmt.Sprintf("Security Violation %s", headline)
	}
	return headline
}

func getXrayLicenseSarifHeadline(depName, version, key, watch string) string {
	headline := fmt.Sprintf("[%s] in %s %s", key, depName, version)
	if watch != "" {
		headline = fmt.Sprintf("%s (%s)", headline, watch)
	} else {
		headline = fmt.Sprintf("License violation %s", headline)
	}
	return headline
}

func getLicenseViolationSummary(depName, version, key string) string {
	return fmt.Sprintf("Dependency %s version %s is using a license (%s) that is not allowed.", depName, version, key)
}

func getScaLicenseViolationMarkdown(depName, version, key string, directDependencies []formats.ComponentRow) (string, error) {
	formattedDirectDependencies, err := getDirectDependenciesFormatted(directDependencies)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s<br/>Direct dependencies:<br/>%s", getLicenseViolationSummary(depName, version, key), formattedDirectDependencies), nil
}

func patchRunsToPassIngestionRules(baseJfrogUrl string, cmdType utils.CommandType, subScanType utils.SubScanType, patchBinaryPaths, isJasViolations bool, target results.ScanTarget, runs ...*sarif.Run) []*sarif.Run {
	patchedRuns := []*sarif.Run{}
	// Patch changes may alter the original run, so we will create a new run for each
	for _, run := range runs {
		patched := sarifutils.CopyRun(run)
		// Since we run in temp directories files should be relative
		// Patch by converting the file paths to relative paths according to the invocations
		convertPaths(cmdType, subScanType, patched)
		if cmdType.IsTargetBinary() && subScanType == utils.SecretsScan {
			// Patch the tool name in case of binary scan
			sarifutils.SetRunToolName(BinarySecretScannerToolName, patched)
		}
		if patched.Tool.Driver != nil {
			patched.Tool.Driver.Rules = patchRules(baseJfrogUrl, cmdType, subScanType, isJasViolations, patched.Tool.Driver.Rules...)
		}
		patched.Results = patchResults(cmdType, subScanType, patchBinaryPaths, isJasViolations, target, patched, patched.Results...)
		patchedRuns = append(patchedRuns, patched)
	}
	return patchedRuns
}

func convertPaths(commandType utils.CommandType, subScanType utils.SubScanType, runs ...*sarif.Run) {
	// Convert base on invocation for source code
	sarifutils.ConvertRunsPathsToRelative(runs...)
	if !(commandType == utils.DockerImage && subScanType == utils.SecretsScan) {
		return
	}
	for _, run := range runs {
		for _, result := range run.Results {
			// For Docker secret scan, patch the logical location if not exists
			patchDockerSecretLocations(result)
		}
	}
}

// Patch the URI to be the file path from sha<number>/<hash>/
// Extract the layer from the location URI, adds it as a logical location kind "layer"
func patchDockerSecretLocations(result *sarif.Result) {
	for _, location := range result.Locations {
		algorithm, layerHash, relativePath := getLayerContentFromPath(sarifutils.GetLocationFileName(location))
		if algorithm == "" || layerHash == "" || relativePath == "" {
			continue
		}
		// Set Logical location kind "layer" with the layer hash
		logicalLocation := sarifutils.NewLogicalLocation(layerHash, "layer")
		logicalLocation.Properties = sarif.Properties(map[string]interface{}{"algorithm": algorithm})
		location.LogicalLocations = append(location.LogicalLocations, logicalLocation)
		sarifutils.SetLocationFileName(location, relativePath)
	}
}

func patchRules(platformBaseUrl string, commandType utils.CommandType, subScanType utils.SubScanType, isViolations bool, rules ...*sarif.ReportingDescriptor) (patched []*sarif.ReportingDescriptor) {
	patched = []*sarif.ReportingDescriptor{}
	for _, rule := range rules {
		if rule.Name != nil && rule.ID == *rule.Name {
			// SARIF1001 - if both 'id' and 'name' are present, they must be different. If they are identical, the tool must omit the 'name' property.
			rule.Name = nil
		}
		if commandType.IsTargetBinary() && subScanType == utils.SecretsScan {
			// Patch the rule name in case of binary scan
			sarifutils.SetRuleShortDescriptionText(fmt.Sprintf("[Secret in Binary found] %s", sarifutils.GetRuleShortDescriptionText(rule)), rule)
		}
		if isViolations && subScanType != utils.ScaScan {
			// Add prefix to the rule description for violations
			sarifutils.SetRuleShortDescriptionText(fmt.Sprintf("[Security Violation] %s", sarifutils.GetRuleShortDescriptionText(rule)), rule)
		}
		if rule.Help == nil {
			// Github code scanning ingestion rules rejects rules without help content.
			// Patch by transferring the full description to the help field.
			rule.Help = rule.FullDescription
		}
		// Add analytics hidden pixel to the help content if needed (Github code scanning)
		if analytics := getAnalyticsHiddenPixel(platformBaseUrl, subScanType); rule.Help != nil && analytics != "" {
			rule.Help.Markdown = utils.NewStringPtr(fmt.Sprintf("%s\n%s", analytics, sarifutils.GetRuleHelpMarkdown(rule)))
		}
		patched = append(patched, rule)
	}
	return
}

func patchResults(commandType utils.CommandType, subScanType utils.SubScanType, patchBinaryPaths, isJasViolations bool, target results.ScanTarget, run *sarif.Run, results ...*sarif.Result) (patched []*sarif.Result) {
	patched = []*sarif.Result{}
	for _, result := range results {
		if len(result.Locations) == 0 {
			// Github code scanning ingestion rules rejects results without locations.
			// Patch by removing results without locations.
			log.Debug(fmt.Sprintf("[%s] Removing result [ruleId=%s] without locations: %s", subScanType.String(), sarifutils.GetResultRuleId(result), sarifutils.GetResultMsgText(result)))
			continue
		}
		patchResultMsg(result, target, commandType, subScanType, isJasViolations)
		if commandType.IsTargetBinary() {
			if patchBinaryPaths {
				// For Binary scans, override the physical location if applicable (after data already used for markdown)
				result = convertBinaryPhysicalLocations(commandType, run, result)
			}
			// Calculate the fingerprints if not exists
			if !sarifutils.IsFingerprintsExists(result) {
				if err := calculateResultFingerprints(commandType, run, result); err != nil {
					log.Warn(fmt.Sprintf("Failed to calculate the fingerprint for result [ruleId=%s]: %s", sarifutils.GetResultRuleId(result), err.Error()))
				}
			}
		}
		patched = append(patched, result)
	}
	return patched
}

func patchResultMsg(result *sarif.Result, target results.ScanTarget, commandType utils.CommandType, subScanType utils.SubScanType, isJasViolations bool) {
	if commandType.IsTargetBinary() {
		var markdown string
		if subScanType == utils.SecretsScan {
			markdown = getSecretInBinaryMarkdownMsg(commandType, target, result)
		} else {
			markdown = getScaInBinaryMarkdownMsg(commandType, target, result)
		}
		sarifutils.SetResultMsgMarkdown(markdown, result)
	}
	// Patch markdown
	markdown := sarifutils.GetResultMsgMarkdown(result)
	if markdown == "" {
		markdown = sarifutils.GetResultMsgText(result)
	}
	if isJasViolations {
		// Add prefix to the rule description for violations
		markdown = fmt.Sprintf("Security Violation %s", markdown)
	}
	sarifutils.SetResultMsgMarkdown(markdown, result)
}

// This method may need to replace the physical location if applicable, to avoid override on the existing object we will return a new object if changed
func convertBinaryPhysicalLocations(commandType utils.CommandType, run *sarif.Run, result *sarif.Result) *sarif.Result {
	if patchedLocation := getPatchedBinaryLocation(commandType, run); patchedLocation != "" {
		patched := sarifutils.CopyResult(result)
		for _, location := range patched.Locations {
			// Patch the location - Reset the uri and region
			location.PhysicalLocation = sarifutils.NewPhysicalLocation(patchedLocation)
		}
		return patched
	} else {
		return result
	}
}

func getPatchedBinaryLocation(commandType utils.CommandType, run *sarif.Run) (patchedLocation string) {
	if commandType == utils.DockerImage {
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
			return location
		}
	}
	if workspace := os.Getenv(CurrentWorkflowWorkspaceEnvVar); workspace != "" {
		if exists, err := fileutils.IsFileExists(filepath.Join(workspace, "Dockerfile"), false); err == nil && exists {
			return filepath.Join(workspace, "Dockerfile")
		}
	}
	return ""
}

func getGithubWorkflowsDirIfExists() string {
	if exists, err := fileutils.IsDirExists(GithubBaseWorkflowDir, false); err == nil && exists {
		return GithubBaseWorkflowDir
	}
	if workspace := os.Getenv(CurrentWorkflowWorkspaceEnvVar); workspace != "" {
		if exists, err := fileutils.IsDirExists(filepath.Join(workspace, GithubBaseWorkflowDir), false); err == nil && exists {
			return filepath.Join(workspace, GithubBaseWorkflowDir)
		}
	}
	return ""
}

func getWorkflowFileLocationIfExists() (location string) {
	workflowName := os.Getenv(CurrentWorkflowNameEnvVar)
	if workflowName == "" {
		return
	}
	workflowsDir := getGithubWorkflowsDirIfExists()
	if workflowsDir == "" {
		return
	}
	currentWd, err := os.Getwd()
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to get the current working directory to get workflow file location: %s", err.Error()))
		return
	}
	// Check if exists in the .github/workflows directory as file name or in the content, return the file path or empty string
	if files, err := fileutils.ListFiles(workflowsDir, false); err == nil && len(files) > 0 {
		for _, file := range files {
			if strings.Contains(file, workflowName) {
				return strings.TrimPrefix(file, currentWd)
			}
		}
		for _, file := range files {
			if content, err := fileutils.ReadFile(file); err == nil && strings.Contains(string(content), workflowName) {
				return strings.TrimPrefix(file, currentWd)
			}
		}
	}
	return
}

func getSecretInBinaryMarkdownMsg(commandType utils.CommandType, target results.ScanTarget, result *sarif.Result) string {
	if !commandType.IsTargetBinary() {
		return ""
	}
	content := "🔒 Found Secrets in Binary"
	if commandType == utils.DockerImage {
		content += " docker"
	}
	content += " scanning:"
	return content + getBaseBinaryDescriptionMarkdown(commandType, target, utils.SecretsScan, result)
}

func getScaInBinaryMarkdownMsg(commandType utils.CommandType, target results.ScanTarget, result *sarif.Result) string {
	return sarifutils.GetResultMsgText(result) + getBaseBinaryDescriptionMarkdown(commandType, target, utils.ScaScan, result)
}

func getBaseBinaryDescriptionMarkdown(commandType utils.CommandType, target results.ScanTarget, subScanType utils.SubScanType, result *sarif.Result) (content string) {
	// If in github action, add the workflow name and run number
	if workflowLocation := getWorkflowFileLocationIfExists(); workflowLocation != "" {
		content += fmt.Sprintf("\nGithub Actions Workflow: %s", workflowLocation)
	}
	if os.Getenv(CurrentWorkflowRunNumberEnvVar) != "" {
		content += fmt.Sprintf("\nRun: %s", os.Getenv(CurrentWorkflowRunNumberEnvVar))
	}
	// If is docker image, add the image tag
	if commandType == utils.DockerImage {
		if imageTag := getDockerImageTag(commandType, target); imageTag != "" {
			content += fmt.Sprintf("\nImage: %s", imageTag)
		}
	}
	var location *sarif.Location
	if len(result.Locations) > 0 {
		location = result.Locations[0]
	}
	return content + getBinaryLocationMarkdownString(commandType, subScanType, result, location)
}

func getDockerImageTag(commandType utils.CommandType, target results.ScanTarget) string {
	if commandType != utils.DockerImage {
		return ""
	}
	if target.Name != "" {
		return target.Name
	}
	return filepath.Base(target.Target)
}

// If command is docker prepare the markdown string for the location:
// * Layer: <HASH>
// * Filepath: <PATH>
// * Evidence: <Snippet>
func getBinaryLocationMarkdownString(commandType utils.CommandType, subScanType utils.SubScanType, result *sarif.Result, location *sarif.Location) (content string) {
	if location == nil {
		return ""
	}
	if commandType == utils.DockerImage {
		if layer, algorithm := getDockerLayer(location); layer != "" {
			if algorithm != "" {
				content += fmt.Sprintf("\nLayer (%s): %s", algorithm, layer)
			} else {
				content += fmt.Sprintf("\nLayer: %s", layer)
			}
		}
	}
	if subScanType != utils.SecretsScan {
		return
	}
	if locationFilePath := sarifutils.GetLocationFileName(location); locationFilePath != "" {
		content += fmt.Sprintf("\nFilepath: %s", locationFilePath)
	}
	if snippet := sarifutils.GetLocationSnippetText(location); snippet != "" {
		content += fmt.Sprintf("\nEvidence: %s", snippet)
	}
	if tokenValidation := results.GetResultPropertyTokenValidation(result); tokenValidation != "" {
		content += fmt.Sprintf("\nToken Validation %s", tokenValidation)
	}
	return
}

func getDockerLayer(location *sarif.Location) (layer, algorithm string) {
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

// Match: <algorithm>__<hash>.tar
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
func calculateResultFingerprints(resultType utils.CommandType, run *sarif.Run, result *sarif.Result) error {
	if !resultType.IsTargetBinary() {
		return nil
	}
	ids := []string{sarifutils.GetRunToolName(run), sarifutils.GetResultRuleId(result), sarifutils.GetResultWatches(result)}
	for _, location := range sarifutils.GetResultFileLocations(result) {
		ids = append(ids, strings.ReplaceAll(location, string(filepath.Separator), "/"))
	}
	ids = append(ids, sarifutils.GetResultLocationSnippets(result)...)
	// Calculate the hash value and set the fingerprint to the result
	hashValue, err := utils.Md5Hash(ids...)
	if err != nil {
		return err
	}
	sarifutils.SetResultFingerprint(jfrogFingerprintAlgorithmName, hashValue, result)
	return nil
}

// This method returns an image tag of invisible image that is used to track some parameters.
// It will send a count as soon as the page with it is logged.
func getAnalyticsHiddenPixel(baseUrl string, resultOfSubScan utils.SubScanType) string {
	jobId := os.Getenv(utils.JfrogExternalJobIdEnv)
	runId := os.Getenv(utils.JfrogExternalRunIdEnv)
	gitRepo := os.Getenv(utils.JfrogExternalGitRepoEnv)
	if jobId == "" || runId == "" || gitRepo == "" {
		return ""
	}
	return fmt.Sprintf(
		"![](%sui/api/v1/u?s=1&m=2&job_id=%s&run_id=%s&git_repo=%s&type=%s)",
		baseUrl,
		url.QueryEscape(jobId),
		runId,
		gitRepo,
		resultOfSubScan.String(),
	)
}
