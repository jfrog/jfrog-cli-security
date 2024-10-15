package sarifparser

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/jfrog/gofrog/datastructures"
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

	FixedVersionSarifPropertyKey  = "fixedVersion"
	WatchSarifPropertyKey         = "watch"
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
	// Include vulnerabilities/violations in the output
	includeVulnerabilities bool
	hasViolationContext    bool
	// If we are running on Github actions, we need to add/change information to the output
	patchBinaryPaths bool
	// Current stream parse cache information
	current       *sarif.Report
	scaCurrentRun *sarif.Run
	currentTarget results.ScanTarget
	parsedScaKeys *datastructures.Set[string]
	// General information on the current command results
	entitledForJas bool
	xrayVersion    string
	currentCmdType utils.CommandType
}

func NewCmdResultsSarifConverter(includeVulnerabilities, hasViolationContext, patchBinaryPaths bool) *CmdResultsSarifConverter {
	return &CmdResultsSarifConverter{includeVulnerabilities: includeVulnerabilities, hasViolationContext: hasViolationContext, patchBinaryPaths: patchBinaryPaths}
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
	sc.scaCurrentRun = nil
	return
}

func (sc *CmdResultsSarifConverter) ParseNewTargetResults(target results.ScanTarget, errors ...error) (err error) {
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	if sc.scaCurrentRun != nil {
		// Flush the current run
		sc.current.Runs = append(sc.current.Runs, patchRunsToPassIngestionRules(sc.currentCmdType, utils.ScaScan, sc.patchBinaryPaths, sc.currentTarget, sc.scaCurrentRun)...)
	}
	sc.currentTarget = target
	if sc.hasViolationContext || sc.includeVulnerabilities {
		// Create Sca Run if requested to parse all vulnerabilities/violations to it
		sc.scaCurrentRun = sc.createScaRun(sc.currentTarget, len(errors))
		sc.parsedScaKeys = datastructures.MakeSet[string]()
	}
	return
}

func (sc *CmdResultsSarifConverter) createScaRun(target results.ScanTarget, errorCount int) *sarif.Run {
	run := sarif.NewRunWithInformationURI(ScaScannerToolName, utils.BaseDocumentationURL+"sca")
	run.Tool.Driver.Version = &sc.xrayVersion
	run.Invocations = append(run.Invocations, sarif.NewInvocation().
		WithWorkingDirectory(sarif.NewSimpleArtifactLocation(target.Target)).
		WithExecutionSuccess(errorCount == 0),
	)
	return run
}

// validateBeforeParse checks if the parser is initialized to parse results (checks if Reset and at least one ParseNewTargetResults was called before)
func (sc *CmdResultsSarifConverter) validateBeforeParse() (err error) {
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	if (sc.hasViolationContext || sc.includeVulnerabilities) && sc.scaCurrentRun == nil {
		return results.ErrNoTargetConvertor
	}
	return
}

func (sc *CmdResultsSarifConverter) ParseViolations(target results.ScanTarget, scanResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.scaCurrentRun == nil {
		return
	}
	// Parse violations
	sarifResults, sarifRules, err := PrepareSarifScaViolations(sc.currentCmdType, target, scanResponse.Violations, sc.entitledForJas, applicabilityRuns...)
	if err != nil || len(sarifRules) == 0 || len(sarifResults) == 0 {
		return
	}
	sc.addScaResultsToCurrentRun(sarifRules, sarifResults...)
	return
}

func (sc *CmdResultsSarifConverter) ParseVulnerabilities(target results.ScanTarget, scanResponse services.ScanResponse, applicabilityRuns ...*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil || sc.scaCurrentRun == nil {
		return
	}
	sarifResults, sarifRules, err := PrepareSarifScaVulnerabilities(sc.currentCmdType, target, scanResponse.Vulnerabilities, sc.entitledForJas, applicabilityRuns...)
	if err != nil || len(sarifRules) == 0 || len(sarifResults) == 0 {
		return
	}
	sc.addScaResultsToCurrentRun(sarifRules, sarifResults...)
	return
}

func (sc *CmdResultsSarifConverter) ParseLicenses(target results.ScanTarget, licenses []services.License) (err error) {
	// Not supported in Sarif format
	return
}

func (sc *CmdResultsSarifConverter) ParseSecrets(target results.ScanTarget, secrets ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	sc.current.Runs = append(sc.current.Runs, patchRunsToPassIngestionRules(sc.currentCmdType, utils.SecretsScan, sc.patchBinaryPaths, target, secrets...)...)
	return
}

func (sc *CmdResultsSarifConverter) ParseIacs(target results.ScanTarget, iacs ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	sc.current.Runs = append(sc.current.Runs, patchRunsToPassIngestionRules(sc.currentCmdType, utils.IacScan, sc.patchBinaryPaths, target, iacs...)...)
	return
}

func (sc *CmdResultsSarifConverter) ParseSast(target results.ScanTarget, sast ...*sarif.Run) (err error) {
	if !sc.entitledForJas {
		return
	}
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	sc.current.Runs = append(sc.current.Runs, patchRunsToPassIngestionRules(sc.currentCmdType, utils.SastScan, sc.patchBinaryPaths, target, sast...)...)
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

func PrepareSarifScaViolations(cmdType utils.CommandType, target results.ScanTarget, violations []services.Violation, entitledForJas bool, applicabilityRuns ...*sarif.Run) ([]*sarif.Result, map[string]*sarif.ReportingDescriptor, error) {
	sarifResults := []*sarif.Result{}
	rules := map[string]*sarif.ReportingDescriptor{}
	_, _, err := results.PrepareScaViolations(
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
	err := results.PrepareScaVulnerabilities(
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
		currentResults, currentRule := parseScaToSarifFormat(cmdType, vulnerability.IssueId, vulnerability.Summary, markdownDescription, maxCveScore, getScaIssueSarifHeadline, cves, severity, applicabilityStatus, impactedPackagesName, impactedPackagesVersion, fixedVersions, directComponents)
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
		currentResults, currentRule := parseScaToSarifFormat(cmdType, violation.IssueId, violation.Summary, markdownDescription, maxCveScore, getScaIssueSarifHeadline, cves, severity, applicabilityStatus, impactedPackagesName, impactedPackagesVersion, fixedVersions, directComponents, violation.WatchName)
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
		currentResults, currentRule := parseScaToSarifFormat(cmdType, violation.LicenseKey, getLicenseViolationSummary(impactedPackagesName, impactedPackagesVersion, violation.LicenseKey), markdownDescription, maxCveScore, getXrayLicenseSarifHeadline, cves, severity, applicabilityStatus, impactedPackagesName, impactedPackagesVersion, fixedVersions, directComponents)
		cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, results.GetIssueIdentifier(cves, violation.LicenseKey, "_"))
		if _, ok := (*rules)[cveImpactedComponentRuleId]; !ok {
			// New Rule
			(*rules)[cveImpactedComponentRuleId] = currentRule
		}
		*sarifResults = append(*sarifResults, currentResults...)
		return nil
	}
}

func parseScaToSarifFormat(cmdType utils.CommandType, xrayId, summary, markdownDescription, cveScore string, generateTitleFunc func(depName string, version string, issueId string) string, cves []formats.CveRow, severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus, impactedPackagesName, impactedPackagesVersion string, fixedVersions []string, directComponents []formats.ComponentRow, watches ...string) (sarifResults []*sarif.Result, rule *sarif.ReportingDescriptor) {
	// General information
	issueId := results.GetIssueIdentifier(cves, xrayId, "_")
	cveImpactedComponentRuleId := results.GetScaIssueId(impactedPackagesName, impactedPackagesVersion, issueId)
	level := severityutils.SeverityToSarifSeverityLevel(severity)
	// Add rule for the cve if not exists
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
		issueLocation := getComponentSarifLocation(cmdType, directDependency)
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

func getScaIssueSarifHeadline(depName, version, issueId string) string {
	return fmt.Sprintf("[%s] %s %s", issueId, depName, version)
}

func getXrayLicenseSarifHeadline(depName, version, key string) string {
	return fmt.Sprintf("License violation [%s] in %s %s", key, depName, version)
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

func patchRunsToPassIngestionRules(cmdType utils.CommandType, subScanType utils.SubScanType, patchBinaryPaths bool, target results.ScanTarget, runs ...*sarif.Run) []*sarif.Run {
	// Since we run in temp directories files should be relative
	// Patch by converting the file paths to relative paths according to the invocations
	convertPaths(cmdType, subScanType, runs...)
	patchedRuns := []*sarif.Run{}
	// Patch changes may alter the original run, so we will create a new run for each
	for _, run := range runs {
		patched := sarifutils.CopyRunMetadata(run)
		if cmdType.IsTargetBinary() && subScanType == utils.SecretsScan {
			// Patch the tool name in case of binary scan
			sarifutils.SetRunToolName(BinarySecretScannerToolName, patched)
		}
		if patched.Tool.Driver != nil {
			patched.Tool.Driver.Rules = patchRules(cmdType, subScanType, run.Tool.Driver.Rules...)
		}
		patched.Results = patchResults(cmdType, subScanType, patchBinaryPaths, target, run, run.Results...)
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

func patchRules(commandType utils.CommandType, subScanType utils.SubScanType, rules ...*sarif.ReportingDescriptor) (patched []*sarif.ReportingDescriptor) {
	patched = []*sarif.ReportingDescriptor{}
	for _, rule := range rules {
		cloned := sarif.NewRule(rule.ID)
		if rule.Name != nil && rule.ID == *rule.Name {
			// SARIF1001 - if both 'id' and 'name' are present, they must be different. If they are identical, the tool must omit the 'name' property.
			cloned.Name = rule.Name
		}
		cloned.ShortDescription = rule.ShortDescription
		if commandType.IsTargetBinary() && subScanType == utils.SecretsScan {
			// Patch the rule name in case of binary scan
			sarifutils.SetRuleShortDescriptionText(fmt.Sprintf("[Secret in Binary found] %s", sarifutils.GetRuleShortDescriptionText(rule)), cloned)
		}
		cloned.FullDescription = rule.FullDescription
		cloned.Help = rule.Help
		if cloned.Help == nil {
			// Github code scanning ingestion rules rejects rules without help content.
			// Patch by transferring the full description to the help field.
			cloned.Help = rule.FullDescription
		}
		cloned.HelpURI = rule.HelpURI
		cloned.Properties = rule.Properties
		cloned.MessageStrings = rule.MessageStrings

		patched = append(patched, cloned)
	}
	return
}

func patchResults(commandType utils.CommandType, subScanType utils.SubScanType, patchBinaryPaths bool, target results.ScanTarget, run *sarif.Run, results ...*sarif.Result) (patched []*sarif.Result) {
	patched = []*sarif.Result{}
	for _, result := range results {
		if len(result.Locations) == 0 {
			// Github code scanning ingestion rules rejects results without locations.
			// Patch by removing results without locations.
			log.Debug(fmt.Sprintf("[%s] Removing result [ruleId=%s] without locations: %s", subScanType.String(), sarifutils.GetResultRuleId(result), sarifutils.GetResultMsgText(result)))
			continue
		}
		if commandType.IsTargetBinary() {
			var markdown string
			if subScanType == utils.SecretsScan {
				markdown = getSecretInBinaryMarkdownMsg(commandType, target, result)
			} else {
				markdown = getScaInBinaryMarkdownMsg(commandType, target, result)
			}
			sarifutils.SetResultMsgMarkdown(markdown, result)
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
	ids := []string{sarifutils.GetRunToolName(run), sarifutils.GetResultRuleId(result)}
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
