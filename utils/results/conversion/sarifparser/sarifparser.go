package sarifparser

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	fixedVersionSarifPropertyKey  = "fixedVersion"
	jfrogFingerprintAlgorithmName = "jfrogFingerprintHash"
	MissingCveScore               = "0"
	maxPossibleCve                = 10.0

	// #nosec G101 -- Not credentials.
	BinarySecretScannerToolName = "JFrog Binary Secrets Scanner"
	PolicyEnforcerToolName      = "JFrog Policy Enforcer"
)

var (
	GithubBaseWorkflowDir         = filepath.Join(".github", "workflows")
	dockerJasLocationPathPattern  = regexp.MustCompile(`.*[\\/](?P<algorithm>[^\\/]+)[\\/](?P<hash>[0-9a-fA-F]+)[\\/](?P<relativePath>.*)`)
	dockerScaComponentNamePattern = regexp.MustCompile(`(?P<algorithm>[^__]+)__(?P<hash>[0-9a-fA-F]+)\.tar`)
)

const (
	ScaRun        RunInJfrogReport = "sca"
	SecretsRun    RunInJfrogReport = "secrets"
	IacRun        RunInJfrogReport = "iac"
	SastRun       RunInJfrogReport = "sast"
	ViolationsRun RunInJfrogReport = "violations"
)

type RunInJfrogReport string

type CmdResultsSarifConverter struct {
	baseJfrogUrl string
	// If we are running on Github actions, we need to add/change information to the output
	patchBinaryPaths bool
	// Current stream parse cache information
	current                    *sarif.Report
	currentTargetConvertedRuns *currentTargetRuns
	violationsRun              *sarif.Run
	currentErrors              []error
	// General information on the current command results
	entitledForJas bool
	xrayVersion    string
	currentCmdType utils.CommandType
	status         results.ResultsStatus
}

type currentTargetRuns struct {
	currentTarget results.ScanTarget
	// Current run cache information
	scaCurrentRun     *sarif.Run
	secretsCurrentRun *sarif.Run
	iacCurrentRun     *sarif.Run
	sastCurrentRun    *sarif.Run
}

// Parse parameters for the SCA result
type scaParseParams struct {
	CmdType                 utils.CommandType
	IssueId                 string
	Summary                 string
	MarkdownDescription     string
	SeverityScore           string
	ImpactedPackagesName    string
	ImpactedPackagesVersion string
	GenerateTitleFunc       func(depName string, version string, issueId string, watch string) string
	Cves                    []formats.CveRow
	AddFixedVersionProperty bool
	Severity                severityutils.Severity
	ApplicabilityStatus     jasutils.ApplicabilityStatus
	FixedVersions           []string
	DirectComponents        []formats.ComponentRow
	Violation               *violationutils.Violation
	ImpactPaths             [][]formats.ComponentRow
}

func NewCmdResultsSarifConverter(baseUrl string, patchBinaryPaths bool) *CmdResultsSarifConverter {
	return &CmdResultsSarifConverter{baseJfrogUrl: baseUrl, patchBinaryPaths: patchBinaryPaths}
}

func (sc *CmdResultsSarifConverter) Get() (*sarif.Report, error) {
	if sc.current == nil {
		return sarif.NewReport(), nil
	}
	// Flush the current run
	if err := sc.ParseNewTargetResults(results.ScanTarget{}, nil); err != nil {
		return sarif.NewReport(), err
	}
	// Add the violations run if needed
	if sc.violationsRun != nil && len(sc.violationsRun.Results) > 0 {
		sc.current.Runs = append(sc.current.Runs, patchSarifRuns(sc.getViolationsConvertParams(), sc.violationsRun)...)
	}
	return sarifutils.CombineMultipleRunsWithSameTool(sc.current), nil
}

func (sc *CmdResultsSarifConverter) Reset(metadata results.ResultsMetaData, statusCodes results.ResultsStatus, multipleTargets bool) (err error) {
	sc.current = sarif.NewReport()
	// Reset the current stream general information
	sc.currentCmdType = metadata.CmdType
	sc.xrayVersion = metadata.XrayVersion
	sc.entitledForJas = metadata.EntitledForJas
	sc.status = statusCodes
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
	sc.currentErrors = errors
	return
}

func (sc *CmdResultsSarifConverter) flush() {
	if sc.currentTargetConvertedRuns == nil {
		return
	}
	// Flush Sca if needed
	if sc.currentTargetConvertedRuns.scaCurrentRun != nil {
		sc.current.Runs = append(sc.current.Runs, patchSarifRuns(sc.getVulnerabilitiesConvertParams(utils.ScaScan), sc.currentTargetConvertedRuns.scaCurrentRun)...)
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
	sc.currentTargetConvertedRuns = nil
}

func (sc *CmdResultsSarifConverter) createScaRun(target results.ScanTarget, errorCount int) *sarif.Run {
	run := sarif.NewRunWithInformationURI(utils.XrayToolName, utils.BaseDocumentationURL+"xray/features-and-capabilities/sca")
	run.Tool.Driver.Version = &sc.xrayVersion
	wd := target.Target
	if sc.currentCmdType.IsTargetBinary() {
		// For binary, the target is a file and not a directory
		wd = filepath.Dir(wd)
	}
	run.Invocations = append(run.Invocations, sarif.NewInvocation().
		WithWorkingDirectory(sarif.NewSimpleArtifactLocation(utils.ToURI(wd))).
		WithExecutionSuccessful(errorCount == 0),
	)
	return run
}

func (sc *CmdResultsSarifConverter) createViolationsRun() *sarif.Run {
	run := sarif.NewRunWithInformationURI(PolicyEnforcerToolName, utils.BaseDocumentationURL+"xray/features-and-capabilities/sdlc-policy-mangement/sdlc-policy-mangement")
	run.Tool.Driver.Version = &sc.xrayVersion
	currentWd, _ := os.Getwd()
	run.Invocations = append(run.Invocations, sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(utils.ToURI(currentWd))).WithExecutionSuccessful(true))
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

func (sc *CmdResultsSarifConverter) DeprecatedParseScaVulnerabilities(descriptors []string, scaResponse services.ScanResponse, applicableScan ...[]*sarif.Run) (err error) {
	return sc.parseScaVulnerabilities(sc.currentTargetConvertedRuns.currentTarget, descriptors, scaResponse, applicableScan...)
}

func (sc *CmdResultsSarifConverter) ParseViolations(violationsScanResults violationutils.Violations) (err error) {
	if sc.current == nil {
		return results.ErrResetConvertor
	}
	if sc.status.IsScanFailed(results.CmdStepViolations) {
		return
	}
	// Create the violations run if needed
	if sc.violationsRun == nil {
		sc.violationsRun = sc.createViolationsRun()
	}
	// Sca violations (Operational risk are not supported in Sarif format)
	scaSarifResults := []*sarif.Result{}
	scaRules := map[string]*sarif.ReportingDescriptor{}
	// Cve violations
	for _, cveViolation := range violationsScanResults.Sca {
		applicabilityStatus, maxCveScore, cves, fixedVersions, markdownDescription, e := prepareCdxInfoForSarif(
			cveViolation.CveVulnerability,
			cveViolation.Severity,
			cveViolation.ContextualAnalysis,
			cveViolation.DirectComponents,
			cveViolation.FixedVersions,
		)
		if e != nil {
			err = errors.Join(err, e)
			continue
		}
		compName, compVersion, _ := techutils.SplitPackageURL(cveViolation.ImpactedComponent.PackageURL)
		createAndAddScaIssue(scaParseParams{
			CmdType:                 sc.currentCmdType,
			IssueId:                 cveViolation.CveVulnerability.ID,
			Summary:                 cveViolation.CveVulnerability.Description,
			Violation:               &cveViolation.Violation,
			MarkdownDescription:     markdownDescription,
			SeverityScore:           maxCveScore,
			GenerateTitleFunc:       getScaSecurityViolationSarifHeadline,
			Cves:                    cves,
			Severity:                cveViolation.Severity,
			ApplicabilityStatus:     applicabilityStatus,
			ImpactedPackagesName:    compName,
			ImpactedPackagesVersion: compVersion,
			AddFixedVersionProperty: true,
			FixedVersions:           fixedVersions,
			DirectComponents:        cveViolation.DirectComponents,
			ImpactPaths:             cveViolation.ImpactPaths,
		}, &scaSarifResults, &scaRules)
	}
	// License violations
	for _, licenseViolation := range violationsScanResults.License {
		compName, compVersion, _ := techutils.SplitPackageURL(licenseViolation.ImpactedComponent.PackageURL)
		markdownDescription, e := getScaLicenseViolationMarkdown(compName, compVersion, licenseViolation.LicenseKey, licenseViolation.DirectComponents)
		if e != nil {
			err = errors.Join(err, e)
			continue
		}
		createAndAddScaIssue(scaParseParams{
			CmdType:                 sc.currentCmdType,
			IssueId:                 licenseViolation.LicenseKey,
			Summary:                 getLicenseViolationSummary(compName, compVersion, licenseViolation.LicenseKey),
			Violation:               &licenseViolation.Violation,
			MarkdownDescription:     markdownDescription,
			SeverityScore:           fmt.Sprintf("%.1f", severityutils.GetSeverityScore(licenseViolation.Severity, jasutils.Applicable)),
			GenerateTitleFunc:       getXrayLicenseSarifHeadline,
			Severity:                licenseViolation.Severity,
			ImpactedPackagesName:    compName,
			ImpactedPackagesVersion: compVersion,
			DirectComponents:        licenseViolation.DirectComponents,
			ImpactPaths:             licenseViolation.ImpactPaths,
		}, &scaSarifResults, &scaRules)
	}
	if len(scaRules) > 0 && len(scaSarifResults) > 0 {
		sc.addResultsToCurrentRun(ViolationsRun, maps.Values(scaRules), scaSarifResults...)
	}
	// Secrets violations
	for _, secretViolation := range violationsScanResults.Secrets {
		secretResult, secretRule := createJasViolation(secretViolation)
		sc.addResultsToCurrentRun(ViolationsRun, []*sarif.ReportingDescriptor{secretRule}, secretResult)
	}
	// IaC violations
	for _, iacViolation := range violationsScanResults.Iac {
		iacResult, iacRule := createJasViolation(iacViolation)
		sc.addResultsToCurrentRun(ViolationsRun, []*sarif.ReportingDescriptor{iacRule}, iacResult)
	}
	// Sast violations
	for _, sastViolation := range violationsScanResults.Sast {
		sastResult, sastRule := createJasViolation(sastViolation)
		sc.addResultsToCurrentRun(ViolationsRun, []*sarif.ReportingDescriptor{sastRule}, sastResult)
	}
	return
}

func (sc *CmdResultsSarifConverter) parseScaVulnerabilities(target results.ScanTarget, descriptors []string, scanResponse services.ScanResponse, applicableScan ...[]*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil {
		return
	}
	if sc.currentTargetConvertedRuns.scaCurrentRun == nil {
		sc.currentTargetConvertedRuns.scaCurrentRun = sc.createScaRun(target, len(sc.currentErrors))
	}
	sarifResults, sarifRules, err := PrepareSarifScaVulnerabilities(sc.currentCmdType, target, descriptors, scanResponse.Vulnerabilities, sc.entitledForJas, results.CollectRuns(applicableScan...)...)
	if err != nil || len(sarifRules) == 0 || len(sarifResults) == 0 {
		return
	}
	sc.addResultsToCurrentRun(ScaRun, maps.Values(sarifRules), sarifResults...)
	return
}

func (sc *CmdResultsSarifConverter) DeprecatedParseLicenses(_ services.ScanResponse) (err error) {
	// Not supported in Sarif format
	return
}

func (sc *CmdResultsSarifConverter) ParseSbom(_ *cyclonedx.BOM) (err error) {
	// Not supported in Sarif format
	return
}

func (sc *CmdResultsSarifConverter) ParseSbomLicenses(components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (err error) {
	// Not supported in Sarif format
	return
}

func (sc *CmdResultsSarifConverter) ParseCVEs(enrichedSbom *cyclonedx.BOM, applicableScan ...[]*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil {
		return
	}
	if sc.currentTargetConvertedRuns.scaCurrentRun == nil {
		sc.currentTargetConvertedRuns.scaCurrentRun = sc.createScaRun(sc.currentTargetConvertedRuns.currentTarget, len(sc.currentErrors))
	}
	sarifResults := []*sarif.Result{}
	sarifRules := map[string]*sarif.ReportingDescriptor{}
	err = results.ForEachScaBomVulnerability(sc.currentTargetConvertedRuns.currentTarget, enrichedSbom, sc.entitledForJas, results.CollectRuns(applicableScan...), addCdxScaVulnerability(sc.currentCmdType, enrichedSbom, &sarifResults, &sarifRules))
	if err != nil || len(sarifRules) == 0 || len(sarifResults) == 0 {
		return
	}
	sc.addResultsToCurrentRun(ScaRun, maps.Values(sarifRules), sarifResults...)
	return
}

func addCdxScaVulnerability(cmdType utils.CommandType, enrichedSbom *cyclonedx.BOM, sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) results.ParseBomScaVulnerabilityFunc {
	return func(vulnerability cyclonedx.Vulnerability, component cyclonedx.Component, fixedVersion *[]cyclonedx.AffectedVersions, applicability *formats.Applicability, severity severityutils.Severity) (e error) {
		// Prepare the required fields
		directDependencies := getDirectDependenciesForSarif(component, enrichedSbom)
		applicabilityStatus, maxCveScore, cves, fixedVersions, markdownDescription, e := prepareCdxInfoForSarif(vulnerability, severity, applicability, directDependencies, fixedVersion)
		if e != nil {
			return
		}
		dependencies := []cyclonedx.Dependency{}
		if enrichedSbom.Dependencies != nil {
			dependencies = append(dependencies, *enrichedSbom.Dependencies...)
		}
		compName, compVersion, _ := techutils.SplitPackageURL(component.PackageURL)
		createAndAddScaIssue(scaParseParams{
			CmdType:                 cmdType,
			IssueId:                 vulnerability.ID,
			Summary:                 vulnerability.Description,
			MarkdownDescription:     markdownDescription,
			SeverityScore:           maxCveScore,
			GenerateTitleFunc:       getScaVulnerabilitySarifHeadline,
			Cves:                    cves,
			Severity:                severity,
			ApplicabilityStatus:     applicabilityStatus,
			ImpactedPackagesName:    compName,
			ImpactedPackagesVersion: compVersion,
			AddFixedVersionProperty: true,
			FixedVersions:           fixedVersions,
			DirectComponents:        directDependencies,
			ImpactPaths:             results.BuildImpactPath(component, *enrichedSbom.Components, dependencies...),
		}, sarifResults, rules)
		return
	}
}

func getDirectDependenciesForSarif(component cyclonedx.Component, enrichedSbom *cyclonedx.BOM) (directDependencies []formats.ComponentRow) {
	// Extract the direct dependencies
	dependencies := []cyclonedx.Dependency{}
	if enrichedSbom.Dependencies != nil {
		dependencies = append(dependencies, *enrichedSbom.Dependencies...)
	}
	return results.GetDirectDependenciesAsComponentRows(component, *enrichedSbom.Components, dependencies)
}

func prepareCdxInfoForSarif(vulnerability cyclonedx.Vulnerability, severity severityutils.Severity, applicability *formats.Applicability, directDependencies []formats.ComponentRow, fixedVersion *[]cyclonedx.AffectedVersions) (applicabilityStatus jasutils.ApplicabilityStatus, maxCveScore string, cves []formats.CveRow, fixedVersions []string, markdownDescription string, err error) {
	// Extract the applicability status
	applicabilityStatus = jasutils.NotScanned
	if applicability != nil {
		applicabilityStatus = jasutils.ConvertToApplicabilityStatus(applicability.Status)
	}
	// Extract the CVEs
	cves = results.CdxVulnToCveRows(vulnerability, applicability)
	// Extract the fixed versions
	fixedVersions = results.CdxToFixedVersions(fixedVersion)
	// Extract the maximum CVE score
	if maxCveScore, err = results.FindMaxCVEScore(severity, applicabilityStatus, cves); err != nil {
		return
	}
	// Prepare the markdown description
	markdownDescription, err = getScaIssueMarkdownDescription(directDependencies, maxCveScore, applicabilityStatus, fixedVersions)
	return
}

func getSarifConvertParams(cmdType utils.CommandType, scanType utils.SubScanType, target *results.ScanTarget, isViolations, patchBinaryPaths bool, baseUrl string) PatchSarifParams {
	return PatchSarifParams{
		BaseJfrogUrl:     baseUrl,
		CmdType:          cmdType,
		SubScanType:      scanType,
		Target:           target,
		IsViolations:     isViolations,
		PatchBinaryPaths: patchBinaryPaths,
		ConvertPaths:     !isViolations,
		CopyContent:      !isViolations,
	}
}

func (sc *CmdResultsSarifConverter) getViolationsConvertParams() PatchSarifParams {
	return getSarifConvertParams(sc.currentCmdType, "", nil, true, sc.patchBinaryPaths, sc.baseJfrogUrl)
}

func (sc *CmdResultsSarifConverter) getVulnerabilitiesConvertParams(scanType utils.SubScanType) PatchSarifParams {
	return getSarifConvertParams(sc.currentCmdType, scanType, &sc.currentTargetConvertedRuns.currentTarget, false, sc.patchBinaryPaths, sc.baseJfrogUrl)
}

func (sc *CmdResultsSarifConverter) ParseSecrets(secrets ...[]*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil || !sc.entitledForJas {
		return
	}
	sc.currentTargetConvertedRuns.secretsCurrentRun = combineJasRunsToCurrentRun(sc.currentTargetConvertedRuns.secretsCurrentRun, patchSarifRuns(sc.getVulnerabilitiesConvertParams(utils.SecretsScan), results.CollectRuns(secrets...)...)...)
	return
}

func (sc *CmdResultsSarifConverter) ParseIacs(iacs ...[]*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil || !sc.entitledForJas {
		return
	}
	sc.currentTargetConvertedRuns.iacCurrentRun = combineJasRunsToCurrentRun(sc.currentTargetConvertedRuns.iacCurrentRun, patchSarifRuns(sc.getVulnerabilitiesConvertParams(utils.IacScan), results.CollectRuns(iacs...)...)...)
	return
}

func (sc *CmdResultsSarifConverter) ParseSast(sast ...[]*sarif.Run) (err error) {
	if err = sc.validateBeforeParse(); err != nil || !sc.entitledForJas {
		return
	}
	sc.currentTargetConvertedRuns.sastCurrentRun = combineJasRunsToCurrentRun(sc.currentTargetConvertedRuns.sastCurrentRun, patchSarifRuns(sc.getVulnerabilitiesConvertParams(utils.SastScan), results.CollectRuns(sast...)...)...)
	return
}

func (sc *CmdResultsSarifConverter) addResultsToCurrentRun(runType RunInJfrogReport, rules []*sarif.ReportingDescriptor, results ...*sarif.Result) {
	var currentRun *sarif.Run
	switch runType {
	case ScaRun:
		currentRun = sc.currentTargetConvertedRuns.scaCurrentRun
	case SecretsRun:
		currentRun = sc.currentTargetConvertedRuns.secretsCurrentRun
	case IacRun:
		currentRun = sc.currentTargetConvertedRuns.iacCurrentRun
	case SastRun:
		currentRun = sc.currentTargetConvertedRuns.sastCurrentRun
	case ViolationsRun:
		currentRun = sc.violationsRun
	default:
		log.Error(fmt.Sprintf("Unknown run type: %s", runType))
		return
	}
	for _, rule := range rules {
		if exist := sarifutils.GetRuleById(currentRun, sarifutils.GetRuleId(rule)); exist != nil {
			// Rule already exists, skip adding it again
			continue
		}
		currentRun.Tool.Driver.AddRule(rule)
	}
	for _, result := range results {
		currentRun.AddResult(result)
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
		} else if sarifutils.GetRunToolName(destination) != sarifutils.GetRunToolName(run) {
			log.Warn(fmt.Sprintf("Skipping JAS run (%s) as it doesn't match the current run (%s)", sarifutils.GetRunToolName(run), sarifutils.GetRunToolName(destination)))
			continue
		}
		// Combine the rules and results of the run to the destination
		for _, rule := range sarifutils.GetRunRules(run) {
			if exist := sarifutils.GetRuleById(destination, sarifutils.GetRuleId(rule)); exist != nil {
				// Rule already exists, skip adding it again
				continue
			}
			destination.Tool.Driver.AddRule(rule)
		}
		for _, result := range run.Results {
			destination.AddResult(result)
		}
	}
	return destination
}

func PrepareSarifScaVulnerabilities(cmdType utils.CommandType, target results.ScanTarget, descriptors []string, vulnerabilities []services.Vulnerability, entitledForJas bool, applicabilityRuns ...*sarif.Run) ([]*sarif.Result, map[string]*sarif.ReportingDescriptor, error) {
	sarifResults := []*sarif.Result{}
	rules := map[string]*sarif.ReportingDescriptor{}
	err := results.ForEachScanGraphVulnerability(
		target,
		descriptors,
		vulnerabilities,
		entitledForJas,
		applicabilityRuns,
		addSarifScaVulnerability(cmdType, &sarifResults, &rules),
	)
	return sarifResults, rules, err
}

func addSarifScaVulnerability(cmdType utils.CommandType, sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) results.ParseScanGraphVulnerabilityFunc {
	return func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersions []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		maxCveScore, err := results.FindMaxCVEScore(severity, applicabilityStatus, cves)
		if err != nil {
			return err
		}
		markdownDescription, err := getScaIssueMarkdownDescription(directComponents, maxCveScore, applicabilityStatus, fixedVersions)
		if err != nil {
			return err
		}
		impactedPackagesName, impactedPackagesVersion, _ := techutils.SplitComponentId(impactedPackagesId)
		createAndAddScaIssue(scaParseParams{
			CmdType:                 cmdType,
			IssueId:                 vulnerability.IssueId,
			Summary:                 vulnerability.Summary,
			MarkdownDescription:     markdownDescription,
			SeverityScore:           maxCveScore,
			GenerateTitleFunc:       getScaVulnerabilitySarifHeadline,
			Cves:                    cves,
			Severity:                severity,
			ApplicabilityStatus:     applicabilityStatus,
			ImpactedPackagesName:    impactedPackagesName,
			ImpactedPackagesVersion: impactedPackagesVersion,
			AddFixedVersionProperty: true,
			FixedVersions:           fixedVersions,
			DirectComponents:        directComponents,
			ImpactPaths:             impactPaths,
		}, sarifResults, rules)
		return nil
	}
}

func createAndAddScaIssue(params scaParseParams, sarifResults *[]*sarif.Result, rules *map[string]*sarif.ReportingDescriptor) {
	currentResults, currentRule := parseScaToSarifFormat(params)
	cveImpactedComponentRuleId := results.GetScaIssueId(params.ImpactedPackagesName, params.ImpactedPackagesVersion, results.GetIssueIdentifier(params.Cves, params.IssueId, "_"))
	if _, ok := (*rules)[cveImpactedComponentRuleId]; !ok {
		// New Rule
		(*rules)[cveImpactedComponentRuleId] = currentRule
	}
	*sarifResults = append(*sarifResults, currentResults...)
}

func createJasViolation(jasViolation violationutils.JasViolation) (sarifResult *sarif.Result, rule *sarif.ReportingDescriptor) {
	// Rule is the same as the vulnerability rule, no need to create a new one
	rule = jasViolation.Rule
	// Copy the result to avoid modifying the original one, Append the violation context to the result properties
	sarifResult = appendViolationContextToSarifResult(sarifutils.CopyResult(jasViolation.Result), jasViolation.Violation)
	return
}

func parseScaToSarifFormat(params scaParseParams) (sarifResults []*sarif.Result, rule *sarif.ReportingDescriptor) {
	// General information
	issueId := results.GetIssueIdentifier(params.Cves, params.IssueId, "_")
	cveImpactedComponentRuleId := results.GetScaIssueId(params.ImpactedPackagesName, params.ImpactedPackagesVersion, issueId)
	level := severityutils.SeverityToSarifSeverityLevel(params.Severity)
	isViolation := params.Violation != nil
	watch := ""
	if isViolation {
		watch = params.Violation.Watch
	}
	// Add rule for the cve if not exists
	rule = getScaIssueSarifRule(
		params.ImpactPaths,
		cveImpactedComponentRuleId,
		params.GenerateTitleFunc(params.ImpactedPackagesName, params.ImpactedPackagesVersion, issueId, watch),
		params.SeverityScore,
		params.Summary,
		params.MarkdownDescription,
	)
	for _, directDependency := range params.DirectComponents {
		// Create result for each direct dependency
		issueResult := sarif.NewRuleResult(cveImpactedComponentRuleId).
			WithMessage(sarif.NewTextMessage(params.GenerateTitleFunc(directDependency.Name, directDependency.Version, issueId, watch))).
			WithLevel(level.String())
		// Add properties
		issueResult = appendScaVulnerabilityPropertiesToSarifResult(issueResult, params.ApplicabilityStatus, params.FixedVersions, params.AddFixedVersionProperty)
		if isViolation {
			issueResult = appendViolationContextToSarifResult(issueResult, *params.Violation)
		}
		// Add location
		issueLocation := getComponentSarifLocation(params.CmdType, directDependency)
		if issueLocation != nil {
			issueResult.AddLocation(issueLocation)
		}
		sarifResults = append(sarifResults, issueResult)
	}
	return
}

func appendScaVulnerabilityPropertiesToSarifResult(sarifResult *sarif.Result, applicabilityStatus jasutils.ApplicabilityStatus, fixedVersions []string, addFixedVersionProperty bool) *sarif.Result {
	if sarifResult.Properties == nil {
		sarifResult.Properties = sarif.NewPropertyBag()
	}
	if applicabilityStatus != jasutils.NotScanned {
		sarifResult.Properties.Add(jasutils.ApplicabilitySarifPropertyKey, applicabilityStatus.String())
	}
	if addFixedVersionProperty {
		// Add fixed versions property
		sarifResult.Properties.Add(fixedVersionSarifPropertyKey, getFixedVersionString(fixedVersions))
	}
	return sarifResult
}

func appendViolationContextToSarifResult(sarifResult *sarif.Result, violation violationutils.Violation) *sarif.Result {
	if sarifResult.Properties == nil {
		sarifResult.Properties = sarif.NewPropertyBag()
	}
	if violation.Watch != "" {
		sarifResult.Properties.Add(sarifutils.WatchSarifPropertyKey, violation.Watch)
	}
	if violation.ViolationType != "" {
		sarifResult.Properties.Add(sarifutils.ViolationTypeSarifPropertyKey, violation.ViolationType.String())
	}
	if len(violation.Policies) > 0 {
		policies := []string{}
		for _, policy := range violation.Policies {
			policies = append(policies, strings.TrimSpace(policy.PolicyName))
		}
		sarifResult.Properties.Add(sarifutils.PoliciesSarifPropertyKey, strings.Join(policies, ","))
	}
	return sarifResult
}

func getScaIssueSarifRule(impactPaths [][]formats.ComponentRow, ruleId, ruleDescription, maxCveScore, summary, markdownDescription string) *sarif.ReportingDescriptor {
	cveRuleProperties := sarif.NewPropertyBag()
	cveRuleProperties.Add(severityutils.SarifSeverityRuleProperty, maxCveScore)
	if len(impactPaths) > 0 {
		cveRuleProperties.Add(sarifutils.SarifImpactPathsRulePropertyKey, impactPaths)
	}
	return sarif.NewRule(ruleId).
		WithName(results.IdToName(ruleId)).
		WithDescription(ruleDescription).
		WithFullDescription(sarif.NewMultiformatMessageString().WithText(summary).WithMarkdown(markdownDescription)).
		WithHelp(sarif.NewMultiformatMessageString().WithText(summary).WithMarkdown(markdownDescription)).
		WithProperties(cveRuleProperties)
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
				logicalLocation.Properties = sarif.NewPropertyBag().Add("algorithm", algorithm)
			}
			logicalLocations = append(logicalLocations, logicalLocation)
		}
	}
	location := sarif.NewLocation().WithPhysicalLocation(sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithURI(filepath.ToSlash(filePath))))
	if len(logicalLocations) > 0 {
		location.WithLogicalLocations(logicalLocations)
	}
	return location
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

type PatchSarifParams struct {
	// Required parameters
	CmdType     utils.CommandType
	SubScanType utils.SubScanType
	// Optional parameters
	CopyContent  bool
	ConvertPaths bool
	// Use instead of invocation to convert the paths to relative
	WorkingDirectory string
	// Indicate if the runs are violations runs
	IsViolations bool
	// Add Analytics to the runs when viewed in web
	BaseJfrogUrl string
	// For uploading to Source Code Scanning, replace binary inner paths with the DOCKER file path or workflow path
	// (append the replaced path to the help text)
	PatchBinaryPaths bool
	// Add docker image tag for docker image scans
	Target *results.ScanTarget
}

// PatchSarifRuns patches the given SARIF runs according to the given parameters.
// If CopyContent is true, the runs are copied before patching to avoid modifying the original runs.
// This is needed in order to support and insure the content to pass the ingestion rules for JFrog platform and GitHub code scanning.
func patchSarifRuns(params PatchSarifParams, runs ...*sarif.Run) []*sarif.Run {
	// Prepare the runs according to the parameters
	input, patchedRuns := []*sarif.Run{}, []*sarif.Run{}
	if params.CopyContent {
		for _, run := range runs {
			input = append(input, sarifutils.CopyRun(run))
		}
	} else {
		input = runs
	}
	// Patch the runs to pass the ingestion rules
	for _, run := range input {
		// Since we run in temp directories files should be relative
		// Patch by converting the file paths to relative paths according to the invocations
		patchPaths(params, run)
		// Patch the tool content according to the parameters
		pathTool(params, run)
		// Patch the results according to the parameters
		run.Results = patchResults(params.CmdType, params.SubScanType, params.PatchBinaryPaths, params.IsViolations, params.Target, run, run.Results...)
		// Add the patched run to the list
		patchedRuns = append(patchedRuns, run)
	}
	return patchedRuns
}

func patchPaths(params PatchSarifParams, runs ...*sarif.Run) {
	if !params.ConvertPaths {
		return
	}
	if params.WorkingDirectory == "" {
		// Convert base on invocation
		sarifutils.ConvertRunsPathsToRelative(runs...)
	} else {
		// Convert base on the given working directory
		sarifutils.ConvertRunsPathsToRelativeFromWd(params.WorkingDirectory, runs...)
	}
	if params.CmdType != utils.DockerImage || params.SubScanType != utils.SecretsScan {
		return
	}
	for _, run := range runs {
		for _, result := range run.Results {
			// For Docker secret scan, patch the logical location if not exists
			patchDockerSecretLocations(result)
		}
	}
}

func pathTool(params PatchSarifParams, runs ...*sarif.Run) {
	for _, run := range runs {
		if params.CmdType.IsTargetBinary() && params.SubScanType == utils.SecretsScan {
			// Patch the tool name in case of secret binary scan
			sarifutils.SetRunToolName(BinarySecretScannerToolName, run)
		}
		if run.Tool.Driver != nil {
			run.Tool.Driver.Rules = patchRules(params.BaseJfrogUrl, params.CmdType, params.SubScanType, params.IsViolations, run.Tool.Driver.Rules...)
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
		logicalLocation.Properties = sarif.NewPropertyBag().Add("algorithm", algorithm)
		location.LogicalLocations = append(location.LogicalLocations, logicalLocation)
		sarifutils.SetLocationFileName(location, relativePath)
	}
}

func patchRules(platformBaseUrl string, commandType utils.CommandType, subScanType utils.SubScanType, isViolations bool, rules ...*sarif.ReportingDescriptor) (patched []*sarif.ReportingDescriptor) {
	patched = []*sarif.ReportingDescriptor{}
	for _, rule := range rules {
		if rule.Name != nil && sarifutils.GetRuleId(rule) == *rule.Name {
			// SARIF1001 - if both 'id' and 'name' are present, they must be different. If they are identical, the tool must omit the 'name' property.
			rule.Name = nil
		}
		scanType := getScanTypeFromRule(subScanType, rule)
		if commandType.IsTargetBinary() && scanType == utils.SecretsScan {
			// Patch the rule name in case of binary scan
			sarifutils.SetRuleShortDescriptionText(fmt.Sprintf("[Secret in Binary found] %s", sarifutils.GetRuleShortDescriptionText(rule)), rule)
		}
		if isViolations {
			// Add prefix to the rule description for violations
			sarifutils.SetRuleShortDescriptionText(fmt.Sprintf("[Security Violation] %s", sarifutils.GetRuleShortDescriptionText(rule)), rule)
		}
		if rule.Help == nil {
			// Github code scanning ingestion rules rejects rules without help content.
			// Patch by transferring the full description to the help field.
			rule.Help = rule.FullDescription
		}
		// Add analytics hidden pixel to the help content if needed (Github code scanning)
		if analytics := getAnalyticsHiddenPixel(platformBaseUrl, scanType); rule.Help != nil && analytics != "" {
			rule.Help.Markdown = utils.NewStringPtr(fmt.Sprintf("%s\n%s", analytics, sarifutils.GetRuleHelpMarkdown(rule)))
		}
		patched = append(patched, rule)
	}
	return
}

func getScanTypeFromRule(subScanType utils.SubScanType, rule *sarif.ReportingDescriptor) utils.SubScanType {
	if rule == nil {
		return subScanType
	}
	return getScanType(subScanType, sarifutils.GetRuleId(rule))
}

func getScanTypeFromResult(subScanType utils.SubScanType, result *sarif.Result) utils.SubScanType {
	if result == nil {
		return subScanType
	}
	// Try to get from properties first
	if violationType := sarifutils.GetResultViolationType(result); violationType != "" {
		return getResultViolationType(violationType)
	}
	// Fallback to rule id
	return getScanType(subScanType, sarifutils.GetResultRuleId(result))
}

func getResultViolationType(violationType string) utils.SubScanType {
	switch violationutils.ViolationIssueType(violationType) {
	case violationutils.SecretsViolationType:
		return utils.SecretsScan
	case violationutils.IacViolationType:
		return utils.IacScan
	case violationutils.SastViolationType:
		return utils.SastScan
	default:
		return utils.ScaScan
	}
}

func getScanType(defaultType utils.SubScanType, scanType string) utils.SubScanType {
	if defaultType != "" || scanType == "" {
		// If default type is given, use it
		return defaultType
	}
	if strings.HasPrefix(scanType, "CVE") || strings.HasPrefix(scanType, "XRAY") {
		return utils.ScaScan
	}
	if strings.HasPrefix(scanType, "EXP") || strings.Contains(scanType, "SECRET") {
		return utils.SecretsScan
	}
	// TODO: Add more rules to identify IAC
	// Default to SAST
	return utils.SastScan
}

func patchResults(commandType utils.CommandType, subScanType utils.SubScanType, patchBinaryPaths, isJasViolations bool, target *results.ScanTarget, run *sarif.Run, results ...*sarif.Result) (patched []*sarif.Result) {
	patched = []*sarif.Result{}
	for _, result := range results {
		scanType := getScanTypeFromResult(subScanType, result)
		if len(result.Locations) == 0 {
			// Github code scanning ingestion rules rejects results without locations.
			// Patch by removing results without locations.
			log.Debug(fmt.Sprintf("[%s] Removing result [ruleId=%s] without locations: %s", scanType.String(), sarifutils.GetResultRuleId(result), sarifutils.GetResultMsgText(result)))
			continue
		}
		if commandType == utils.DockerImage && subScanType == utils.SecretsScan {
			// For Docker secret scan, patch the logical location if not exists
			patchDockerSecretLocations(result)
		}
		patchResultMsg(result, target, commandType, scanType, isJasViolations)
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

func patchResultMsg(result *sarif.Result, target *results.ScanTarget, commandType utils.CommandType, subScanType utils.SubScanType, isViolations bool) {
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
	if isViolations {
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
	// Validate file path to prevent directory traversal
	if workspace := os.Getenv(utils.CurrentGithubWorkflowWorkspaceEnvVar); workspace != "" && !strings.Contains(workspace, "..") {
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
	// Validate file path to prevent directory traversal
	if workspace := os.Getenv(utils.CurrentGithubWorkflowWorkspaceEnvVar); workspace != "" && !strings.Contains(workspace, "..") {
		if exists, err := fileutils.IsDirExists(filepath.Join(workspace, GithubBaseWorkflowDir), false); err == nil && exists {
			return filepath.Join(workspace, GithubBaseWorkflowDir)
		}
	}
	return ""
}

func getWorkflowFileLocationIfExists() (location string) {
	workflowName := os.Getenv(utils.CurrentGithubWorkflowNameEnvVar)
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

func getSecretInBinaryMarkdownMsg(commandType utils.CommandType, target *results.ScanTarget, result *sarif.Result) string {
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

func getScaInBinaryMarkdownMsg(commandType utils.CommandType, target *results.ScanTarget, result *sarif.Result) string {
	return sarifutils.GetResultMsgText(result) + getBaseBinaryDescriptionMarkdown(commandType, target, utils.ScaScan, result)
}

func getBaseBinaryDescriptionMarkdown(commandType utils.CommandType, target *results.ScanTarget, subScanType utils.SubScanType, result *sarif.Result) (content string) {
	// If in github action, add the workflow name and run number
	if workflowLocation := getWorkflowFileLocationIfExists(); workflowLocation != "" {
		content += fmt.Sprintf("\nGithub Actions Workflow: %s", workflowLocation)
	}
	if os.Getenv(utils.CurrentGithubWorkflowRunNumberEnvVar) != "" {
		content += fmt.Sprintf("\nRun: %s", os.Getenv(utils.CurrentGithubWorkflowRunNumberEnvVar))
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

func getDockerImageTag(commandType utils.CommandType, target *results.ScanTarget) string {
	if commandType != utils.DockerImage || target == nil {
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
		if layer, algorithm := sarifutils.GetDockerLayer(location); layer != "" {
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
	if tokenValidation := sarifutils.GetResultPropertyTokenValidation(result); tokenValidation != "" {
		content += fmt.Sprintf("\nToken Validation %s", tokenValidation)
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
