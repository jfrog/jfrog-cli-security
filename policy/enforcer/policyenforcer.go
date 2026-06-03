package enforcer

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/artifact"
)

type PolicyEnforcerViolationGenerator struct {
	serverDetails *config.ServerDetails
	// Results Artifact
	artifactPath string
	rtRepository string
	// Filters
	projectKey string
	watches    []string
	// Run options
	resultsOutputDir string
}

func NewPolicyEnforcerViolationGenerator() *PolicyEnforcerViolationGenerator {
	return &PolicyEnforcerViolationGenerator{}
}

func WithServerDetails(serverDetails *config.ServerDetails) policy.PolicyHandlerOption {
	return func(generator policy.PolicyHandler) {
		if p, ok := generator.(*PolicyEnforcerViolationGenerator); ok {
			p.serverDetails = serverDetails
		}
	}
}

func WithProjectKey(projectKey string) policy.PolicyHandlerOption {
	return func(generator policy.PolicyHandler) {
		if p, ok := generator.(*PolicyEnforcerViolationGenerator); ok {
			p.projectKey = projectKey
		}
	}
}

func WithResultsOutputDir(resultsOutputDir string) policy.PolicyHandlerOption {
	return func(generator policy.PolicyHandler) {
		if p, ok := generator.(*PolicyEnforcerViolationGenerator); ok {
			p.resultsOutputDir = resultsOutputDir
		}
	}
}

func WithArtifactParams(repo, path string) policy.PolicyHandlerOption {
	return func(generator policy.PolicyHandler) {
		if p, ok := generator.(*PolicyEnforcerViolationGenerator); ok {
			p.rtRepository = repo
			p.artifactPath = path
		}
	}
}

func WithWatches(watches []string) policy.PolicyHandlerOption {
	return func(generator policy.PolicyHandler) {
		if p, ok := generator.(*PolicyEnforcerViolationGenerator); ok {
			p.watches = watches
		}
	}
}

func (p *PolicyEnforcerViolationGenerator) WithOptions(options ...policy.PolicyHandlerOption) policy.PolicyHandler {
	for _, option := range options {
		option(p)
	}
	return p
}

func (p *PolicyEnforcerViolationGenerator) GenerateViolations(cmdResults *results.SecurityCommandResults) (convertedViolations violationutils.Violations, err error) {
	if p.rtRepository == "" || p.artifactPath == "" {
		log.Debug("Repository or artifact path not provided, skipping violation generation from Xray")
		return
	}
	xrayManager, err := xray.CreateXrayServiceManager(p.serverDetails, xray.WithScopedProjectKey(p.projectKey))
	if err != nil {
		return
	}
	convertedViolations = violationutils.Violations{}
	log.Debug("Waiting for Xray scans to complete...")
	startedTimeStamp := time.Now()
	if err = artifact.WaitForArtifactScanStatus(xrayManager, p.rtRepository, p.artifactPath, artifact.Steps(artifact.XrayScanStepViolations)); err != nil {
		return
	}
	log.Debug(fmt.Sprintf("Xray scan completed in %s seconds", time.Since(startedTimeStamp).String()))
	// Get with API
	log.Info("Fetching violations from Xray...")
	params := xrayUtils.NewViolationsRequest().IncludeDetails(true).FilterByArtifacts(xrayUtils.ArtifactResourceFilter{Repository: p.rtRepository, Path: p.artifactPath})
	if len(p.watches) > 0 {
		if len(p.watches) > 1 {
			return convertedViolations, errors.New("the policy enforcer violation generator supports a single watch")
		}
		params.FilterByWatchName(p.watches[0])
	}
	generatedViolations, err := xrayManager.GetViolations(params)
	if err != nil {
		return
	}
	if generatedViolations.Total == 0 {
		log.Debug("Xray scan completed with no violations")
	} else {
		log.Debug(fmt.Sprintf("Xray scans completed with %d violations", generatedViolations.Total))
	}
	if err = dumpViolationsResponseToFileIfNeeded(generatedViolations, p.resultsOutputDir); err != nil {
		return
	}
	return convertToViolations(cmdResults, generatedViolations.Violations)
}

func dumpViolationsResponseToFileIfNeeded(generatedViolations *services.ViolationsResponse, resultsOutputDir string) (err error) {
	if resultsOutputDir == "" {
		return
	}
	fileContent, err := json.Marshal(generatedViolations)
	if err != nil {
		return fmt.Errorf("failed to write fetched violations to file: %s", err.Error())
	}
	return utils.DumpJsonContentToFile(fileContent, resultsOutputDir, "violations", -1)
}

func convertToViolations(cmdResults *results.SecurityCommandResults, generatedViolations []services.XrayViolation) (convertedViolations violationutils.Violations, err error) {
	convertedViolations = violationutils.Violations{}
	for _, violation := range generatedViolations {
		switch getViolationType(violation) {
		case utils.ScaScan:
			switch violation.Type {
			case xrayUtils.SecurityViolation:
				convertedViolations.Sca = append(convertedViolations.Sca, convertToCveViolations(cmdResults, violation)...)
			case xrayUtils.LicenseViolation:
				convertedViolations.License = append(convertedViolations.License, convertToLicenseViolations(cmdResults, violation)...)
			case xrayUtils.OperationalRiskViolation:
				convertedViolations.OpRisk = append(convertedViolations.OpRisk, convertToOpRiskViolations(cmdResults, violation)...)
			default:
				err = errors.Join(err, fmt.Errorf("unknown violation type %s for violation id %s", violation.Type, violation.Id))
			}
		case utils.SastScan:
			if sastViolation := convertToJasViolation(cmdResults, jasutils.Sast, violation); sastViolation != nil {
				convertedViolations.Sast = append(convertedViolations.Sast, *sastViolation)
			}
		case utils.SecretsScan:
			if secretsViolation := convertToJasViolation(cmdResults, jasutils.Secrets, violation); secretsViolation != nil {
				convertedViolations.Secrets = append(convertedViolations.Secrets, *secretsViolation)
			}
		default:
			log.Warn(fmt.Sprintf("Skipping violation with unknown scan type for violation ID %s", violation.Id))
		}
	}
	return
}

func getViolationType(violation services.XrayViolation) utils.SubScanType {
	if violation.SastDetails != nil {
		return utils.SastScan
	}
	if violation.ExposureDetails != nil {
		if strings.HasPrefix(violation.ExposureDetails.Id, "EXP") {
			return utils.SecretsScan
		}
		// TODO: add IaC support when Xray adds IaC details to violations
		return ""
	}
	return utils.ScaScan
}

// bomResolvedComponent holds the result of a single locateBomComponentInfo call for one Xray infected-component ID.
type bomResolvedComponent struct {
	xrayId           string
	impacted         *cyclonedx.Component
	directComponents []formats.ComponentRow
	impactPaths      [][]formats.ComponentRow
}

// resolveInfectedComponents maps violation.InfectedComponentIds to BOM components in one pass.
// unresolvedCount is the number of non-empty IDs that did not resolve in the BOM.
func resolveInfectedComponents(cmdResults *results.SecurityCommandResults, violation services.XrayViolation) (resolved []bomResolvedComponent, unresolvedCount int) {
	for _, infectedComponentXrayId := range violation.InfectedComponentIds {
		if infectedComponentXrayId == "" {
			log.Warn(fmt.Sprintf("Skipping violation with empty infected component ID for violation ID %s", violation.Id))
			continue
		}
		impacted, directComponents, impactPaths := locateBomComponentInfo(cmdResults, infectedComponentXrayId, violation)
		if impacted == nil {
			log.Warn(fmt.Sprintf("Skipping violation with no located affected component for violation ID %s and infected component ID %s", violation.Id, infectedComponentXrayId))
			unresolvedCount++
			continue
		}
		resolved = append(resolved, bomResolvedComponent{
			xrayId:           infectedComponentXrayId,
			impacted:         impacted,
			directComponents: directComponents,
			impactPaths:      impactPaths,
		})
	}
	return resolved, unresolvedCount
}

func logComponentLessFallback(violation services.XrayViolation, unresolvedCount int) {
	if len(violation.InfectedComponentIds) > 0 && unresolvedCount > 0 {
		log.Warn(fmt.Sprintf(
			"Falling back to component-less violation for violation ID %s: none of %d infected component ID(s) resolved in BOM",
			violation.Id, unresolvedCount,
		))
	}
}

func convertToScaViolation(cmdResults *results.SecurityCommandResults, impactedComponentXrayId string, violation services.XrayViolation, preResolved *bomResolvedComponent) (affectedComponent *cyclonedx.Component, scaViolation violationutils.ScaViolation) {
	scaViolation = violationutils.ScaViolation{
		Violation: convertToBasicViolation(getScaViolationType(violation), violation),
	}
	if preResolved != nil && preResolved.xrayId == impactedComponentXrayId {
		scaViolation.ImpactedComponent = preResolved.impacted
		scaViolation.DirectComponents = preResolved.directComponents
		scaViolation.ImpactPaths = preResolved.impactPaths
		return preResolved.impacted, scaViolation
	}
	if impactedComponentXrayId == "" {
		return nil, scaViolation
	}
	scaViolation.ImpactedComponent, scaViolation.DirectComponents, scaViolation.ImpactPaths = locateBomComponentInfo(cmdResults, impactedComponentXrayId, violation)
	return scaViolation.ImpactedComponent, scaViolation
}

func getJasViolationType(jasType jasutils.JasScanType) violationutils.ViolationIssueType {
	switch jasType {
	case jasutils.Sast:
		return violationutils.SastViolationType
	case jasutils.Secrets:
		return violationutils.SecretsViolationType
	case jasutils.IaC:
		return violationutils.IacViolationType
	default:
		return ""
	}
}

func getScaViolationType(violation services.XrayViolation) violationutils.ViolationIssueType {
	switch violation.Type {
	case xrayUtils.SecurityViolation:
		return violationutils.CveViolationType
	case xrayUtils.LicenseViolation:
		return violationutils.LicenseViolationType
	case xrayUtils.OperationalRiskViolation:
		return violationutils.OperationalRiskType
	default:
		return ""
	}
}

func locateBomComponentInfo(cmdResults *results.SecurityCommandResults, impactedComponentXrayId string, violation services.XrayViolation) (impactedComponent *cyclonedx.Component, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) {
	ref := techutils.XrayComponentIdToCdxComponentRef(impactedComponentXrayId)
	for _, target := range cmdResults.Targets {
		if target.ScaResults == nil || target.ScaResults.Sbom == nil || target.ScaResults.Sbom.Components == nil {
			continue
		}
		bomIndex := cdxutils.NewBOMIndex(target.ScaResults.Sbom, true)
		for _, component := range *target.ScaResults.Sbom.Components {
			// XRAY-135509, CTLG-1290 Bug in Xray: the BOMRef is not always in the same case as the ref, so we need to check both
			if strings.HasPrefix(component.BOMRef, ref) || strings.EqualFold(component.BOMRef, ref) {
				// Found the relevant component
				impactedComponent = &component
				impactPaths = results.BuildImpactPath(component, bomIndex)
				directComponents = results.ExtractComponentDirectComponentsInBOM(bomIndex, component, impactPaths)
				break
			}
		}
	}
	if impactedComponent == nil {
		log.Debug(fmt.Sprintf("Could not locate component %s in the scan results for (%s) violation ID %s", impactedComponentXrayId, violation.Type, violation.Id))
	}
	return
}

// locateBomVulnerabilityInfo finds a CycloneDX vulnerability in scan results by issue/CVE id.
// When impactedComponent is nil, only vulnerabilities with empty Affects are matched.
// If the BOM lists Affects but Xray omits InfectedComponentIds, conversion still fails (returns nil).
func locateBomVulnerabilityInfo(cmdResults *results.SecurityCommandResults, issueId string, impactedComponent *cyclonedx.Component) (relevantVulnerability *cyclonedx.Vulnerability, contextualAnalysis *formats.Applicability) {
	for _, target := range cmdResults.Targets {
		if target.ScaResults == nil || target.ScaResults.Sbom == nil || target.ScaResults.Sbom.Vulnerabilities == nil {
			continue
		}
		for _, vulnerability := range *target.ScaResults.Sbom.Vulnerabilities {
			if vulnerability.ID != issueId {
				continue
			}
			if impactedComponent != nil && vulnerability.Affects != nil {
				for _, affected := range *vulnerability.Affects {
					if affected.Ref == impactedComponent.BOMRef {
						// Found the relevant component in a vulnerability
						relevantVulnerability = &vulnerability
						break
					}
				}
			} else if vulnerability.Affects == nil || len(*vulnerability.Affects) == 0 {
				// No impacted component, use the first vulnerability that matches the issue ID
				relevantVulnerability = &vulnerability
			}
			if relevantVulnerability != nil {
				// Found the relevant vulnerability, no need to continue searching
				contextualAnalysis = results.GetCveApplicabilityField(vulnerability.BOMRef, target.JasResults.GetApplicabilityScanResults())
				break
			}
		}
	}
	if relevantVulnerability == nil {
		log.Warn(fmt.Sprintf("Could not locate vulnerability with ID %s in the scan results", issueId))
	}
	return
}

func convertToJasViolation(cmdResults *results.SecurityCommandResults, jasType jasutils.JasScanType, violation services.XrayViolation) (jasViolations *violationutils.JasViolation) {
	match := locateJasVulnerabilityInfo(cmdResults, jasType, violation)
	if match.rule == nil || match.result == nil || match.location == nil {
		log.Debug(fmt.Sprintf("Could not locate all required information for %s violation ID %s (%s#%d)", jasType, violation.Id, strings.Join(violation.InfectedFilePaths, ","), violation.LineNumber))
		return nil
	}
	return &violationutils.JasViolation{
		Violation: convertToBasicViolation(getJasViolationType(jasType), violation),
		Rule:      match.rule,
		Result:    match.result,
		Location:  match.location,
	}
}

type matchedJsaVulnerability struct {
	rule     *sarif.ReportingDescriptor
	result   *sarif.Result
	location *sarif.Location
}

func locateJasVulnerabilityInfo(cmdResults *results.SecurityCommandResults, jasType jasutils.JasScanType, violation services.XrayViolation) (match matchedJsaVulnerability) {
	id := getJasVulnerabilityId(violation, jasType)
	if id == "" {
		log.Debug(fmt.Sprintf("Skipping Jas violation with empty ID for issue ID %s violation ID %s", violation.IssueId, violation.Id))
		return
	}
	found := false
	for _, target := range cmdResults.Targets {
		if target.JasResults == nil {
			log.Debug(fmt.Sprintf("Skipping %s violation search for target %s with no Jas results", jasType, target.ScanTarget))
			continue
		}
		if err := results.ForEachJasIssue(target.JasResults.GetVulnerabilitiesResults(jasType), cmdResults.Entitlements.Jas,
			func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) error {
				if !found && isMatchingJasViolation(id, jasType, rule, location, run.Invocations, violation) {
					// Found a relevant issue (JAS Violations only provide abbreviation and file name, no region so we match only by those)
					match = matchedJsaVulnerability{
						rule:     rule,
						result:   result,
						location: location,
					}
					found = true
				}
				return nil
			},
		); err != nil {
			log.Verbose(fmt.Sprintf("Failed to search for %s issue %s in the scan results: %s", jasType, violation.IssueId, err.Error()))
		}
	}
	return
}

func isMatchingJasViolation(id string, jasType jasutils.JasScanType, rule *sarif.ReportingDescriptor, location *sarif.Location, invocations []*sarif.Invocation, violation services.XrayViolation) bool {
	if jasType == jasutils.Secrets {
		// Secrets Jas should relay on Scanner ID to match
		if id != sarifutils.GetSecretScannerRuleId(rule) {
			return false
		}
	} else if sarifutils.GetRuleId(rule) != id {
		// Other Jas should relay on rule ID to match
		return false
	}
	return isLocationMatchingJasViolation(location, invocations, violation)
}

func isLocationMatchingJasViolation(location *sarif.Location, invocations []*sarif.Invocation, violation services.XrayViolation) bool {
	// Convert location to relative path
	if relative := sarifutils.GetRelativeLocationFileName(location, invocations); !slices.Contains(violation.InfectedFilePaths, relative) {
		return false
	}
	return sarifutils.GetLocationStartLine(location) == violation.LineNumber
}

func getJasVulnerabilityId(violation services.XrayViolation, jasType jasutils.JasScanType) string {
	switch jasType {
	case jasutils.Sast:
		if violation.SastDetails == nil {
			log.Debug(fmt.Sprintf("Skipping SAST violation with mismatched or missing SAST details for ID %s", violation.IssueId))
			return ""
		}
		return violation.SastDetails.Abbreviation
	case jasutils.Secrets:
		if violation.ExposureDetails == nil || !strings.HasPrefix(violation.ExposureDetails.Id, "EXP") {
			log.Debug(fmt.Sprintf("Skipping Secrets violation with mismatched or missing Exposure details for ID %s", violation.IssueId))
			return ""
		}
		// ID format: 'EXP-<rule_id>-<unique_id>' --> return 'EXP-<rule_id>'
		split := strings.Split(violation.ExposureDetails.Id, "-")
		if len(split) < 2 {
			log.Warn(fmt.Sprintf("Skipping Secrets violation with invalid ID format for ID %s", violation.IssueId))
			return ""
		}
		return fmt.Sprintf("EXP-%s", split[1])
	}
	return ""
}

func convertToBasicViolation(violationType violationutils.ViolationIssueType, violation services.XrayViolation) violationutils.Violation {
	cmdViolation := violationutils.Violation{
		ViolationId:   violation.Id,
		ViolationType: violationType,
		Watch:         violation.Watch,
		Severity:      severityutils.XraySeverityToSeverity(violation.Severity),
	}
	for _, policy := range violation.Policies {
		cmdViolation.Policies = append(cmdViolation.Policies, violationutils.Policy{
			PolicyName:        policy.PolicyName,
			Rule:              policy.Rule,
			FailBuild:         policy.FailBuild,
			FailPullRequest:   policy.FailPullRequest,
			SkipNotApplicable: policy.SkipNotApplicable,
		})
	}
	return cmdViolation
}

func convertToCveViolations(cmdResults *results.SecurityCommandResults, violation services.XrayViolation) (cveViolations []violationutils.CveViolation) {
	resolved, unresolvedCount := resolveInfectedComponents(cmdResults, violation)
	for _, cve := range violation.Cves {
		if cve.Id == "" {
			log.Warn(fmt.Sprintf("Skipping CVE violation with empty CVE ID for violation ID %s", violation.Id))
			continue
		}
		if len(resolved) == 0 {
			logComponentLessFallback(violation, unresolvedCount)
			cveViolation := createCveViolation(cmdResults, "", cve.Id, violation, nil)
			if cveViolation == nil {
				log.Warn(fmt.Sprintf("CVE (%s) violation with no located affected components for violation ID %s", cve.Id, violation.Id))
				continue
			}
			cveViolations = append(cveViolations, *cveViolation)
			continue
		}
		for i := range resolved {
			cveViolation := createCveViolation(cmdResults, resolved[i].xrayId, cve.Id, violation, &resolved[i])
			if cveViolation == nil {
				log.Warn(fmt.Sprintf("CVE (%s) violation for component (%s) with no located affected components for violation ID %s", cve.Id, resolved[i].xrayId, violation.Id))
				continue
			}
			cveViolations = append(cveViolations, *cveViolation)
		}
	}
	return cveViolations
}

func createCveViolation(cmdResults *results.SecurityCommandResults, impactedComponentXrayId, cveId string, violation services.XrayViolation, preResolved *bomResolvedComponent) *violationutils.CveViolation {
	affectedComponent, scaViolation := convertToScaViolation(cmdResults, impactedComponentXrayId, violation, preResolved)
	vulnerability, contextualAnalysis := locateBomVulnerabilityInfo(cmdResults, cveId, affectedComponent)
	if vulnerability == nil {
		log.Warn(fmt.Sprintf("Skipping CVE violation with no located vulnerability for CVE ID %s, violation ID %s and infected component ID %s", cveId, violation.Id, impactedComponentXrayId))
		return nil
	}
	var fixedVersions *[]cyclonedx.AffectedVersions
	if affectedComponent != nil {
		fixedVersions = cdxutils.ConvertToAffectedVersions(*affectedComponent, violation.FixVersions)
	}
	cveViolation := violationutils.CveViolation{
		ScaViolation:             scaViolation,
		CveVulnerability:         *vulnerability,
		ContextualAnalysis:       contextualAnalysis,
		FixedVersions:            fixedVersions,
		JfrogResearchInformation: results.ConvertJfrogResearchInformation(violation.JfrogResearchInformation),
	}
	return &cveViolation
}

func convertToLicenseViolations(cmdResults *results.SecurityCommandResults, violation services.XrayViolation) (licenseViolations []violationutils.LicenseViolation) {
	if violation.IssueId == "" {
		log.Warn(fmt.Sprintf("Skipping license violation with empty issue ID for violation ID %s", violation.Id))
		return nil
	}
	resolved, unresolvedCount := resolveInfectedComponents(cmdResults, violation)
	if len(resolved) == 0 {
		logComponentLessFallback(violation, unresolvedCount)
		return append(licenseViolations, createLicenseViolation(cmdResults, "", violation, nil))
	}
	for i := range resolved {
		licenseViolations = append(licenseViolations, createLicenseViolation(cmdResults, resolved[i].xrayId, violation, &resolved[i]))
	}
	return licenseViolations
}

func createLicenseViolation(cmdResults *results.SecurityCommandResults, impactedComponentXrayId string, violation services.XrayViolation, preResolved *bomResolvedComponent) violationutils.LicenseViolation {
	_, scaViolation := convertToScaViolation(cmdResults, impactedComponentXrayId, violation, preResolved)
	return violationutils.LicenseViolation{
		ScaViolation: scaViolation,
		LicenseKey:   violation.IssueId,
		LicenseName:  violation.Description,
	}
}

func convertToOpRiskViolations(cmdResults *results.SecurityCommandResults, violation services.XrayViolation) (opRiskViolations []violationutils.OperationalRiskViolation) {
	resolved, unresolvedCount := resolveInfectedComponents(cmdResults, violation)
	if len(resolved) == 0 {
		logComponentLessFallback(violation, unresolvedCount)
		return append(opRiskViolations, createOpRiskViolation(cmdResults, "", violation, nil))
	}
	for i := range resolved {
		opRiskViolations = append(opRiskViolations, createOpRiskViolation(cmdResults, resolved[i].xrayId, violation, &resolved[i]))
	}
	return opRiskViolations
}

func createOpRiskViolation(cmdResults *results.SecurityCommandResults, impactedComponentXrayId string, violation services.XrayViolation, preResolved *bomResolvedComponent) violationutils.OperationalRiskViolation {
	_, scaViolation := convertToScaViolation(cmdResults, impactedComponentXrayId, violation, preResolved)
	return violationutils.OperationalRiskViolation{
		ScaViolation: scaViolation,
		OperationalRiskViolationReadableData: violationutils.GetOperationalRiskViolationReadableData(
			violation.OperationalRisk.RiskReason,
			violation.OperationalRisk.IsEol,
			violation.OperationalRisk.EolMessage,
			violation.OperationalRisk.Cadence,
			violation.OperationalRisk.Commits,
			violation.OperationalRisk.Committers,
			violation.OperationalRisk.LatestVersion,
			violation.OperationalRisk.NewerVersions,
		),
	}
}
