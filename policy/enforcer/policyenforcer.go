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
		return ""
	}
	return utils.ScaScan
}

func convertToScaViolation(cmdResults *results.SecurityCommandResults, impactedComponentXrayId string, violation services.XrayViolation) (affectedComponent *cyclonedx.Component, scaViolation violationutils.ScaViolation) {
	scaViolation = violationutils.ScaViolation{
		Violation: convertToBasicViolation(getScaViolationType(violation), violation),
	}
	affectedComponent, scaViolation.DirectComponents, scaViolation.ImpactPaths = locateBomComponentInfo(cmdResults, impactedComponentXrayId, violation)
	if affectedComponent == nil {
		return
	}
	scaViolation.ImpactedComponent = *affectedComponent
	return
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
		for _, component := range *target.ScaResults.Sbom.Components {
			if strings.HasPrefix(component.BOMRef, ref) {
				// Found the relevant component
				impactedComponent = &component
				dependencies := []cyclonedx.Dependency{}
				if target.ScaResults.Sbom.Dependencies != nil {
					dependencies = *target.ScaResults.Sbom.Dependencies
				}
				directComponents = results.GetDirectDependenciesAsComponentRows(component, *target.ScaResults.Sbom.Components, dependencies)
				impactPaths = results.BuildImpactPath(component, *target.ScaResults.Sbom.Components, dependencies...)
				break
			}
		}
	}
	if impactedComponent == nil {
		log.Debug(fmt.Sprintf("Could not locate component %s in the scan results for (%s) violation ID %s", impactedComponentXrayId, violation.Type, violation.Id))
	}
	return
}

func locateBomVulnerabilityInfo(cmdResults *results.SecurityCommandResults, issueId string, impactedComponent cyclonedx.Component) (relevantVulnerability *cyclonedx.Vulnerability, contextualAnalysis *formats.Applicability) {
	for _, target := range cmdResults.Targets {
		if target.ScaResults == nil || target.ScaResults.Sbom == nil || target.ScaResults.Sbom.Vulnerabilities == nil {
			continue
		}
		var applicabilityRuns []*sarif.Run
		if cmdResults.EntitledForJas && target.JasResults != nil {
			applicabilityRuns = results.ScanResultsToRuns(target.JasResults.ApplicabilityScanResults)
		}
		for _, vulnerability := range *target.ScaResults.Sbom.Vulnerabilities {
			if vulnerability.ID != issueId || vulnerability.Affects == nil || len(*vulnerability.Affects) == 0 {
				continue
			}
			for _, affected := range *vulnerability.Affects {
				if affected.Ref == impactedComponent.BOMRef {
					// Found the relevant component in a vulnerability
					relevantVulnerability = &vulnerability
					contextualAnalysis = results.GetCveApplicabilityField(vulnerability.BOMRef, applicabilityRuns)
					break
				}
			}
			if relevantVulnerability != nil {
				// Found the relevant vulnerability, no need to continue searching
				break
			}
		}
	}
	if relevantVulnerability == nil {
		log.Debug(fmt.Sprintf("Could not locate vulnerability with ID %s in the scan results", issueId))
	}
	return
}

func convertToJasViolation(cmdResults *results.SecurityCommandResults, jasType jasutils.JasScanType, violation services.XrayViolation) (jasViolations *violationutils.JasViolation) {
	match := locateJasVulnerabilityInfo(cmdResults, jasType, violation)
	if match.rule == nil || match.result == nil || match.location == nil {
		log.Warn(fmt.Sprintf("Could not locate all required information for %s violation ID %s", jasType, violation.Id))
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
		if err := results.ForEachJasIssue(target.JasResults.GetVulnerabilitiesResults(jasType), cmdResults.EntitledForJas,
			func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) error {
				if !found && sarifutils.GetRuleId(rule) == id && isLocationMatchingJasViolation(location, run.Invocations, violation) {
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

func isLocationMatchingJasViolation(location *sarif.Location, invocations []*sarif.Invocation, violation services.XrayViolation) bool {
	// Convert location to relative path
	if relative := sarifutils.GetRelativeLocationFileName(location, invocations); !slices.Contains(violation.InfectedFilePaths, relative) {
		return false
	}
	// TODO: Improve matching logic when more data is available in Xray violations (Line + Column)
	return true
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
		return violation.ExposureDetails.Abbreviation
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
	for _, infectedComponentXrayId := range violation.InfectedComponentIds {
		if infectedComponentXrayId == "" {
			log.Warn(fmt.Sprintf("Skipping CVE violation with empty infected component ID for violation ID %s", violation.Id))
			continue
		}
		affectedComponent, scaViolation := convertToScaViolation(cmdResults, infectedComponentXrayId, violation)
		if affectedComponent == nil {
			log.Warn(fmt.Sprintf("Skipping CVE violation with no located affected component for violation ID %s and infected component ID %s", violation.Id, infectedComponentXrayId))
			continue
		}
		for _, cve := range violation.Cves {
			if cve.Id == "" {
				log.Warn(fmt.Sprintf("Skipping CVE violation with empty CVE ID for violation ID %s", violation.Id))
				continue
			}
			vulnerability, contextualAnalysis := locateBomVulnerabilityInfo(cmdResults, cve.Id, *affectedComponent)
			if vulnerability == nil {
				log.Warn(fmt.Sprintf("Skipping CVE violation with no located vulnerability for CVE ID %s, violation ID %s and infected component ID %s", cve.Id, violation.Id, infectedComponentXrayId))
				continue
			}
			cveViolation := violationutils.CveViolation{
				ScaViolation:             scaViolation,
				CveVulnerability:         *vulnerability,
				ContextualAnalysis:       contextualAnalysis,
				FixedVersions:            cdxutils.ConvertToAffectedVersions(*affectedComponent, violation.FixVersions),
				JfrogResearchInformation: results.ConvertJfrogResearchInformation(violation.JfrogResearchInformation),
			}
			cveViolations = append(cveViolations, cveViolation)
		}
	}
	return cveViolations
}

func convertToLicenseViolations(cmdResults *results.SecurityCommandResults, violation services.XrayViolation) (licenseViolations []violationutils.LicenseViolation) {
	for _, infectedComponentXrayId := range violation.InfectedComponentIds {
		if infectedComponentXrayId == "" {
			log.Verbose(fmt.Sprintf("Skipping license violation with empty infected component ID for violation ID %s", violation.Id))
			continue
		}
		_, scaViolation := convertToScaViolation(cmdResults, infectedComponentXrayId, violation)
		licenseViolation := violationutils.LicenseViolation{
			ScaViolation: scaViolation,
			LicenseKey:   violation.IssueId,
			LicenseName:  violation.Description,
		}
		licenseViolations = append(licenseViolations, licenseViolation)
	}
	return licenseViolations
}

func convertToOpRiskViolations(cmdResults *results.SecurityCommandResults, violation services.XrayViolation) (opRiskViolations []violationutils.OperationalRiskViolation) {
	for _, infectedComponentXrayId := range violation.InfectedComponentIds {
		if infectedComponentXrayId == "" {
			log.Verbose(fmt.Sprintf("Skipping operational risk violation with empty infected component ID for violation ID %s", violation.Id))
			continue
		}
		_, scaViolation := convertToScaViolation(cmdResults, infectedComponentXrayId, violation)
		opRiskViolation := violationutils.OperationalRiskViolation{
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
		opRiskViolations = append(opRiskViolations, opRiskViolation)
	}

	return opRiskViolations
}
