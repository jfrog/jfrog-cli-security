package enforcer

import (
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
	projectKey    string

	rtRepository string
	artifactPath string
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

func WithParams(repo, path string) policy.PolicyHandlerOption {
	return func(generator policy.PolicyHandler) {
		if p, ok := generator.(*PolicyEnforcerViolationGenerator); ok {
			p.rtRepository = repo
			p.artifactPath = path
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
	generatedViolations, err := xrayManager.GetViolations(params)
	if err != nil {
		return
	}
	if generatedViolations.Total == 0 {
		log.Debug("Xray scan completed with no violations")
	} else {
		log.Debug(fmt.Sprintf("Xray scans completed with %d violations", generatedViolations.Total))
	}
	return convertToViolations(cmdResults, generatedViolations.Violations)
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
			convertedViolations.Sast = append(convertedViolations.Sast, convertToJasViolations(cmdResults, jasutils.Sast, violation)...)
		case utils.SecretsScan:
			convertedViolations.Secrets = append(convertedViolations.Secrets, convertToJasViolations(cmdResults, jasutils.Secrets, violation)...)
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

func convertToScaViolation(cmdResults *results.SecurityCommandResults, impactedComponentXrayId string, violation services.XrayViolation) (*cyclonedx.Component, violationutils.ScaViolation) {
	affectedComponent, directComponents, impactPaths := locateBomComponentInfo(cmdResults, impactedComponentXrayId, violation)
	if affectedComponent == nil {
		return nil, violationutils.ScaViolation{}
	}
	return affectedComponent, violationutils.ScaViolation{
		Violation:         convertToBasicViolation(violation),
		ImpactedComponent: *affectedComponent,
		DirectComponents:  directComponents,
		ImpactPaths:       impactPaths,
	}
}

func locateBomComponentInfo(cmdResults *results.SecurityCommandResults, impactedComponentXrayId string, violation services.XrayViolation) (impactedComponent *cyclonedx.Component, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) {
	for _, target := range cmdResults.Targets {
		if target.ScaResults == nil || target.ScaResults.Sbom == nil || target.ScaResults.Sbom.Components == nil {
			continue
		}
		ref := techutils.XrayComponentIdToCdxComponentRef(impactedComponentXrayId)
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
		log.Debug(fmt.Sprintf("Could not locate component with Xray ID %s in the scan results for violation ID %s", impactedComponentXrayId, violation.Id))
	}
	return
}

func locateBomVulnerabilityInfo(cmdResults *results.SecurityCommandResults, issueId string, impactedComponent cyclonedx.Component) (relevantVulnerability *cyclonedx.Vulnerability, contextualAnalysis *formats.Applicability) {
	for _, target := range cmdResults.Targets {
		if target.ScaResults == nil || target.ScaResults.Sbom == nil {
			continue
		}
		var applicableRuns []*sarif.Run
		if cmdResults.EntitledForJas && target.JasResults != nil {
			applicableRuns = results.ScanResultsToRuns(target.JasResults.ApplicabilityScanResults)
		}
		if err := results.ForEachScaBomVulnerability(target.ScanTarget, target.ScaResults.Sbom, cmdResults.EntitledForJas, applicableRuns,
			func(vulnerability cyclonedx.Vulnerability, component cyclonedx.Component, fixedVersion *[]cyclonedx.AffectedVersions, applicability *formats.Applicability, severity severityutils.Severity) error {
				if vulnerability.ID == issueId && impactedComponent.BOMRef == component.BOMRef {
					// Found the relevant component in a vulnerability
					relevantVulnerability = &vulnerability
					contextualAnalysis = applicability
				}
				return nil
			},
		); err != nil {
			log.Verbose(fmt.Sprintf("Failed to search for vulnerability %s in the scan results: %s", issueId, err.Error()))
		}
	}
	if relevantVulnerability == nil {
		log.Debug(fmt.Sprintf("Could not locate vulnerability with ID %s in the scan results", issueId))
	}
	return
}

func convertToJasViolations(cmdResults *results.SecurityCommandResults, jasType jasutils.JasScanType, violation services.XrayViolation) (jasViolations []violationutils.JasViolation) {
	matches := locateJasVulnerabilityInfo(cmdResults, jasType, violation)
	for _, match := range matches {
		JasViolation := violationutils.JasViolation{
			Violation: convertToBasicViolation(violation),
			Rule:      match.rule,
			Result:    match.result,
			Location:  match.location,
		}
		jasViolations = append(jasViolations, JasViolation)
	}
	return
}

type matchedJsaVulnerability struct {
	rule     *sarif.ReportingDescriptor
	result   *sarif.Result
	location *sarif.Location
}

func locateJasVulnerabilityInfo(cmdResults *results.SecurityCommandResults, jasType jasutils.JasScanType, violation services.XrayViolation) (matches []matchedJsaVulnerability) {
	id := getJasVulnerabilityId(violation, jasType)
	if id == "" {
		log.Debug(fmt.Sprintf("Skipping Jas violation with empty ID for issue ID %s violation ID %s", violation.IssueId, violation.Id))
		return
	}
	for _, target := range cmdResults.Targets {
		if target.JasResults == nil {
			log.Debug(fmt.Sprintf("Skipping %s violation search for target %s with no Jas results", jasType, target.ScanTarget))
			continue
		}
		if err := results.ForEachJasIssue(target.JasResults.GetVulnerabilitiesResults(jasType), cmdResults.EntitledForJas,
			func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) error {
				if sarifutils.GetRuleId(rule) == id && slices.Contains(violation.PhysicalPaths, sarifutils.GetLocationFileName(location)) {
					// Found a relevant issue (JAS Violations only provide abbreviation and file name, no region so we match only by those)
					matches = append(matches, matchedJsaVulnerability{
						rule:     rule,
						result:   result,
						location: location,
					})
				}
				return nil
			},
		); err != nil {
			log.Verbose(fmt.Sprintf("Failed to search for %s issue %s in the scan results: %s", jasType, violation.IssueId, err.Error()))
		}
	}
	return
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

func convertToBasicViolation(violation services.XrayViolation) violationutils.Violation {
	cmdViolation := violationutils.Violation{
		ViolationId: violation.Id,
		Watch:       violation.Watch,
		Severity:    severityutils.XraySeverityToSeverity(violation.Severity),
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
			log.Verbose(fmt.Sprintf("Skipping CVE violation with empty infected component ID for violation ID %s", violation.Id))
			continue
		}
		affectedComponent, scaViolation := convertToScaViolation(cmdResults, infectedComponentXrayId, violation)
		if affectedComponent == nil {
			log.Verbose(fmt.Sprintf("Skipping CVE violation with no located affected component for violation ID %s and infected component ID %s", violation.Id, infectedComponentXrayId))
			continue
		}
		for _, cve := range violation.Cves {
			if cve.Id == "" {
				log.Verbose(fmt.Sprintf("Skipping CVE violation with empty CVE ID for violation ID %s", violation.Id))
				continue
			}
			vulnerability, contextualAnalysis := locateBomVulnerabilityInfo(cmdResults, cve.Id, *affectedComponent)
			if vulnerability == nil {
				log.Verbose(fmt.Sprintf("Skipping CVE violation with no located vulnerability for CVE ID %s, violation ID %s and infected component ID %s", cve.Id, violation.Id, infectedComponentXrayId))
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
			OperationalRiskViolationReadableData: policy.GetOperationalRiskViolationReadableData(
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
