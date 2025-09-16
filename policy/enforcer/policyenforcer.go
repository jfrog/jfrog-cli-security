package enforcer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
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
	err = artifact.WaitForArtifactScanCompletion(xrayManager, p.rtRepository, p.artifactPath, artifact.Steps(artifact.XrayScanStepViolations))
	if err != nil {
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
		if violation.SastDetails != nil {
			convertedViolations.Sast = append(convertedViolations.Sast, convertToSastViolation(violation))
		} else if violation.ExposureDetails != nil {
			if strings.HasPrefix(violation.ExposureDetails.Id, "SEC") {
				convertedViolations.Secrets = append(convertedViolations.Secrets, convertToSecretViolation(violation))
			} else if strings.HasPrefix(violation.ExposureDetails.Id, "IAC") {
				convertedViolations.Iac = append(convertedViolations.Iac, convertToIacViolation(violation))
			}
		} else {
			// SCA as default
			switch violation.Type {
			case xrayUtils.SecurityViolation:
				convertedViolations.Sca = append(convertedViolations.Sca, convertToCveViolation(violation))
			case xrayUtils.LicenseViolation:
				convertedViolations.License = append(convertedViolations.License, convertToLicenseViolation(violation))
			case xrayUtils.OperationalRiskViolation:
				convertedViolations.OpRisk = append(convertedViolations.OpRisk, convertToOpRiskViolation(violation))
			default:
				err = errors.Join(err, fmt.Errorf("unknown violation type %s for violation id %s", violation.Type, violation.Id))
			}
		}
	}
	return
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

func convertToScaViolations(violation services.XrayViolation) []violationutils.ScaViolation {
	return []violationutils.ScaViolation{
		{
			Violation: convertToBasicViolation(violation),
		},
	}
}

func convertToScaViolation(violation services.XrayViolation) violationutils.ScaViolation {
	return violationutils.ScaViolation{
		Violation: convertToBasicViolation(violation),
		// ImpactedComponent: affectedComponent,
		// DirectComponents:  directComponents,
		// ImpactPaths:       impactPaths,
	}
}

func convertToCveViolation(violation services.XrayViolation) violationutils.CveViolation {
	cveViolation := violationutils.CveViolation{
		ScaViolation: convertToScaViolation(violation),
		// FixedVersions: cdxutils.ConvertToAffectedVersions(affectedComponent, violation.FixVersions),
		JfrogResearchInformation: results.ConvertJfrogResearchInformation(violation.JfrogResearchInformation),
	}
	return cveViolation
}

func convertToLicenseViolation(violation services.XrayViolation) violationutils.LicenseViolation {
	licenseViolation := violationutils.LicenseViolation{
		ScaViolation: convertToScaViolation(violation),
	}
	return licenseViolation
}

func convertToOpRiskViolation(violation services.XrayViolation) violationutils.OperationalRiskViolation {
	opRiskViolation := violationutils.OperationalRiskViolation{
		ScaViolation: convertToScaViolation(violation),
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
	return opRiskViolation
}

func convertToSecretViolation(violation services.XrayViolation) violationutils.JasViolation {
	secretViolation := violationutils.JasViolation{
		Violation: convertToBasicViolation(violation),
	}
	return secretViolation
}

func convertToIacViolation(violation services.XrayViolation) violationutils.JasViolation {
	iacViolation := violationutils.JasViolation{
		Violation: convertToBasicViolation(violation),
	}
	return iacViolation
}

func convertToSastViolation(violation services.XrayViolation) violationutils.JasViolation {
	sastViolation := violationutils.JasViolation{
		Violation: convertToBasicViolation(violation),
	}
	return sastViolation
}
