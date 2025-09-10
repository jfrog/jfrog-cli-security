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

func (p *PolicyEnforcerViolationGenerator) GenerateViolations(cmdResults *results.SecurityCommandResults) (convertedViolations []violationutils.Violation, err error) {
	xrayManager, err := xray.CreateXrayServiceManager(p.serverDetails, xray.WithScopedProjectKey(p.projectKey))
	if err != nil {
		return
	}
	convertedViolations = []violationutils.Violation{}
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
	return convertToLocalViolations(generatedViolations.Violations)
}

func convertToLocalViolations(generatedViolations []services.XrayViolation) (convertedViolations []violationutils.Violation, err error) {
	convertedViolations = make([]violationutils.Violation, 0, len(generatedViolations))
	for _, v := range generatedViolations {
		violationType, e := getViolationType(v)
		if e != nil {
			err = errors.Join(err, fmt.Errorf("couldn't determine violation type for violation id %s: %w", v.Id, e))
			continue
		}
		convertedViolations = append(convertedViolations, violationutils.Violation{
			Type:        violationType,
			IssueId:     v.IssueId,
			ViolationId: v.Id,
			Severity:    severityutils.XraySeverityToSeverity(v.Severity),
		})
	}
	return
}

func getViolationType(xrayViolation services.XrayViolation) (violationType violationutils.ViolationType, err error) {
	if xrayViolation.SastDetails != nil {
		return violationutils.SastViolationType, nil
	}
	if xrayViolation.ExposureDetails != nil {
		if strings.HasPrefix(xrayViolation.ExposureDetails.Id, "SEC") {
			return violationutils.SecretsViolationType, nil
		} else if strings.HasPrefix(xrayViolation.ExposureDetails.Id, "IAC") {
			return violationutils.IacViolationType, nil
		}
	}
	// SCA as default
	return violationutils.ScaViolationType, nil
}
