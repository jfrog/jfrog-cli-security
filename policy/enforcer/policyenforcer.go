package enforcer

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/artifact"
	"github.com/jfrog/jfrog-client-go/utils/log"
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
	log.Debug("Waiting for Xray scan to complete...")
	err = artifact.WaitForArtifactScanCompletion(xrayManager, p.rtRepository, p.artifactPath, artifact.Steps(artifact.XrayScanStepViolations))
	if err != nil {
		return
	}
	// Get with API
	log.Debug("Fetching violations from Xray...")

	return
}
