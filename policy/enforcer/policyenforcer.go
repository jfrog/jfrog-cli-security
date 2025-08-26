package enforcer

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type PolicyEnforcerViolationGenerator struct {
	serverDetails *config.ServerDetails
	rtRepository  string
	artifactPath  string
}

func NewPolicyEnforcerViolationGenerator() *PolicyEnforcerViolationGenerator {
	return &PolicyEnforcerViolationGenerator{}
}

func WithParams(serverDetails *config.ServerDetails, repo, path string) policy.ViolationGeneratorOption {
	return func(generator policy.ViolationGenerator) {
		if p, ok := generator.(*PolicyEnforcerViolationGenerator); ok {
			p.serverDetails = serverDetails
			p.rtRepository = repo
			p.artifactPath = path
		}
	}
}

func (p *PolicyEnforcerViolationGenerator) WithOptions(options ...policy.ViolationGeneratorOption) policy.ViolationGenerator {
	for _, option := range options {
		option(p)
	}
	return p
}

func (p *PolicyEnforcerViolationGenerator) GenerateViolations(cmdResults *results.SecurityCommandResults) (convertedViolations []policy.Violation, err error) {
	convertedViolations = []policy.Violation{}
	// Get with API
	return
}
