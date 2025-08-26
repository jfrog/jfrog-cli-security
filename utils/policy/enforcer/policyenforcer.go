package enforcer

import (
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type PolicyEnforcerViolationGenerator struct {
}

func NewPolicyEnforcerViolationGenerator() *PolicyEnforcerViolationGenerator {
	return &PolicyEnforcerViolationGenerator{}
}

func (p PolicyEnforcerViolationGenerator) GenerateViolations(cmdResults *results.SecurityCommandResults) (convertedViolations []services.XrayViolation, err error) {
	convertedViolations = []services.XrayViolation{}
	// Get with API
	return
}
