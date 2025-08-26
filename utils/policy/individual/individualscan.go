package individual

// Implementing violation generator interface from each scan by itself

import (
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type DeprecatedViolationGenerator struct {
}

func NewDeprecatedViolationGenerator() *DeprecatedViolationGenerator {
	return &DeprecatedViolationGenerator{}
}

func (d DeprecatedViolationGenerator) GenerateViolations(cmdResults *results.SecurityCommandResults) (convertedViolations []services.XrayViolation, err error) {
	convertedViolations = []services.XrayViolation{}
	// Convert from cmdResults to services.XrayViolation
	return
}
