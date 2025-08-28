package local

import (
	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type DeprecatedViolationGenerator struct {
}

func NewDeprecatedViolationGenerator() *DeprecatedViolationGenerator {
	return &DeprecatedViolationGenerator{}
}

func (d *DeprecatedViolationGenerator) WithOptions(options ...policy.ViolationGeneratorOption) policy.ViolationGenerator {
	for _, option := range options {
		option(d)
	}
	return d
}

func (d *DeprecatedViolationGenerator) GenerateViolations(cmdResults *results.SecurityCommandResults) (convertedViolations []policy.Violation, err error) {
	convertedViolations = []policy.Violation{}
	// Convert from cmdResults to policy.Violation
	return
}
