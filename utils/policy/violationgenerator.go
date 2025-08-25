package policy

import (
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type ViolationGenerator interface {
	GenerateViolations(cmdResults results.SecurityCommandResults) ([]services.XrayViolation, error)
}
