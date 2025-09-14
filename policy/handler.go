package policy

import (
	"errors"
	"fmt"
	"slices"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"

	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

type PolicyHandler interface {
	WithOptions(options ...PolicyHandlerOption) PolicyHandler
	GenerateViolations(cmdResults *results.SecurityCommandResults) (violationutils.Violations, error)
}

type PolicyHandlerOption func(sg PolicyHandler)

func EnrichWithGeneratedViolations(generator PolicyHandler, cmdResults *results.SecurityCommandResults) (err error) {
	log.Info("Generating violations...")
	var violations violationutils.Violations
	if violations, err = generator.GenerateViolations(cmdResults); err != nil {
		return fmt.Errorf("failed to fetch violations: %s", err.Error())
	}
	log.Info(fmt.Sprintf("Generated %d violations. [%s]", violations.Count(), violations.String()))
	cmdResults.SetViolations(violations)
	return
}

func CheckPolicyFailure(cmdResults *results.SecurityCommandResults) (err error) {
	policyErrors := []error{}

	// for _, violation := range cmdResults.Violations {

	// }

	return errors.Join(policyErrors...)
}

func NewFailBuildError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeVulnerableBuild, ErrorMsg: "One or more of the detected violations are configured to fail the build that including them"}
}

func NewFailPrError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeError, ErrorMsg: "One or more of the detected violations are configured to fail the pull request that including them"}
}

func GetViolatedLicenses(allowedLicenses []string, licenses []services.License) (violatedLicenses []services.Violation) {
	if len(allowedLicenses) == 0 {
		return
	}
	for _, license := range licenses {
		if !slices.Contains(allowedLicenses, license.Key) {
			violatedLicenses = append(violatedLicenses, services.Violation{
				LicenseKey:    license.Key,
				LicenseName:   license.Name,
				Severity:      severityutils.Medium.String(),
				Components:    license.Components,
				IssueId:       violationutils.CustomLicenseViolationId,
				WatchName:     fmt.Sprintf("jfrog_%s", violationutils.CustomLicenseViolationId),
				ViolationType: violationutils.ScaViolationTypeLicense.String(),
			})
		}
	}
	return
}
