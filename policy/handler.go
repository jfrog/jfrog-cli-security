package policy

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type PolicyHandler interface {
	WithOptions(options ...PolicyHandlerOption) PolicyHandler
	GenerateViolations(cmdResults *results.SecurityCommandResults) (violationutils.Violations, error)
}

type PolicyHandlerOption func(sg PolicyHandler)

func EnrichWithGeneratedViolations(generator PolicyHandler, cmdResults *results.SecurityCommandResults) (err error) {
	log.Info("Xray is processing your scan results...")
	violations, err := generator.GenerateViolations(cmdResults)
	// We add the results before checking for errors, so we can display the results even if an error occur
	if filteredScaViolations := filterNotApplicableViolations(violations.Sca); len(filteredScaViolations) != len(violations.Sca) {
		log.Debug(fmt.Sprintf("Filtered out %d not applicable SCA violations based on policy settings.", len(violations.Sca)-len(filteredScaViolations)))
		violations.Sca = filteredScaViolations
	}
	cmdResults.SetViolations(getStatusCodeFromErr(err), violations)
	if err != nil {
		return fmt.Errorf("failed to fetch violations: %s", err.Error())
	}
	if violations.Count() == 0 {
		log.Info("No violations found.")
	} else {
		log.Info(fmt.Sprintf("Found %d violations: [%s]", violations.Count(), violations.String()))
	}
	return
}

func filterNotApplicableViolations(violations []violationutils.CveViolation) (filteredViolations []violationutils.CveViolation) {
	filteredViolations = make([]violationutils.CveViolation, 0)
	for _, violation := range violations {
		if !violation.ShouldSkipNotApplicable() || violation.ContextualAnalysis == nil || jasutils.ConvertToApplicabilityStatus(violation.ContextualAnalysis.Status) != jasutils.NotApplicable {
			filteredViolations = append(filteredViolations, violation)
		}
	}
	return filteredViolations
}

func getStatusCodeFromErr(err error) int {
	if err == nil {
		return 0
	}
	return 1
}

func CheckPolicyFailBuildError(cmdResults *results.SecurityCommandResults) (FailBuildError error) {
	if cmdResults == nil || cmdResults.Violations == nil || (cmdResults.ViolationsStatusCode != nil && *cmdResults.ViolationsStatusCode != 0) {
		return
	}
	if cmdResults.Violations.ShouldFailBuild() {
		FailBuildError = NewFailBuildError()
	}
	return
}

func CheckPolicyFailPrError(cmdResults *results.SecurityCommandResults) (err error) {
	if cmdResults == nil || (cmdResults.ViolationsStatusCode != nil && *cmdResults.ViolationsStatusCode != 0) {
		return
	}
	if cmdResults.Violations.ShouldFailPR() {
		err = NewFailPrError()
	}
	return
}

func NewFailBuildError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeVulnerableBuild, ErrorMsg: "One or more of the detected violations are configured to fail the build that including them"}
}

func NewFailPrError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeError, ErrorMsg: "One or more of the detected violations are configured to fail the pull request that including them"}
}
