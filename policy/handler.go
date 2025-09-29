package policy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"

	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
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
	violations, err := generator.GenerateViolations(cmdResults)
	// We add the results before checking for errors, so we can display the results even if an error occur
	if filteredScaViolations := filterNotApplicableViolations(violations.Sca); len(filteredScaViolations) != len(violations.Sca) {
		log.Debug(fmt.Sprintf("Filtered out %d not applicable SCA violations based on policy settings.", len(violations.Sca)-len(filteredScaViolations)))
		violations.Sca = filteredScaViolations
	}
	cmdResults.SetViolations(getStatusCode(err), violations)
	if err != nil {
		return fmt.Errorf("failed to fetch violations: %s", err.Error())
	}
	if violations.Count() == 0 {
		log.Info("No violations found.")
	} else {
		log.Info(fmt.Sprintf("Generated %d violations. [%s]", violations.Count(), violations.String()))
	}
	return
}

func filterNotApplicableViolations(violations []violationutils.CveViolation) (filteredViolations []violationutils.CveViolation) {
	filteredViolations = make([]violationutils.CveViolation, 0)
	for _, violation := range violations {
		shouldSkip := false
		for _, policy := range violation.Policies {
			shouldSkip = shouldSkip || policy.SkipNotApplicable
		}
		if !shouldSkip || violation.ContextualAnalysis == nil || jasutils.ConvertToApplicabilityStatus(violation.ContextualAnalysis.Status) != jasutils.NotApplicable {
			filteredViolations = append(filteredViolations, violation)
		}
	}
	return filteredViolations
}

func getStatusCode(err error) int {
	if err == nil {
		return 0
	}
	return 1
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

func GetOperationalRiskViolationReadableData(riskReason string, isEol *bool, eolMsg string, cadence *float64, commits *int64, committers *int, latestVersion string, newerVersion *int) violationutils.OperationalRiskViolationReadableData {
	isEolStr, cadenceStr, commitsStr, committersStr, newerVersionsStr, latestVersionStr := "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
	if isEol != nil {
		isEolStr = strconv.FormatBool(*isEol)
	}
	if cadence != nil {
		cadenceStr = strconv.FormatFloat(*cadence, 'f', -1, 64)
	}
	if committers != nil {
		committersStr = strconv.FormatInt(int64(*committers), 10)
	}
	if commits != nil {
		commitsStr = strconv.FormatInt(*commits, 10)
	}
	if newerVersion != nil {
		newerVersionsStr = strconv.FormatInt(int64(*newerVersion), 10)
	}
	if latestVersion != "" {
		latestVersionStr = latestVersion
	}
	return violationutils.OperationalRiskViolationReadableData{
		IsEol:         isEolStr,
		Cadence:       cadenceStr,
		Commits:       commitsStr,
		Committers:    committersStr,
		EolMessage:    eolMsg,
		RiskReason:    riskReason,
		LatestVersion: latestVersionStr,
		NewerVersions: newerVersionsStr,
	}
}
