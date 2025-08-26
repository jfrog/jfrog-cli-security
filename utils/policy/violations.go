package policy

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type ViolationGenerator interface {
	WithOptions(options ...ViolationGeneratorOption) ViolationGenerator
	GenerateViolations(cmdResults *results.SecurityCommandResults) ([]services.XrayViolation, error)
}

type ViolationGeneratorOption func(sg ViolationGenerator)

func FetchGeneratedViolations(generator ViolationGenerator, cmdResults *results.SecurityCommandResults) (err error) {
	var violations []services.XrayViolation
	if violations, err = generator.GenerateViolations(cmdResults); err != nil {
		return fmt.Errorf("failed to fetch violations: %s", err.Error())
	}
	cmdResults.AddViolations(violations...)
	return
}

func NewFailBuildError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeVulnerableBuild, ErrorMsg: "One or more of the detected violations are configured to fail the build that including them"}
}

// This func iterates every violation and checks if there is a violation that should fail the build.
// The build should be failed if there exists at least one violation in any target that holds the following conditions:
// 1) The violation is set to fail the build by FailBuild or FailPr
// 2) The violation has applicability status other than 'NotApplicable' OR the violation has 'NotApplicable' status and is not set to skip-non-applicable
func CheckIfFailBuild(auditResults *SecurityCommandResults) (bool, error) {
	for _, target := range auditResults.Targets {
		shouldFailBuild := false
		// We first check if JasResults exist so we can extract CA results and consider Applicability status when checking if the build should fail.
		if target.JasResults == nil {
			shouldFailBuild = checkIfFailBuildWithoutConsideringApplicability(target)
		} else {
			// If JasResults are not empty we check old and new violation while considering Applicability status and Skip-not-applicable policy rule.
			if err := checkIfFailBuildConsideringApplicability(target, auditResults.EntitledForJas, &shouldFailBuild); err != nil {
				return false, fmt.Errorf("failed to check if build should fail for target %s: %w", target.ScanTarget.Target, err)
			}
		}
		if shouldFailBuild {
			// If we found a violation that should fail the build, we return true.
			return true, nil
		}
	}
	return false, nil
}

func checkIfFailBuildConsideringApplicability(target *TargetResults, entitledForJas bool, shouldFailBuild *bool) error {
	jasApplicabilityResults := target.JasResults.GetApplicabilityScanResults()

	if target.ScaResults == nil {
		return nil
	}
	// Get new violations from the target
	newViolations := target.ScaResults.Violations

	// Here we iterate the new violation results and check if any of them should fail the build.
	_, _, err := ForEachScanGraphViolation(
		target.ScanTarget,
		newViolations,
		entitledForJas,
		jasApplicabilityResults,
		checkIfShouldFailBuildAccordingToPolicy(shouldFailBuild),
		nil,
		nil)
	if err != nil {
		return err
	}

	// Here we iterate the deprecated violation results to check if any of them should fail the build.
	// TODO remove this part once the DeprecatedXrayResults are completely removed and no longer in use
	for _, result := range target.ScaResults.DeprecatedXrayResults {
		deprecatedViolations := result.Scan.Violations
		_, _, err = ForEachScanGraphViolation(
			target.ScanTarget,
			deprecatedViolations,
			entitledForJas,
			jasApplicabilityResults,
			checkIfShouldFailBuildAccordingToPolicy(shouldFailBuild),
			nil,
			nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkIfFailBuildWithoutConsideringApplicability(target *TargetResults) bool {
	if target.ScaResults == nil {
		return false
	}
	for _, newViolation := range target.ScaResults.Violations {
		if newViolation.FailBuild || newViolation.FailPr {
			return true
		}
	}
	// TODO remove this for loop once the DeprecatedXrayResults are completely removed and no longer in use
	for _, scanResponse := range target.GetScaScansXrayResults() {
		for _, oldViolation := range scanResponse.Violations {
			if oldViolation.FailBuild || oldViolation.FailPr {
				return true
			}
		}
	}
	return false
}

func checkIfShouldFailBuildAccordingToPolicy(shouldFailBuild *bool) func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
	return func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) (err error) {
		if !violation.FailBuild && !violation.FailPr {
			// If the violation is not set to fail the build we simply return
			return nil
		}
		// If the violation is set to fail the build, we check if the violation has NotApplicable status and is set to skip-non-applicable.
		// If the violation is NotApplicable and is set to skip-non-applicable, we don't fail the build.
		// If the violation has any other status OR has NotApplicable status but is not set to skip-not-applicable, we fail the build.
		var shouldSkip bool
		if shouldSkip, err = shouldSkipNotApplicable(violation, applicabilityStatus); err != nil {
			return err
		}
		if !shouldSkip {
			*shouldFailBuild = true
		}
		return nil
	}
}
