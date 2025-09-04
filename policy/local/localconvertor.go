package local

import (
	"errors"
	"fmt"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/log"
	"github.com/jfrog/jfrog-cli-security/policy"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

type DeprecatedViolationGenerator struct {
}

func NewDeprecatedViolationGenerator() *DeprecatedViolationGenerator {
	return &DeprecatedViolationGenerator{}
}

func (d *DeprecatedViolationGenerator) WithOptions(options ...policy.PolicyHandlerOption) policy.PolicyHandler {
	for _, option := range options {
		option(d)
	}
	return d
}

func (d *DeprecatedViolationGenerator) GenerateViolations(cmdResults *results.SecurityCommandResults) (convertedViolations []violationutils.Violation, err error) {
	convertedViolations = []violationutils.Violation{}
	// Convert from cmdResults to policy.Violation
	for _, target := range cmdResults.Targets {
		// SCA violations
		if target.ScaResults != nil {

		}
	}
	return
}

type ParseScanGraphViolationFunc func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error

// Allows to iterate over the provided SCA violations and call the provided handler for each impacted component/package with a violation to process it.
func ForEachScanGraphViolation(target results.ScanTarget, descriptors []string, violations []services.Violation, entitledForJas bool, applicabilityRuns []*sarif.Run, securityHandler ParseScanGraphViolationFunc, licenseHandler ParseScanGraphViolationFunc, operationalRiskHandler ParseScanGraphViolationFunc) (watches []string, failBuild bool, err error) {
	if securityHandler == nil && licenseHandler == nil && operationalRiskHandler == nil {
		return
	}
	watchesSet := datastructures.MakeSet[string]()
	for _, violation := range violations {
		// Handle duplicates and general attributes
		watchesSet.Add(violation.WatchName)
		failBuild = failBuild || violation.FailBuild
		// Prepare violation information
		impactedPackagesIds, fixedVersions, directComponents, impactPaths, e := results.SplitComponents(results.GetBestScaEvidenceMatch(target, descriptors), violation.Components)
		if e != nil {
			err = errors.Join(err, e)
			continue
		}
		cves, applicabilityStatus := results.ConvertCvesWithApplicability(violation.Cves, entitledForJas, applicabilityRuns, violation.Components)
		severity, e := severityutils.ParseSeverity(violation.Severity, false)
		if e != nil {
			err = errors.Join(err, e)
			continue
		}
		// Parse the violation according to its type
		switch violation.ViolationType {
		case violationutils.ViolationTypeSecurity.String():
			if securityHandler == nil {
				// No handler was provided for security violations
				continue
			}

			var skipNotApplicable bool
			if skipNotApplicable, err = shouldSkipNotApplicable(violation, applicabilityStatus); skipNotApplicable {
				log.Debug("A non-applicable violation was found and will be removed from final results as requested by its policies")
				continue
			}

			for compIndex := 0; compIndex < len(impactedPackagesIds); compIndex++ {
				if e := securityHandler(violation, cves, applicabilityStatus, severity, impactedPackagesIds[compIndex], fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex]); e != nil {
					err = errors.Join(err, e)
					continue
				}
			}
		case violationutils.ViolationTypeLicense.String():
			if licenseHandler == nil {
				// No handler was provided for license violations
				continue
			}
			for compIndex := 0; compIndex < len(impactedPackagesIds); compIndex++ {
				if impactedPackagesName, _, _ := techutils.SplitComponentId(impactedPackagesIds[compIndex]); impactedPackagesName == "root" {
					// No Need to output 'root' as impacted package for license since we add this as the root node for the scan
					continue
				}
				if e := licenseHandler(violation, cves, applicabilityStatus, severity, impactedPackagesIds[compIndex], fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex]); e != nil {
					err = errors.Join(err, e)
					continue
				}
			}
		case violationutils.ViolationTypeOperationalRisk.String():
			if operationalRiskHandler == nil {
				// No handler was provided for operational risk violations
				continue
			}
			for compIndex := 0; compIndex < len(impactedPackagesIds); compIndex++ {
				if e := operationalRiskHandler(violation, cves, applicabilityStatus, severity, impactedPackagesIds[compIndex], fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex]); e != nil {
					err = errors.Join(err, e)
					continue
				}
			}
		}
	}
	watches = watchesSet.ToSlice()
	return
}

// This func iterates every violation and checks if there is a violation that should fail the build.
// The build should be failed if there exists at least one violation in any target that holds the following conditions:
// 1) The violation is set to fail the build by FailBuild or FailPr
// 2) The violation has applicability status other than 'NotApplicable' OR the violation has 'NotApplicable' status and is not set to skip-non-applicable
func CheckIfFailBuild(auditResults *results.SecurityCommandResults) (bool, error) {
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

func checkIfFailBuildConsideringApplicability(target *results.TargetResults, entitledForJas bool, shouldFailBuild *bool) error {
	jasApplicabilityResults := target.JasResults.GetApplicabilityScanResults()

	if target.ScaResults == nil {
		return nil
	}
	// Get new violations from the target
	// newViolations := target.ScaResults.Violations

	// // Here we iterate the new violation results and check if any of them should fail the build.
	// _, _, err := ForEachScanGraphViolation(
	// 	target.ScanTarget,
	// 	[]string{},
	// 	newViolations,
	// 	entitledForJas,
	// 	jasApplicabilityResults,
	// 	checkIfShouldFailBuildAccordingToPolicy(shouldFailBuild),
	// 	nil,
	// 	nil)
	// if err != nil {
	// 	return err
	// }

	// Here we iterate the deprecated violation results to check if any of them should fail the build.
	// TODO remove this part once the DeprecatedXrayResults are completely removed and no longer in use
	for _, result := range target.ScaResults.DeprecatedXrayResults {
		deprecatedViolations := result.Scan.Violations
		_, _, err := ForEachScanGraphViolation(
			target.ScanTarget,
			[]string{},
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

func checkIfFailBuildWithoutConsideringApplicability(target *results.TargetResults) bool {
	if target.ScaResults == nil {
		return false
	}
	// for _, newViolation := range target.ScaResults.Violations {
	// 	if newViolation.FailBuild || newViolation.FailPr {
	// 		return true
	// 	}
	// }
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

// Checks if the violation's applicability status is NotApplicable and if all of its policies states that non-applicable CVEs should be skipped
func shouldSkipNotApplicable(violation services.Violation, applicabilityStatus jasutils.ApplicabilityStatus) (bool, error) {
	if applicabilityStatus != jasutils.NotApplicable {
		return false, nil
	}

	if len(violation.Policies) == 0 {
		return false, errors.New("a violation with no policies was provided")
	}

	for _, policy := range violation.Policies {
		if !policy.SkipNotApplicable {
			return false, nil
		}
	}
	return true, nil
}
