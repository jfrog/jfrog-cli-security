package results

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	customLicenseViolationId   = "custom_license_violation"
	RootIndex                  = 0
	DirectDependencyIndex      = 1
	DirectDependencyPathLength = 2
	nodeModules                = "node_modules"

	// <FILE_REF>#L<START_LINE>C<START_COLUMN>-L<END_LINE>C<END_COLUMN>
	LocationIdTemplate = "%s#L%dC%d-L%dC%d"
	// Applicability properties for cdx
	ApplicabilityStatusPropertyName             = "jfrog:contextual-analysis:status"
	ApplicabilityEvidenceReasonPropertyTemplate = "jfrog:contextual-analysis:evidence:reason:" + LocationIdTemplate
	ApplicabilityEvidencePropertyTemplate       = "jfrog:contextual-analysis:evidence:" + LocationIdTemplate
)

var (
	ErrResetConvertor    = fmt.Errorf("reset must be called before parsing new scan results metadata")
	ErrNoTargetConvertor = fmt.Errorf("ParseNewTargetResults must be called before starting to parse issues")
)

func NewFailBuildError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeVulnerableBuild, ErrorMsg: "One or more of the detected violations are configured to fail the build that including them"}
}

// This func iterated every violation and checks if there is a violation that should fail the build.
// The build should be failed if there exists at least one violation in any target that holds the following conditions:
// 1) The violation is set to fail the build
// 2) The violation has applicability status other than 'NotApplicable' OR the violation has 'NotApplicable' status and is not set to skip-non-applicable
func CheckIfFailBuild(auditResults *SecurityCommandResults) (bool, error) {
	for _, target := range auditResults.Targets {
		// We first check if JasResults exist so we can extract CA results and consider Applicability status when checking if the build should fail.
		if target.JasResults == nil {
			shouldFailBuild, err := checkIfFailBuildWithoutConsideringApplicability(target)
			if err != nil {
				return false, fmt.Errorf("failed to check if build should fail for target %s: %w", target.ScanTarget.Target, err)
			}
			if shouldFailBuild {
				// If we found a violation that should fail the build, we return true.
				return true, nil
			}
		} else {
			// If JasResults are not empty we check old and new violation while considering Applicability status and Skip-not-applicable policy rule.
			var shouldFailBuild bool
			if err := checkIfFailBuildConsideringApplicability(target, auditResults.EntitledForJas, &shouldFailBuild); err != nil {
				return false, fmt.Errorf("failed to check if build should fail for target %s: %w", target.ScanTarget.Target, err)
			}
			if shouldFailBuild {
				// If we found a violation that should fail the build, we return true.
				return true, nil
			}
		}
	}
	return false, nil
}

func checkIfFailBuildConsideringApplicability(target *TargetResults, entitledForJas bool, shouldFailBuild *bool) error {
	jasApplicabilityResults := target.JasResults.GetApplicabilityScanResults()

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

func checkIfFailBuildWithoutConsideringApplicability(target *TargetResults) (bool, error) {
	for _, newViolation := range target.ScaResults.Violations {
		if newViolation.FailBuild || newViolation.FailPr {
			return true, nil
		}
	}

	// TODO remove this for loop once the DeprecatedXrayResults are completely removed and no longer in use
	for _, scanResponse := range target.GetScaScansXrayResults() {
		for _, oldViolation := range scanResponse.Violations {
			if oldViolation.FailBuild || oldViolation.FailPr {
				return true, nil
			}
		}
	}

	return false, nil
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

type ParseScanGraphVulnerabilityFunc func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type ParseScanGraphViolationFunc func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type ParseLicenseFunc func(license services.License, impactedPackagesId string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type ParseJasIssueFunc func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) error
type ParseSbomComponentFunc func(component cyclonedx.Component, relatedDependencies *cyclonedx.Dependency, relation cdxutils.ComponentRelation) error

type ParseBomScaVulnerabilityFunc func(vulnerability cyclonedx.Vulnerability, component cyclonedx.Component, fixedVersion *[]cyclonedx.AffectedVersions, applicability *formats.Applicability, severity severityutils.Severity) error

// Allows to iterate over the provided SARIF runs and call the provided handler for each issue to process it.
func ForEachJasIssue(runs []*sarif.Run, entitledForJas bool, handler ParseJasIssueFunc) error {
	if !entitledForJas || handler == nil {
		return nil
	}
	for _, run := range runs {
		for _, result := range run.Results {
			severity, err := severityutils.ParseSeverity(result.Level, true)
			if err != nil {
				return err
			}
			rule := sarifutils.GetRuleById(run, sarifutils.GetResultRuleId(result))
			if len(result.Locations) == 0 {
				// If there are no locations, the issue is not specific to a location, and we should handle it as a general issue.
				if err := handler(run, rule, severity, result, nil); err != nil {
					return err
				}
			} else {
				for _, location := range result.Locations {
					if err := handler(run, rule, severity, result, location); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// ForEachScanGraphVulnerability allows to iterate over the provided SCA security vulnerabilities and call the provided handler for each impacted component/package with a vulnerability to process it.
func ForEachScanGraphVulnerability(target ScanTarget, vulnerabilities []services.Vulnerability, entitledForJas bool, applicabilityRuns []*sarif.Run, handler ParseScanGraphVulnerabilityFunc) error {
	if handler == nil {
		return nil
	}
	for _, vulnerability := range vulnerabilities {
		cves, applicabilityStatus := ConvertCvesWithApplicability(vulnerability.Cves, entitledForJas, applicabilityRuns, vulnerability.Components)
		severity, err := severityutils.ParseSeverity(vulnerability.Severity, false)
		if err != nil {
			return err
		}
		impactedPackagesIds, fixedVersions, directComponents, impactPaths, err := SplitComponents(target.Target, vulnerability.Components)
		if err != nil {
			return err
		}
		for compIndex := 0; compIndex < len(impactedPackagesIds); compIndex++ {
			if err := handler(vulnerability, cves, applicabilityStatus, severity, impactedPackagesIds[compIndex], fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex]); err != nil {
				return err
			}
		}
	}
	return nil
}

func ForEachScaBomVulnerability(target ScanTarget, bom *cyclonedx.BOM, entitledForJas bool, applicabilityRuns []*sarif.Run, handler ParseBomScaVulnerabilityFunc) error {
	if handler == nil || bom == nil || bom.Components == nil || bom.Vulnerabilities == nil {
		return nil
	}
	for _, vulnerability := range *bom.Vulnerabilities {
		if vulnerability.Affects == nil || len(*vulnerability.Affects) == 0 {
			// If there are no affected components, we skip the vulnerability.
			log.Debug(fmt.Sprintf("Skipping vulnerability %s as it has no affected components", vulnerability.BOMRef))
			continue
		}
		// Check the CA status of the vulnerability
		var applicability *formats.Applicability
		if entitledForJas && len(applicabilityRuns) > 0 {
			applicability = GetCveApplicabilityField(vulnerability.BOMRef, applicabilityRuns)
		}
		// Get the related components for the vulnerability
		for _, affectedComponent := range *vulnerability.Affects {
			relatedComponent := cdxutils.SearchComponentByRef(bom.Components, affectedComponent.Ref)
			if relatedComponent == nil {
				log.Debug(fmt.Sprintf("Skipping vulnerability %s as it has no related component with BOMRef %s", vulnerability.BOMRef, affectedComponent.Ref))
				continue
			}
			var fixedVersion *[]cyclonedx.AffectedVersions
			if affectedComponent.Range != nil {
				for _, affectedVersion := range *affectedComponent.Range {
					if affectedVersion.Status == cyclonedx.VulnerabilityStatusNotAffected {
						if fixedVersion == nil {
							fixedVersion = &[]cyclonedx.AffectedVersions{}
						}
						*fixedVersion = append(*fixedVersion, affectedVersion)
					}
				}
			}
			// Pass the vulnerability to the handler with its related information
			if err := handler(vulnerability, *relatedComponent, fixedVersion, applicability, cdxRatingToSeverity(vulnerability.Ratings)); err != nil {
				return err
			}
		}
	}
	return nil
}

func cdxRatingToSeverity(ratings *[]cyclonedx.VulnerabilityRating) (severity severityutils.Severity) {
	if ratings == nil || len(*ratings) == 0 {
		return severityutils.Unknown
	}
	// If Xray provided ratings, we use them to determine the severity.
	if xraySeverity := cdxutils.SearchRating(ratings, cyclonedx.ScoringMethodOther, &cyclonedx.Source{Name: utils.XrayToolName}); xraySeverity != nil {
		return severityutils.CycloneDxSeverityToSeverity(xraySeverity.Severity)
	}
	// Xray didn't provide severity, Get the highest severity rating
	severities := []severityutils.Severity{}
	for _, rating := range *ratings {
		severities = append(severities, severityutils.CycloneDxSeverityToSeverity(rating.Severity))
	}
	return severityutils.MostSevereSeverity(severities...)
}

// Allows to iterate over the provided SCA violations and call the provided handler for each impacted component/package with a violation to process it.
func ForEachScanGraphViolation(target ScanTarget, violations []services.Violation, entitledForJas bool, applicabilityRuns []*sarif.Run, securityHandler ParseScanGraphViolationFunc, licenseHandler ParseScanGraphViolationFunc, operationalRiskHandler ParseScanGraphViolationFunc) (watches []string, failBuild bool, err error) {
	if securityHandler == nil && licenseHandler == nil && operationalRiskHandler == nil {
		return
	}
	watchesSet := datastructures.MakeSet[string]()
	for _, violation := range violations {
		// Handle duplicates and general attributes
		watchesSet.Add(violation.WatchName)
		failBuild = failBuild || violation.FailBuild
		// Prepare violation information
		impactedPackagesIds, fixedVersions, directComponents, impactPaths, e := SplitComponents(target.Target, violation.Components)
		if e != nil {
			err = errors.Join(err, e)
			continue
		}
		cves, applicabilityStatus := ConvertCvesWithApplicability(violation.Cves, entitledForJas, applicabilityRuns, violation.Components)
		severity, e := severityutils.ParseSeverity(violation.Severity, false)
		if e != nil {
			err = errors.Join(err, e)
			continue
		}
		// Parse the violation according to its type
		switch violation.ViolationType {
		case utils.ViolationTypeSecurity.String():
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
		case utils.ViolationTypeLicense.String():
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
		case utils.ViolationTypeOperationalRisk.String():
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

// ForEachLicense allows to iterate over the provided licenses and call the provided handler for each component/package with a license to process it.
func ForEachLicense(target ScanTarget, licenses []services.License, handler ParseLicenseFunc) error {
	if handler == nil {
		return nil
	}
	for _, license := range licenses {
		impactedPackagesIds, _, directComponents, impactPaths, err := SplitComponents(target.Target, license.Components)
		if err != nil {
			return err
		}
		for compIndex := 0; compIndex < len(impactedPackagesIds); compIndex++ {
			if err := handler(license, impactedPackagesIds[compIndex], directComponents[compIndex], impactPaths[compIndex]); err != nil {
				return err
			}
		}
	}
	return nil
}

// ForEachSbomComponent allows to iterate over the provided CycloneDX SBOM components and call the provided handler for each component to process it.
func ForEachSbomComponent(bom *cyclonedx.BOM, handler ParseSbomComponentFunc) (err error) {
	if handler == nil || bom == nil || bom.Components == nil {
		return
	}
	for _, component := range *bom.Components {
		if err := handler(
			component,
			cdxutils.SearchDependencyEntry(bom.Dependencies, component.BOMRef),
			cdxutils.GetComponentRelation(bom, component.BOMRef, true),
		); err != nil {
			return err
		}
	}
	return
}

func SplitComponents(target string, impactedPackages map[string]services.Component) (impactedPackagesIds []string, fixedVersions [][]string, directComponents [][]formats.ComponentRow, impactPaths [][][]formats.ComponentRow, err error) {
	if len(impactedPackages) == 0 {
		err = errorutils.CheckErrorf("failed while parsing the response from Xray: violation doesn't have any components")
		return
	}
	for currCompId, currComp := range impactedPackages {
		impactedPackagesIds = append(impactedPackagesIds, currCompId)
		fixedVersions = append(fixedVersions, currComp.FixedVersions)
		currDirectComponents, currImpactPaths := getDirectComponentsAndImpactPaths(target, currComp.ImpactPaths)
		directComponents = append(directComponents, currDirectComponents)
		impactPaths = append(impactPaths, currImpactPaths)
	}
	return
}

// Gets a slice of the direct dependencies or packages of the scanned component, that depends on the vulnerable package, and converts the impact paths.
func getDirectComponentsAndImpactPaths(target string, impactPaths [][]services.ImpactPathNode) (components []formats.ComponentRow, impactPathsRows [][]formats.ComponentRow) {
	componentsMap := make(map[string]formats.ComponentRow)

	// The first node in the impact path is the scanned component itself. The second one is the direct dependency.
	impactPathLevel := 1
	for _, impactPath := range impactPaths {
		impactPathIndex := impactPathLevel
		if len(impactPath) <= impactPathLevel {
			impactPathIndex = len(impactPath) - 1
		}
		componentId := impactPath[impactPathIndex].ComponentId
		if _, exist := componentsMap[componentId]; !exist {
			compName, compVersion, _ := techutils.SplitComponentIdRaw(componentId)
			componentsMap[componentId] = formats.ComponentRow{Name: compName, Version: compVersion, Location: getComponentLocation(impactPath[impactPathIndex].FullPath, target)}
		}

		// Convert the impact path
		var compImpactPathRows []formats.ComponentRow
		for _, pathNode := range impactPath {
			nodeCompName, nodeCompVersion, _ := techutils.SplitComponentIdRaw(pathNode.ComponentId)
			compImpactPathRows = append(compImpactPathRows, formats.ComponentRow{
				Name:     nodeCompName,
				Version:  nodeCompVersion,
				Location: getComponentLocation(pathNode.FullPath),
			})
		}
		impactPathsRows = append(impactPathsRows, compImpactPathRows)
	}

	for _, row := range componentsMap {
		components = append(components, row)
	}
	return
}

func BuildImpactPath(affectedComponent cyclonedx.Component, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (impactPathsRows [][]formats.ComponentRow) {
	impactPathsRows = [][]formats.ComponentRow{}
	componentAppearances := map[string]int8{}
	for _, parent := range cdxutils.SearchParents(affectedComponent.BOMRef, components, dependencies...) {
		impactedPath := buildImpactPathForComponent(parent, componentAppearances, components, dependencies...)
		// Add the affected component at the end of the impact path
		impactedPath = append(impactedPath, formats.ComponentRow{
			Name:    affectedComponent.Name,
			Version: affectedComponent.Version,
		})
		// Add the impact path to the list of impact paths
		impactPathsRows = append(impactPathsRows, impactedPath)
	}
	return
}

func buildImpactPathForComponent(component cyclonedx.Component, componentAppearances map[string]int8, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) (impactPath []formats.ComponentRow) {
	componentAppearances[component.BOMRef]++
	// Build the impact path for the component
	impactPath = []formats.ComponentRow{
		{
			Name:    component.Name,
			Version: component.Version,
		},
	}
	// Add the parent components to the impact path
	for _, parent := range cdxutils.SearchParents(component.BOMRef, components, dependencies...) {
		if componentAppearances[parent.BOMRef] > xray.MaxUniqueAppearances || parent.BOMRef == component.BOMRef {
			// If the parent is the same as the affected component, we skip it (cyclic dependencies).
			// If the component has already appeared too many times, skip it to avoid stack overflow.
			continue
		}
		parentImpactPath := buildImpactPathForComponent(parent, componentAppearances, components, dependencies...)
		if len(parentImpactPath) > 0 {
			impactPath = append(parentImpactPath, impactPath...)
		}
	}
	return
}

func getComponentLocation(pathsByPriority ...string) *formats.Location {
	for _, path := range pathsByPriority {
		if path != "" {
			return &formats.Location{File: path}
		}
	}
	return nil
}

func GetIssueIdentifier(cvesRow []formats.CveRow, issueId string, delimiter string) string {
	var cvesBuilder strings.Builder
	for i, cve := range cvesRow {
		if i > 0 {
			cvesBuilder.WriteString(delimiter)
		}
		cvesBuilder.WriteString(cve.Id)
	}
	identifier := cvesBuilder.String()
	if identifier == "" {
		identifier = issueId
	}
	return identifier
}

func ConvertCvesWithApplicability(cves []services.Cve, entitledForJas bool, applicabilityRuns []*sarif.Run, components map[string]services.Component) (convertedCves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus) {
	convertedCves = convertCves(cves)
	for i := range convertedCves {
		convertedCves[i].Applicability = GetCveApplicabilityFieldAndFilterDisqualify(convertedCves[i].Id, applicabilityRuns, components)
	}
	applicabilityStatus = GetApplicableCveStatus(entitledForJas, applicabilityRuns, convertedCves)
	return
}

func convertCves(cves []services.Cve) []formats.CveRow {
	var cveRows []formats.CveRow
	for _, cveObj := range cves {
		cveRows = append(cveRows, formats.CveRow{
			Id:           cveObj.Id,
			CvssV2:       cveObj.CvssV2Score,
			CvssV2Vector: cveObj.CvssV2Vector,
			CvssV3:       cveObj.CvssV3Score,
			CvssV3Vector: cveObj.CvssV3Vector,
			Cwe:          cveObj.Cwe,
		})
	}
	return cveRows
}

// FindMaxCVEScore returns the maximum CVSS score of the given CVEs or score based on severity and applicability status if not exists.
func FindMaxCVEScore(severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus, cves []formats.CveRow) (string, error) {
	if len(cves) == 0 {
		return fmt.Sprintf("%.1f", severityutils.GetSeverityScore(severity, applicabilityStatus)), nil
	}
	maxCve := severityutils.MinCveScore
	for _, cve := range cves {
		cveScore, err := GetCveScore(severity, applicabilityStatus, cve)
		if err != nil {
			return "", err
		}
		if cveScore > maxCve {
			maxCve = cveScore
		}
		// if found maximum possible cve score, no need to keep iterating
		if maxCve == severityutils.MaxCveScore {
			break
		}
	}
	return fmt.Sprintf("%.1f", maxCve), nil
}

// GetCveScore returns the CVSS score of the given CVE or score based on severity and applicability status if not exists.
func GetCveScore(severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus, cve formats.CveRow) (float32, error) {
	if cve.CvssV3 == "" {
		return severityutils.GetSeverityScore(severity, applicabilityStatus), nil
	}
	score, err := strconv.ParseFloat(cve.CvssV3, 32)
	return float32(score), err
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
				IssueId:       customLicenseViolationId,
				WatchName:     fmt.Sprintf("jfrog_%s", customLicenseViolationId),
				ViolationType: utils.ViolationTypeLicense.String(),
			})
		}
	}
	return
}

// AppendUniqueImpactPathsForMultipleRoots appends the source impact path to the target impact path while avoiding duplicates.
// Specifically, it is designed for handling multiple root projects, such as Maven or Gradle, by comparing each pair of paths and identifying the path that is closest to the direct dependency.
func AppendUniqueImpactPathsForMultipleRoots(target [][]services.ImpactPathNode, source [][]services.ImpactPathNode) [][]services.ImpactPathNode {
	for targetPathIndex, targetPath := range target {
		for sourcePathIndex, sourcePath := range source {
			var subset []services.ImpactPathNode
			if len(sourcePath) <= len(targetPath) {
				subset = isImpactPathIsSubset(targetPath, sourcePath)
				if len(subset) != 0 {
					target[targetPathIndex] = subset
				}
			} else {
				subset = isImpactPathIsSubset(sourcePath, targetPath)
				if len(subset) != 0 {
					source[sourcePathIndex] = subset
				}
			}
		}
	}

	return AppendUniqueImpactPaths(target, source, false)
}

// isImpactPathIsSubset checks if targetPath is a subset of sourcePath, and returns the subset if exists
func isImpactPathIsSubset(target []services.ImpactPathNode, source []services.ImpactPathNode) []services.ImpactPathNode {
	var subsetImpactPath []services.ImpactPathNode
	impactPathNodesMap := make(map[string]bool)
	for _, node := range target {
		impactPathNodesMap[node.ComponentId] = true
	}

	for _, node := range source {
		if impactPathNodesMap[node.ComponentId] {
			subsetImpactPath = append(subsetImpactPath, node)
		}
	}

	if len(subsetImpactPath) == len(target) || len(subsetImpactPath) == len(source) {
		return subsetImpactPath
	}
	return []services.ImpactPathNode{}
}

// appendImpactPathsWithoutDuplicates appends the elements of a source [][]ImpactPathNode struct to a target [][]ImpactPathNode, without adding any duplicate elements.
// This implementation uses the ComponentId field of the ImpactPathNode struct to check for duplicates, as it is guaranteed to be unique.
func AppendUniqueImpactPaths(target [][]services.ImpactPathNode, source [][]services.ImpactPathNode, multipleRoots bool) [][]services.ImpactPathNode {
	if multipleRoots {
		return AppendUniqueImpactPathsForMultipleRoots(target, source)
	}
	impactPathMap := make(map[string][]services.ImpactPathNode)
	for _, path := range target {
		// The first node component id is the key and the value is the whole path
		key := getImpactPathKey(path)
		impactPathMap[key] = path
	}

	for _, path := range source {
		key := getImpactPathKey(path)
		if _, exists := impactPathMap[key]; !exists {
			impactPathMap[key] = path
			target = append(target, path)
		}
	}
	return target
}

// getImpactPathKey return a key that is used as a key to identify and deduplicate impact paths.
// If an impact path length is equal to directDependencyPathLength, then the direct dependency is the key, and it's in the directDependencyIndex place.
func getImpactPathKey(path []services.ImpactPathNode) string {
	key := path[RootIndex].ComponentId
	if len(path) == DirectDependencyPathLength {
		key = path[DirectDependencyIndex].ComponentId
	}
	return key
}

func GetCveApplicabilityField(cveId string, applicabilityScanResults []*sarif.Run) *formats.Applicability {
	if len(applicabilityScanResults) == 0 {
		return nil
	}
	applicability := formats.Applicability{}
	resultFound := false
	var applicabilityStatuses []jasutils.ApplicabilityStatus
	for _, applicabilityRun := range applicabilityScanResults {
		if rule := sarifutils.GetRuleById(applicabilityRun, jasutils.CveToApplicabilityRuleId(cveId)); rule != nil {
			applicability.ScannerDescription = sarifutils.GetRuleFullDescription(rule)
			applicability.UndeterminedReason = sarifutils.GetRuleUndeterminedReason(rule)
			status := getApplicabilityStatusFromRule(rule)
			if status != "" {
				applicabilityStatuses = append(applicabilityStatuses, status)
			}
		}
		cveResults := sarifutils.GetResultsByRuleId(jasutils.CveToApplicabilityRuleId(cveId), applicabilityRun)
		if len(cveResults) == 0 {
			continue
		}
		resultFound = true
		for _, result := range cveResults {
			// Add new evidences from locations
			for _, location := range result.Locations {
				if evidence := getEvidence(result, location, applicabilityRun.Invocations...); evidence != nil {
					applicability.Evidence = append(applicability.Evidence, *evidence)
				}
			}
		}
	}
	switch {
	case len(applicabilityStatuses) > 0:
		applicability.Status = string(getFinalApplicabilityStatus(applicabilityStatuses))
	case !resultFound:
		applicability.Status = string(jasutils.ApplicabilityUndetermined)
	case len(applicability.Evidence) == 0:
		applicability.Status = string(jasutils.NotApplicable)
	default:
		applicability.Status = string(jasutils.Applicable)
	}
	return &applicability
}

func GetCveApplicabilityFieldAndFilterDisqualify(cveId string, applicabilityScanResults []*sarif.Run, components map[string]services.Component) (applicability *formats.Applicability) {
	if applicability = GetCveApplicabilityField(cveId, applicabilityScanResults); applicability == nil || len(applicability.Evidence) == 0 {
		// nothing more to do
		return
	}
	// Filter out evidences that are disqualified
	filteredEvidence := make([]formats.Evidence, 0, len(applicability.Evidence))
	for _, evidence := range applicability.Evidence {
		fileName := evidence.Location.File
		if fileName == "" || !shouldDisqualifyEvidence(components, filepath.Clean(fileName)) {
			// If the file name is empty, we cannot determine if it should be disqualified
			// If the evidence is not disqualified, keep it
			filteredEvidence = append(filteredEvidence, evidence)
		}
	}
	applicability.Evidence = filteredEvidence
	return
}

func getEvidence(result *sarif.Result, location *sarif.Location, invocations ...*sarif.Invocation) *formats.Evidence {
	return &formats.Evidence{
		Location: formats.Location{
			File:        sarifutils.GetRelativeLocationFileName(location, invocations),
			StartLine:   sarifutils.GetLocationStartLine(location),
			StartColumn: sarifutils.GetLocationStartColumn(location),
			EndLine:     sarifutils.GetLocationEndLine(location),
			EndColumn:   sarifutils.GetLocationEndColumn(location),
			Snippet:     sarifutils.GetLocationSnippetText(location),
		},
		Reason: sarifutils.GetResultMsgText(result),
	}
}

func GetApplicableCveStatus(entitledForJas bool, applicabilityScanResults []*sarif.Run, cves []formats.CveRow) jasutils.ApplicabilityStatus {
	if !entitledForJas || len(applicabilityScanResults) == 0 {
		return jasutils.NotScanned
	}
	if len(cves) == 0 {
		return jasutils.NotCovered
	}
	var applicableStatuses []jasutils.ApplicabilityStatus
	for _, cve := range cves {
		if cve.Applicability != nil {
			applicableStatuses = append(applicableStatuses, jasutils.ApplicabilityStatus(cve.Applicability.Status))
		}
	}
	return getFinalApplicabilityStatus(applicableStatuses)
}

// We only care to update the status if it's the first time we see it or if status is 0 (completed) and the new status is not (failed)
func ShouldUpdateStatus(currentStatus, newStatus *int) bool {
	if currentStatus == nil || (*currentStatus == 0 && newStatus != nil) {
		return true
	}
	return false
}

func getApplicabilityStatusFromRule(rule *sarif.ReportingDescriptor) jasutils.ApplicabilityStatus {
	if rule != nil && rule.Properties != nil && rule.Properties.Properties[jasutils.ApplicabilitySarifPropertyKey] != nil {
		status, ok := rule.Properties.Properties[jasutils.ApplicabilitySarifPropertyKey].(string)
		if !ok {
			log.Debug(fmt.Sprintf("Failed to get applicability status from rule properties for rule_id %s", sarifutils.GetRuleId(rule)))
		}
		switch status {
		case "not_covered":
			return jasutils.NotCovered
		case "undetermined":
			return jasutils.ApplicabilityUndetermined
		case "not_applicable":
			return jasutils.NotApplicable
		case "applicable":
			return jasutils.Applicable
		case "missing_context":
			return jasutils.MissingContext
		}
	}
	return jasutils.NotScanned
}

func GetDependencyId(depName, version string) string {
	if version == "" {
		return depName
	}
	return fmt.Sprintf("%s:%s", depName, version)
}

func GetScaIssueId(depName, version, issueId string) string {
	return fmt.Sprintf("%s_%s_%s", issueId, depName, version)
}

// replaces underscore with dash
func IdToName(input string) string {
	return strings.Join(strings.Split(input, "_"), "-")
}

// GetUniqueKey returns a unique string key of format "vulnerableDependency:vulnerableVersion:xrayID:fixVersionExist"
func GetUniqueKey(vulnerableDependency, vulnerableVersion, xrayID string, fixVersionExist bool) string {
	return strings.Join([]string{vulnerableDependency, vulnerableVersion, xrayID, strconv.FormatBool(fixVersionExist)}, ":")
}

// Relevant only when "third-party-contextual-analysis" flag is on,
// which mean we scan the environment folders as well (node_modules for example...)
// When a certain package is reported applicable, and the evidence found
// is inside the source code of the same package, we should disqualify it.
//
// For example,
// Cve applicability was found inside the 'mquery' package.
// filePath = myProject/node_modules/mquery/badCode.js , disqualify = True.
// Disqualify the above evidence, as the reported applicability is used inside its own package.
//
// filePath = myProject/node_modules/mpath/badCode.js  , disqualify = False.
// Found use of a badCode inside the node_modules from a different package, report applicable.
func shouldDisqualifyEvidence(components map[string]services.Component, evidenceFilePath string) (disqualify bool) {
	for key := range components {
		if !strings.HasPrefix(key, techutils.Npm.GetPackageTypeId()) {
			return
		}
		dependencyName, _, _ := techutils.SplitComponentIdRaw(key)
		// Check both Unix & Windows paths.
		if strings.Contains(evidenceFilePath, nodeModules+"/"+dependencyName) || strings.Contains(evidenceFilePath, filepath.Join(nodeModules, dependencyName)) {
			return true
		}
	}
	return
}

// If we don't get any statues it means the applicability scanner didn't run -> final value is not scanned
// If at least one cve is applicable -> final value is applicable
// Else if at least one cve is undetermined -> final value is undetermined
// Else if at least one cve is missing context -> final value is missing context
// Else if all cves are not covered -> final value is not covered
// Else (case when all cves aren't applicable) -> final value is not applicable
func getFinalApplicabilityStatus(applicabilityStatuses []jasutils.ApplicabilityStatus) jasutils.ApplicabilityStatus {
	if len(applicabilityStatuses) == 0 {
		return jasutils.NotScanned
	}
	foundUndetermined := false
	foundMissingContext := false
	foundNotCovered := false
	for _, status := range applicabilityStatuses {
		if status == jasutils.Applicable {
			return jasutils.Applicable
		}
		if status == jasutils.ApplicabilityUndetermined {
			foundUndetermined = true
		}
		if status == jasutils.MissingContext {
			foundMissingContext = true
		}
		if status == jasutils.NotCovered {
			foundNotCovered = true
		}

	}
	if foundUndetermined {
		return jasutils.ApplicabilityUndetermined
	}
	if foundMissingContext {
		return jasutils.MissingContext
	}
	if foundNotCovered {
		return jasutils.NotCovered
	}

	return jasutils.NotApplicable
}

func GetJasResultApplicability(result *sarif.Result) *formats.Applicability {
	status := sarifutils.GetResultPropertyTokenValidation(result)
	statusDescription := sarifutils.GetResultPropertyMetadata(result)
	if status == "" && statusDescription == "" {
		return nil
	}
	return &formats.Applicability{Status: status, ScannerDescription: statusDescription}
}

func ConvertPolicesToString(policies []services.Policy) []string {
	var policiesStr []string
	for _, policy := range policies {
		policiesStr = append(policiesStr, policy.Policy)
	}
	return policiesStr
}

func ScanResultsToRuns(results []ScanResult[[]*sarif.Run]) (runs []*sarif.Run) {
	for _, result := range results {
		runs = append(runs, result.Scan...)
	}
	return
}

// Resolve the actual technology from multiple sources:
func GetIssueTechnology(responseTechnology string, targetTech techutils.Technology) techutils.Technology {
	if responseTechnology != "" && responseTechnology != "generic" && (targetTech == "" || targetTech == "generic") {
		// technology returned in the vulnerability/violation obj is the most specific technology
		return techutils.ToTechnology(responseTechnology)
	}
	// if no technology is provided, use the target technology
	return targetTech
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

// This function gets a list of xray scan responses that contain direct and indirect vulnerabilities and returns separate
// lists of the direct and indirect CVEs
func ExtractCvesFromScanResponse(xrayScanResults []services.ScanResponse, directDependencies []string) (directCves []string, indirectCves []string) {
	directCvesSet := datastructures.MakeSet[string]()
	indirectCvesSet := datastructures.MakeSet[string]()
	for _, scanResult := range xrayScanResults {
		for _, vulnerability := range scanResult.Vulnerabilities {
			if isDirectComponents(maps.Keys(vulnerability.Components), directDependencies) {
				addCvesToSet(vulnerability.Cves, directCvesSet)
			} else {
				addCvesToSet(vulnerability.Cves, indirectCvesSet)
			}
		}
		for _, violation := range scanResult.Violations {
			if isDirectComponents(maps.Keys(violation.Components), directDependencies) {
				addCvesToSet(violation.Cves, directCvesSet)
			} else {
				addCvesToSet(violation.Cves, indirectCvesSet)
			}
		}
	}

	return directCvesSet.ToSlice(), indirectCvesSet.ToSlice()
}

func ExtractCdxDependenciesCves(bom *cyclonedx.BOM) (directCves []string, indirectCves []string) {
	if bom == nil || bom.Components == nil || bom.Vulnerabilities == nil {
		return
	}
	directCvesSet := datastructures.MakeSet[string]()
	indirectCvesSet := datastructures.MakeSet[string]()
	for _, vulnerability := range *bom.Vulnerabilities {
		if vulnerability.Affects == nil || len(*vulnerability.Affects) == 0 {
			// No affected components, skip this vulnerability
			continue
		}
		for _, affectedComponent := range *vulnerability.Affects {
			relation := cdxutils.GetComponentRelation(bom, affectedComponent.Ref, true)
			if relation == cdxutils.TransitiveRelation {
				indirectCvesSet.Add(vulnerability.BOMRef)
			} else {
				// All other relations are considered direct
				directCvesSet.Add(vulnerability.BOMRef)
			}
		}
	}
	return directCvesSet.ToSlice(), indirectCvesSet.ToSlice()
}

func isDirectComponents(components []string, directDependencies []string) bool {
	for _, component := range components {
		if slices.Contains(directDependencies, component) {
			return true
		}
	}
	return false
}

func addCvesToSet(cves []services.Cve, set *datastructures.Set[string]) {
	for _, cve := range cves {
		if cve.Id != "" {
			set.Add(cve.Id)
		}
	}
}

func GetTargetDirectDependencies(targetResult *TargetResults, flatTree, convertToXrayCompId bool) (slice []string) {
	slice = []string{}
	if targetResult.ScaResults == nil || targetResult.ScaResults.Sbom == nil || targetResult.ScaResults.Sbom.Components == nil || targetResult.ScaResults.Sbom.Dependencies == nil {
		return
	}
	if flatTree {
		// If the flat tree is requested, we will use the flat tree of the SBOM
		if root := BomToFlatTree(targetResult.ScaResults.Sbom, convertToXrayCompId); root != nil {
			for _, component := range root.Nodes {
				if component != nil && component.Id != "" {
					// Add the component ID to the slice
					slice = append(slice, component.Id)
				}
			}
		}
		return
	}
	// Translate refs to IDs
	directIdsSet := datastructures.MakeSet[string]()
	for _, root := range cdxutils.GetRootDependenciesEntries(targetResult.ScaResults.Sbom, true) {
		if root.Dependencies == nil || len(*root.Dependencies) == 0 {
			continue
		}
		// Collect the IDs of the direct dependencies
		for _, directDepRef := range *root.Dependencies {
			if component := cdxutils.SearchComponentByRef(targetResult.ScaResults.Sbom.Components, directDepRef); component != nil {
				directIdsSet.Add(techutils.PurlToXrayComponentId(component.PackageURL))
			}
		}
	}
	return directIdsSet.ToSlice()
}

// func extract

func SearchTargetResultsByRelativePath(relativeTarget string, resultsToCompare *SecurityCommandResults) (targetResults *TargetResults) {
	if resultsToCompare == nil {
		return
	}
	// Results to compare could be a results from the same path or a relative path
	sourceBasePath := resultsToCompare.GetCommonParentPath()
	var best *TargetResults
	log.Debug(fmt.Sprintf("Searching for target %s in results with base path %s", relativeTarget, sourceBasePath))
	for _, potential := range resultsToCompare.Targets {
		log.Debug(fmt.Sprintf("Comparing target %s with relative target %s, relative: %s", potential.Target, relativeTarget, utils.GetRelativePath(potential.Target, sourceBasePath)))
		if relativeTarget == potential.Target {
			// If the target is exactly the same, return it
			return potential
		}
		// Check if the target is a relative path of the source base path
		if relative := utils.GetRelativePath(potential.Target, sourceBasePath); relativeTarget == relative {
			// Check if this is the best match so far
			if best == nil || len(best.Target) > len(potential.Target) {
				best = potential
			}
		}
	}
	return best
}

func DepsTreeToSbom(trees ...*xrayUtils.GraphNode) (components *[]cyclonedx.Component, dependencies *[]cyclonedx.Dependency) {
	parsed := datastructures.MakeSet[string]()
	components = &[]cyclonedx.Component{}
	dependencies = &[]cyclonedx.Dependency{}
	for _, root := range trees {
		components, dependencies = getDataFromNode(root, parsed, components, dependencies)
	}
	if len(*components) == 0 {
		components = nil
	}
	if len(*dependencies) == 0 {
		dependencies = nil
	}
	return
}

func getDataFromNode(node *xrayUtils.GraphNode, parsed *datastructures.Set[string], components *[]cyclonedx.Component, dependencies *[]cyclonedx.Dependency) (*[]cyclonedx.Component, *[]cyclonedx.Dependency) {
	if parsed.Exists(node.Id) {
		// The node was already parsed, no need to parse it again
		return components, dependencies
	}
	parsed.Add(node.Id)
	// Create a new component and add it to the sbom
	*components = append(*components, CreateScaComponentFromXrayCompId(node.Id))
	if len(node.Nodes) > 0 {
		// Create a matching dependency entry describing the direct dependencies
		*dependencies = append(*dependencies, cyclonedx.Dependency{
			Ref:          techutils.XrayComponentIdToCdxComponentRef(node.Id),
			Dependencies: getNodeDirectDependencies(node),
		})
	}
	// Go through the dependencies and add them to the sbom
	for _, dependencyNode := range node.Nodes {
		components, dependencies = getDataFromNode(dependencyNode, parsed, components, dependencies)
	}
	return components, dependencies
}

func getNodeDirectDependencies(node *xrayUtils.GraphNode) (dependencies *[]string) {
	dependencies = &[]string{}
	for _, dep := range node.Nodes {
		*dependencies = append(*dependencies, techutils.XrayComponentIdToCdxComponentRef(dep.Id))
	}
	return
}

func CreateScaComponentFromXrayCompId(xrayImpactedPackageId string, properties ...cyclonedx.Property) (component cyclonedx.Component) {
	compName, compVersion, compType := techutils.SplitComponentIdRaw(xrayImpactedPackageId)
	component = cyclonedx.Component{
		BOMRef:     techutils.XrayComponentIdToCdxComponentRef(xrayImpactedPackageId),
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       compName,
		Version:    compVersion,
		PackageURL: techutils.ToPackageUrl(compName, compVersion, techutils.ToCdxPackageType(compType)),
	}
	component.Properties = cdxutils.AppendProperties(component.Properties, properties...)
	return
}

func CreateScaComponentFromBinaryNode(node *xrayUtils.BinaryGraphNode) (component cyclonedx.Component) {
	// Create the component
	component = CreateScaComponentFromXrayCompId(node.Id)

	// Add license information to the component if it exists
	licenses := cyclonedx.Licenses{}
	for _, license := range node.Licenses {
		if license == "" {
			continue
		}
		licenses = append(licenses, cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: license}})
	}
	if len(licenses) > 0 {
		component.Licenses = &licenses
	}

	// Add the path property if it exists
	if node.Path != "" {
		cdxutils.AttachEvidenceOccurrenceToComponent(&component, cyclonedx.EvidenceOccurrence{Location: node.Path})
	}

	if node.Sha1 == "" && node.Sha256 == "" {
		return
	}

	// Add hashes to the component if they exist
	hashes := []cyclonedx.Hash{}
	if node.Sha1 != "" {
		hashes = append(hashes, cyclonedx.Hash{Algorithm: cyclonedx.HashAlgoSHA1, Value: node.Sha1})
	}
	if node.Sha256 != "" {
		hashes = append(hashes, cyclonedx.Hash{Algorithm: cyclonedx.HashAlgoSHA256, Value: node.Sha256})
	}
	if len(hashes) > 0 {
		component.Hashes = &hashes
	}
	return
}

func CompTreeToSbom(trees ...*xrayUtils.BinaryGraphNode) (components *[]cyclonedx.Component, dependencies *[]cyclonedx.Dependency) {
	parsed := datastructures.MakeSet[string]()
	components = &[]cyclonedx.Component{}
	dependencies = &[]cyclonedx.Dependency{}
	for _, root := range trees {
		components, dependencies = getDataFromBinaryNode(root, parsed, components, dependencies)
	}
	if len(*components) == 0 {
		components = nil
	}
	if len(*dependencies) == 0 {
		dependencies = nil
	}
	return
}

func getDataFromBinaryNode(node *xrayUtils.BinaryGraphNode, parsed *datastructures.Set[string], components *[]cyclonedx.Component, dependencies *[]cyclonedx.Dependency) (*[]cyclonedx.Component, *[]cyclonedx.Dependency) {
	if parsed.Exists(node.Id) {
		// The node was already parsed, no need to parse it again
		return components, dependencies
	}
	parsed.Add(node.Id)
	// Create a new component and add it to the sbom
	*components = append(*components, CreateScaComponentFromBinaryNode(node))
	if len(node.Nodes) > 0 {
		// Create a matching dependency entry describing the direct dependencies
		*dependencies = append(*dependencies, cyclonedx.Dependency{Ref: techutils.XrayComponentIdToCdxComponentRef(node.Id), Dependencies: getBinaryNodeDirectDependencies(node)})
	}
	// Go through the dependencies and add them to the sbom
	for _, dependencyNode := range node.Nodes {
		components, dependencies = getDataFromBinaryNode(dependencyNode, parsed, components, dependencies)
	}
	return components, dependencies
}

func getBinaryNodeDirectDependencies(node *xrayUtils.BinaryGraphNode) (dependencies *[]string) {
	dependencies = &[]string{}
	for _, dep := range node.Nodes {
		*dependencies = append(*dependencies, techutils.XrayComponentIdToCdxComponentRef(dep.Id))
	}
	return
}

func IsMultiProject(sbom *cyclonedx.BOM) bool {
	if sbom == nil || sbom.Dependencies == nil {
		// No dependencies or components in the SBOM, return false
		return false
	}
	return len(cdxutils.GetRootDependenciesEntries(sbom, false)) > 1
}

func BomToTree(sbom *cyclonedx.BOM) (flatTree *xrayUtils.GraphNode, fullDependencyTrees []*xrayUtils.GraphNode) {
	return BomToFlatTree(sbom, true), BomToFullTree(sbom, true)
}

func BomToFlatTree(sbom *cyclonedx.BOM, convertToXrayCompId bool) (flatTree *xrayUtils.GraphNode) {
	flatTree = &xrayUtils.GraphNode{Id: "root"}
	if sbom == nil || sbom.Components == nil {
		return
	}
	components := datastructures.MakeSet[string]()
	// Collect all components as Xray component IDs and create a node in the flat tree
	for _, component := range *sbom.Components {
		if component.Type != cyclonedx.ComponentTypeLibrary {
			// We are only interested in libraries for the dependency tree
			continue
		}
		// Get the component ID
		id := component.PackageURL
		if convertToXrayCompId {
			id = techutils.PurlToXrayComponentId(id)
		}
		if components.Exists(id) {
			continue
		}
		components.Add(id)
		flatTree.Nodes = append(flatTree.Nodes, &xrayUtils.GraphNode{Id: id, Parent: flatTree})
	}
	return
}

func BomToFullTree(sbom *cyclonedx.BOM, convertToXrayCompId bool) (fullDependencyTrees []*xrayUtils.GraphNode) {
	if sbom == nil || sbom.Dependencies == nil {
		// No dependencies or components in the SBOM, return an empty slice
		return
	}
	for _, rootEntry := range cdxutils.GetRootDependenciesEntries(sbom, false) {
		// Create a new GraphNode with ref as the ID, when populating the tree we need to use the ref as the ID
		currentTree := &xrayUtils.GraphNode{Id: rootEntry.Ref}
		populateDepsNodeDataFromBom(currentTree, sbom.Dependencies)
		fullDependencyTrees = append(fullDependencyTrees, currentTree)
	}
	// Translate refs to Purl/Xray IDs
	for _, node := range fullDependencyTrees {
		convertRefsToPackageID(node, convertToXrayCompId, *sbom.Components...)
	}
	return
}

func populateDepsNodeDataFromBom(node *xrayUtils.GraphNode, dependencies *[]cyclonedx.Dependency) {
	if node == nil || node.NodeHasLoop() {
		// If the node is nil or has a loop, return
		return
	}
	for _, dep := range cdxutils.GetDirectDependencies(dependencies, node.Id) {
		depNode := &xrayUtils.GraphNode{Id: dep, Parent: node}
		// Add the dependency to the current node
		node.Nodes = append(node.Nodes, depNode)
		// Recursively populate the node data
		populateDepsNodeDataFromBom(depNode, dependencies)
	}
}

func convertRefsToPackageID(node *xrayUtils.GraphNode, convertToXrayCompId bool, components ...cyclonedx.Component) {
	if node == nil {
		return
	}
	if component := cdxutils.SearchComponentByRef(&components, node.Id); component != nil {
		node.Id = component.PackageURL
		if convertToXrayCompId {
			node.Id = techutils.PurlToXrayComponentId(node.Id)
		}
	}
	for _, dep := range node.Nodes {
		convertRefsToPackageID(dep, convertToXrayCompId, components...)
	}
}

func BomToFullCompTree(sbom *cyclonedx.BOM, isBuildInfoXray bool) (fullDependencyTrees []*xrayUtils.BinaryGraphNode) {
	if sbom == nil || sbom.Components == nil {
		// No dependencies or components in the SBOM, return an empty slice
		return
	}
	for _, rootEntry := range cdxutils.GetRootDependenciesEntries(sbom, true) {
		// Create a new GraphNode with ref as the ID
		currentTree := toBinaryNode(sbom, rootEntry.Ref)
		// Populate application tree
		populateBinaryNodeDataFromBom(currentTree, sbom)
		// Add the tree to the output list
		fullDependencyTrees = append(fullDependencyTrees, currentTree)
	}
	// Translate refs to IDs
	for _, node := range fullDependencyTrees {
		convertBinaryRefsToPackageID(node, isBuildInfoXray, *sbom.Components...)
	}
	return
}

func populateBinaryNodeDataFromBom(node *xrayUtils.BinaryGraphNode, sbom *cyclonedx.BOM) {
	if node == nil {
		return
	}
	for _, dep := range cdxutils.GetDirectDependencies(sbom.Dependencies, node.Id) {
		depNode := toBinaryNode(sbom, dep)
		// Add the dependency to the current node
		node.Nodes = append(node.Nodes, depNode)
		// Recursively populate the node data
		populateBinaryNodeDataFromBom(depNode, sbom)
	}
}

func toBinaryNode(sbom *cyclonedx.BOM, ref string) *xrayUtils.BinaryGraphNode {
	component := cdxutils.SearchComponentByRef(sbom.Components, ref)
	if component == nil {
		log.Debug("Binary Component with ref %s not found in SBOM, skipping.", ref)
		return nil
	}
	// Create a new BinaryGraphNode and set its ID
	node := &xrayUtils.BinaryGraphNode{Id: component.BOMRef}
	if component.Licenses != nil {
		// Add the licenses to the node
		for _, license := range *component.Licenses {
			if license.License != nil && license.License.ID != "" {
				node.Licenses = append(node.Licenses, license.License.ID)
			}
		}
	}
	if component.Hashes != nil {
		// Add the hashes to the node
		for _, hash := range *component.Hashes {
			switch hash.Algorithm {
			case cyclonedx.HashAlgoSHA1:
				node.Sha1 = hash.Value
			case cyclonedx.HashAlgoSHA256:
				node.Sha256 = hash.Value
			}
		}
	}
	if component.Evidence != nil && component.Evidence.Occurrences != nil && len(*component.Evidence.Occurrences) > 0 {
		// Add the path property if it exists
		if len(*component.Evidence.Occurrences) > 1 {
			log.Warn(fmt.Sprintf("Multiple occurrences found for component %s, using the first one.", component.BOMRef))
		}
		node.Path = (*component.Evidence.Occurrences)[0].Location
	}
	return node
}

func convertBinaryRefsToPackageID(node *xrayUtils.BinaryGraphNode, isBuildInfoXray bool, components ...cyclonedx.Component) {
	if node == nil {
		return
	}
	if component := cdxutils.SearchComponentByRef(&components, node.Id); component != nil {
		node.Id = component.PackageURL
		if isBuildInfoXray {
			node.Id = techutils.PurlToXrayComponentId(node.Id)
		}
	}
	for _, dep := range node.Nodes {
		convertBinaryRefsToPackageID(dep, isBuildInfoXray, components...)
	}
}

func ScanResponseToSbom(destination *cyclonedx.BOM, scanResponse services.ScanResponse) (err error) {
	target := ScanTarget{}
	if err = ForEachScanGraphVulnerability(target, scanResponse.Vulnerabilities, false, []*sarif.Run{}, ParseScanGraphVulnerabilityToSbom(destination)); err != nil {
		return
	}
	return ForEachLicense(target, scanResponse.Licenses, ParseScanGraphLicenseToSbom(destination))
}

func ParseScanGraphLicenseToSbom(destination *cyclonedx.BOM) ParseLicenseFunc {
	return func(license services.License, impactedPackagesId string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		// Add the license related component if it is not already existing
		affectedComponent := GetOrCreateScaComponent(destination, impactedPackagesId)
		// Attach the license to the component
		cdxutils.AttachLicenseToComponent(affectedComponent, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				ID:   license.Key,
				Name: license.Name,
			},
		})
		return nil
	}
}

func ParseScanGraphVulnerabilityToSbom(destination *cyclonedx.BOM) ParseScanGraphVulnerabilityFunc {
	// Prepare the information needed to create the SCA vulnerability
	xrayService := &cyclonedx.Service{Name: utils.XrayToolName}
	return func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesId string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error {
		// Add the vulnerability related component if it is not already existing
		affectedComponent := GetOrCreateScaComponent(destination, impactedPackagesId)
		// Extract the vulnerability CVE's information and create the SCA vulnerability for each
		cveIds, applicability, cwes, ratings := ExtractIssuesInfoForCdx(vulnerability.IssueId, cves, severity, applicabilityStatus, xrayService)
		extendedInformation := ""
		if vulnerability.ExtendedInformation != nil {
			extendedInformation = vulnerability.ExtendedInformation.FullDescription
		}
		for i := 0; i < len(cveIds); i++ {
			params := cdxutils.CdxVulnerabilityParams{
				Ref:         cveIds[i],
				Ratings:     ratings[i],
				CWE:         cwes[i],
				ID:          vulnerability.IssueId,
				Description: vulnerability.Summary,
				Details:     extendedInformation,
				References:  vulnerability.References,
				Service:     xrayService,
			}
			vulnerability := cdxutils.GetOrCreateScaIssue(destination, params)
			// Attach the affected impacted library component to the vulnerability
			cdxutils.AttachComponentAffects(vulnerability, *affectedComponent, func(affectedComponent cyclonedx.Component) cyclonedx.Affects {
				return cdxutils.CreateScaImpactedAffects(affectedComponent, fixedVersion)
			})
			// Attach JAS information to the vulnerability
			AttachApplicabilityToVulnerability(destination, vulnerability, applicability[i])
		}
		return nil
	}
}

func AttachApplicabilityToVulnerability(destination *cyclonedx.BOM, vulnerability *cyclonedx.Vulnerability, applicability *formats.Applicability) {
	if applicability == nil || applicability.Status == jasutils.NotScanned.String() || vulnerability == nil {
		// No applicability to attach
		return
	}
	// Add standard cyclonedx vulnerability analysis attribute if it does not exist
	if vulnerability.Analysis == nil {
		vulnerability.Analysis = getVulnerabilityAnalysis(applicability)
	}
	// Add JFrog specific CA properties to the vulnerability
	vulnerability.Properties = cdxutils.AppendProperties(vulnerability.Properties, cyclonedx.Property{
		Name:  ApplicabilityStatusPropertyName,
		Value: applicability.Status,
	})
	for _, evidence := range applicability.Evidence {
		// Get or create the file component from the BOM
		fileComponent := GetOrCreateFileComponent(destination, evidence.File)
		// Attach the fileComponent evidence affects to the vulnerability and add the evidence snippet
		AddFileIssueAffects(vulnerability, *fileComponent,
			cyclonedx.Property{
				Name:  fmt.Sprintf(ApplicabilityEvidencePropertyTemplate, fileComponent.BOMRef, evidence.StartLine, evidence.StartColumn, evidence.EndLine, evidence.EndColumn),
				Value: evidence.Snippet,
			},
			cyclonedx.Property{
				Name:  fmt.Sprintf(ApplicabilityEvidenceReasonPropertyTemplate, fileComponent.BOMRef, evidence.StartLine, evidence.StartColumn, evidence.EndLine, evidence.EndColumn),
				Value: evidence.Reason,
			},
		)
	}
}

func getVulnerabilityAnalysis(applicability *formats.Applicability) *cyclonedx.VulnerabilityAnalysis {
	status := jasutils.ConvertToApplicabilityStatus(applicability.Status)
	state := jasutils.ApplicabilityStatusToImpactAnalysisState(status)
	if state == nil {
		// No specific impact analysis state, return nil
		return nil
	}
	// Add justification if the status is NotApplicable
	var justification cyclonedx.ImpactAnalysisJustification
	if status == jasutils.NotApplicable {
		justification = cyclonedx.IAJCodeNotReachable
	}
	// Create a new vulnerability analysis with the applicability status
	return &cyclonedx.VulnerabilityAnalysis{
		State:         *state,
		Detail:        applicability.ScannerDescription,
		Justification: justification,
	}
}

func GetOrCreateFileComponent(destination *cyclonedx.BOM, filePathOrUri string) (component *cyclonedx.Component) {
	if component = cdxutils.SearchComponentByRef(destination.Components, cdxutils.GetFileRef(filePathOrUri)); component != nil {
		return
	}
	if destination.Components == nil {
		destination.Components = &[]cyclonedx.Component{}
	}
	*destination.Components = append(*destination.Components, cdxutils.CreateFileOrDirComponent(filePathOrUri))
	return &(*destination.Components)[len(*destination.Components)-1]
}

func AddFileIssueAffects(issue *cyclonedx.Vulnerability, fileComponent cyclonedx.Component, properties ...cyclonedx.Property) {
	cdxutils.AttachComponentAffects(issue, fileComponent, func(affectedComponent cyclonedx.Component) cyclonedx.Affects {
		return cyclonedx.Affects{Ref: affectedComponent.BOMRef}
	}, properties...)
}

func ExtractIssuesInfoForCdx(issueId string, cves []formats.CveRow, severity severityutils.Severity, applicabilityStatus jasutils.ApplicabilityStatus, service *cyclonedx.Service) (cveIds []string, statuses []*formats.Applicability, cwe [][]string, ratings [][]cyclonedx.VulnerabilityRating) {
	if len(cves) == 0 {
		cveIds = append(cveIds, issueId)
		ratings = [][]cyclonedx.VulnerabilityRating{{severityutils.CreateSeverityRating(severity, applicabilityStatus, service)}}
		if applicabilityStatus != jasutils.NotScanned {
			statuses = []*formats.Applicability{{Status: string(applicabilityStatus)}}
		} else {
			statuses = []*formats.Applicability{nil}
		}
		cwe = [][]string{{}}
		return
	}
	for _, cve := range cves {
		cveIds = append(cveIds, cve.Id)
		cwe = append(cwe, cve.Cwe)
		ratings = append(ratings, append(CreateCveRatings(cve), severityutils.CreateSeverityRating(severity, applicabilityStatus, service)))
		var cveApplicability *formats.Applicability
		if cve.Applicability != nil {
			cveApplicability = cve.Applicability
		} else if applicabilityStatus != jasutils.NotScanned {
			cveApplicability = &formats.Applicability{Status: applicabilityStatus.String()}
		}
		statuses = append(statuses, cveApplicability)
	}
	return
}

func CreateCveRatings(cve formats.CveRow) (ratings []cyclonedx.VulnerabilityRating) {
	if cve.CvssV2 != "" {
		ratings = append(ratings, cyclonedx.VulnerabilityRating{
			Source: &cyclonedx.Source{
				Name: utils.XrayToolName,
			},
			Score:  severityutils.GetCvssScore(cve.CvssV2),
			Vector: cve.CvssV2Vector,
			Method: cyclonedx.ScoringMethodCVSSv2,
		})
	}
	if cve.CvssV3 != "" {
		ratings = append(ratings, cyclonedx.VulnerabilityRating{
			Source: &cyclonedx.Source{
				Name: utils.XrayToolName,
			},
			Score:  severityutils.GetCvssScore(cve.CvssV3),
			Vector: cve.CvssV3Vector,
			Method: cyclonedx.ScoringMethodCVSSv3,
		})
	}
	return
}

func GetOrCreateScaComponent(destination *cyclonedx.BOM, xrayCompId string) (libComponent *cyclonedx.Component) {
	ref := techutils.XrayComponentIdToCdxComponentRef(xrayCompId)
	// Check if the component already exists in the BOM
	if component := cdxutils.SearchComponentByRef(destination.Components, ref); component != nil {
		// The component already exists, return it
		return component
	}
	// Create a new component, add it to the BOM and return it
	if destination.Components == nil {
		destination.Components = &[]cyclonedx.Component{}
	}
	component := CreateScaComponentFromXrayCompId(xrayCompId)
	*destination.Components = append(*destination.Components, component)
	return &(*destination.Components)[len(*destination.Components)-1]
}

func CdxToFixedVersions(affectedVersions *[]cyclonedx.AffectedVersions) (fixedVersion []string) {
	fixedVersion = []string{}
	if affectedVersions == nil || len(*affectedVersions) == 0 {
		return
	}
	for _, version := range *affectedVersions {
		if version.Version != "" {
			fixedVersion = append(fixedVersion, version.Version)
		}
	}
	return
}

func GetDirectDependenciesAsComponentRows(component cyclonedx.Component, components []cyclonedx.Component, dependencies []cyclonedx.Dependency) (directComponents []formats.ComponentRow) {
	for _, parent := range cdxutils.SearchParents(component.BOMRef, components, dependencies...) {
		directComponents = append(directComponents, formats.ComponentRow{
			Name:     parent.Name,
			Version:  parent.Version,
			Location: CdxEvidenceToLocation(parent.Evidence),
		})
	}
	return
}

func CdxEvidenceToLocation(evidence *cyclonedx.Evidence) (location *formats.Location) {
	if evidence == nil || evidence.Occurrences == nil || len(*evidence.Occurrences) == 0 {
		return nil
	}
	// We take the first location as the main location
	if len(*evidence.Occurrences) > 1 {
		log.Debug("Multiple locations found for component evidence, using the first one as location")
	}
	loc := (*evidence.Occurrences)[0]
	location = &formats.Location{
		File: loc.Location,
	}
	return location
}

func CdxVulnToCveRows(vulnerability cyclonedx.Vulnerability, applicability *formats.Applicability) (cveRows []formats.CveRow) {
	cwes := []string{}
	if vulnerability.CWEs != nil {
		for _, cwe := range *vulnerability.CWEs {
			cwes = append(cwes, strconv.Itoa(cwe))
		}
	}
	cvssV2 := ""
	cvssV2Vector := ""
	if rating := cdxutils.SearchRating(vulnerability.Ratings, cyclonedx.ScoringMethodCVSSv2); rating != nil {
		if rating.Score != nil {
			// convert the score to string using fmt.Sprintf to ensure it is a string
			cvssV2 = fmt.Sprintf("%v", *rating.Score)
		}
		cvssV2Vector = rating.Vector
	}
	cvssV3 := ""
	cvssV3Vector := ""
	if rating := cdxutils.SearchRating(vulnerability.Ratings, cyclonedx.ScoringMethodCVSSv3); rating != nil {
		if rating.Score != nil {
			// convert the score to string using fmt.Sprintf to ensure it is a string
			cvssV3 = fmt.Sprintf("%v", *rating.Score)
		}
		cvssV3Vector = rating.Vector
	}
	// If vulnerability ID starts with "CVE-", we consider it a CVE ID.
	if strings.HasPrefix(vulnerability.BOMRef, "CVE-") {
		cveRows = append(cveRows, formats.CveRow{
			Id:            vulnerability.BOMRef,
			Cwe:           cwes,
			Applicability: applicability,
			CvssV2:        cvssV2,
			CvssV2Vector:  cvssV2Vector,
			CvssV3:        cvssV3,
			CvssV3Vector:  cvssV3Vector,
		})
	}
	return
}
