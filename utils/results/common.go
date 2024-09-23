package results

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/slices"
)

const (
	customLicenseViolationId   = "custom_license_violation"
	RootIndex                  = 0
	DirectDependencyIndex      = 1
	DirectDependencyPathLength = 2
	nodeModules                = "node_modules"
)

var (
	ErrResetConvertor    = fmt.Errorf("reset must be called before parsing new scan results metadata")
	ErrNoTargetConvertor = fmt.Errorf("ParseNewTargetResults must be called before starting to parse issues")
)

func NewFailBuildError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeVulnerableBuild, ErrorMsg: "One or more of the detected violations are configured to fail the build that including them"}
}

// In case one (or more) of the violations contains the field FailBuild set to true, CliError with exit code 3 will be returned.
func CheckIfFailBuild(results []services.ScanResponse) bool {
	for _, result := range results {
		for _, violation := range result.Violations {
			if violation.FailBuild {
				return true
			}
		}
	}
	return false
}

type ParseScaVulnerabilityFunc func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type ParseScaViolationFunc func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type ParseLicensesFunc func(license services.License, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type ParseJasFunc func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) error

// PrepareJasIssues allows to iterate over the provided SARIF runs and call the provided handler for each issue to process it.
func PrepareJasIssues(runs []*sarif.Run, entitledForJas bool, handler ParseJasFunc) error {
	if !entitledForJas || handler == nil {
		return nil
	}
	for _, run := range runs {
		for _, result := range run.Results {
			severity, err := severityutils.ParseSeverity(sarifutils.GetResultLevel(result), true)
			if err != nil {
				return err
			}
			rule, err := run.GetRuleById(sarifutils.GetResultRuleId(result))
			if errorutils.CheckError(err) != nil {
				return err
			}
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

// PrepareScaVulnerabilities allows to iterate over the provided SCA security vulnerabilities and call the provided handler for each impacted component/package with a vulnerability to process it.
func PrepareScaVulnerabilities(target ScanTarget, vulnerabilities []services.Vulnerability, entitledForJas bool, applicabilityRuns []*sarif.Run, handler ParseScaVulnerabilityFunc) error {
	if handler == nil {
		return nil
	}
	for _, vulnerability := range vulnerabilities {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, fixedVersions, directComponents, impactPaths, err := SplitComponents(target.Target, vulnerability.Components)
		if err != nil {
			return err
		}
		cves, applicabilityStatus := ConvertCvesWithApplicability(vulnerability.Cves, entitledForJas, applicabilityRuns, vulnerability.Components)
		severity, err := severityutils.ParseSeverity(vulnerability.Severity, false)
		if err != nil {
			return err
		}
		for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
			if err := handler(
				vulnerability, cves, applicabilityStatus, severity,
				impactedPackagesNames[compIndex], impactedPackagesVersions[compIndex], impactedPackagesTypes[compIndex],
				fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex],
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// PrepareScaViolations allows to iterate over the provided SCA violations and call the provided handler for each impacted component/package with a violation to process it.
func PrepareScaViolations(target ScanTarget, violations []services.Violation, entitledForJas bool, applicabilityRuns []*sarif.Run, securityHandler ParseScaViolationFunc, licenseHandler ParseScaViolationFunc, operationalRiskHandler ParseScaViolationFunc) (watches []string, failBuild bool, err error) {
	if securityHandler == nil && licenseHandler == nil && operationalRiskHandler == nil {
		return
	}
	watchesSet := datastructures.MakeSet[string]()
	for _, violation := range violations {
		// Handle duplicates and general attributes
		watchesSet.Add(violation.WatchName)
		failBuild = failBuild || violation.FailBuild
		// Prepare violation information
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, fixedVersions, directComponents, impactPaths, e := SplitComponents(target.Target, violation.Components)
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
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				if e := securityHandler(
					violation, cves, applicabilityStatus, severity,
					impactedPackagesNames[compIndex], impactedPackagesVersions[compIndex], impactedPackagesTypes[compIndex],
					fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex],
				); e != nil {
					err = errors.Join(err, e)
					continue
				}
			}
		case utils.ViolationTypeLicense.String():
			if licenseHandler == nil {
				// No handler was provided for license violations
				continue
			}
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				if e := licenseHandler(
					violation, cves, applicabilityStatus, severity,
					impactedPackagesNames[compIndex], impactedPackagesVersions[compIndex], impactedPackagesTypes[compIndex],
					fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex],
				); e != nil {
					err = errors.Join(err, e)
					continue
				}
			}
		case utils.ViolationTypeOperationalRisk.String():
			if operationalRiskHandler == nil {
				// No handler was provided for operational risk violations
				continue
			}
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				if e := operationalRiskHandler(
					violation, cves, applicabilityStatus, severity,
					impactedPackagesNames[compIndex], impactedPackagesVersions[compIndex], impactedPackagesTypes[compIndex],
					fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex],
				); e != nil {
					err = errors.Join(err, e)
					continue
				}
			}
		}
	}
	watches = watchesSet.ToSlice()
	return
}

// PrepareLicenses allows to iterate over the provided licenses and call the provided handler for each component/package with a license to process it.
func PrepareLicenses(target ScanTarget, licenses []services.License, handler ParseLicensesFunc) error {
	if handler == nil {
		return nil
	}
	for _, license := range licenses {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, _, directComponents, impactPaths, err := SplitComponents(target.Target, license.Components)
		if err != nil {
			return err
		}
		for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
			if err := handler(
				license, impactedPackagesNames[compIndex], impactedPackagesVersions[compIndex], impactedPackagesTypes[compIndex], directComponents[compIndex], impactPaths[compIndex],
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func SplitComponents(target string, impactedPackages map[string]services.Component) (impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes []string, fixedVersions [][]string, directComponents [][]formats.ComponentRow, impactPaths [][][]formats.ComponentRow, err error) {
	if len(impactedPackages) == 0 {
		err = errorutils.CheckErrorf("failed while parsing the response from Xray: violation doesn't have any components")
		return
	}
	for currCompId, currComp := range impactedPackages {
		currCompName, currCompVersion, currCompType := techutils.SplitComponentId(currCompId)
		impactedPackagesNames = append(impactedPackagesNames, currCompName)
		impactedPackagesVersions = append(impactedPackagesVersions, currCompVersion)
		impactedPackagesTypes = append(impactedPackagesTypes, currCompType)
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
			compName, compVersion, _ := techutils.SplitComponentId(componentId)
			componentsMap[componentId] = formats.ComponentRow{Name: compName, Version: compVersion, Location: getComponentLocation(impactPath[impactPathIndex].FullPath, target)}
		}

		// Convert the impact path
		var compImpactPathRows []formats.ComponentRow
		for _, pathNode := range impactPath {
			nodeCompName, nodeCompVersion, _ := techutils.SplitComponentId(pathNode.ComponentId)
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
		convertedCves[i].Applicability = GetCveApplicabilityField(convertedCves[i].Id, applicabilityRuns, components)
	}
	applicabilityStatus = GetApplicableCveStatus(entitledForJas, applicabilityRuns, convertedCves)
	return
}

func convertCves(cves []services.Cve) []formats.CveRow {
	var cveRows []formats.CveRow
	for _, cveObj := range cves {
		cveRows = append(cveRows, formats.CveRow{Id: cveObj.Id, CvssV2: cveObj.CvssV2Score, CvssV3: cveObj.CvssV3Score})
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

func GetCveApplicabilityField(cveId string, applicabilityScanResults []*sarif.Run, components map[string]services.Component) *formats.Applicability {
	if len(applicabilityScanResults) == 0 {
		return nil
	}
	applicability := formats.Applicability{}
	resultFound := false
	var applicabilityStatuses []jasutils.ApplicabilityStatus
	for _, applicabilityRun := range applicabilityScanResults {
		if rule, _ := applicabilityRun.GetRuleById(jasutils.CveToApplicabilityRuleId(cveId)); rule != nil {
			applicability.ScannerDescription = sarifutils.GetRuleFullDescription(rule)
			applicability.UndeterminedReason = GetRuleUndeterminedReason(rule)
			status := getApplicabilityStatusFromRule(rule)
			if status != "" {
				applicabilityStatuses = append(applicabilityStatuses, status)
			}

		}
		result, _ := applicabilityRun.GetResultByRuleId(jasutils.CveToApplicabilityRuleId(cveId))
		if result == nil {
			continue
		}
		resultFound = true
		// Add new evidences from locations
		for _, location := range result.Locations {
			if evidence := getEvidence(components, result, location, applicabilityRun.Invocations...); evidence != nil {
				applicability.Evidence = append(applicability.Evidence, *evidence)
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

func getEvidence(components map[string]services.Component, result *sarif.Result, location *sarif.Location, invocations ...*sarif.Invocation) *formats.Evidence {
	fileName := sarifutils.GetRelativeLocationFileName(location, invocations)
	if shouldDisqualifyEvidence(components, fileName) {
		return nil
	}
	return &formats.Evidence{
		Location: formats.Location{
			File:        fileName,
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

func GetRuleUndeterminedReason(rule *sarif.ReportingDescriptor) string {
	return sarifutils.GetRuleProperty("undetermined_reason", rule)
}

func GetResultPropertyTokenValidation(result *sarif.Result) string {
	return sarifutils.GetResultProperty("tokenValidation", result)
}

func GetResultPropertyMetadata(result *sarif.Result) string {
	return sarifutils.GetResultProperty("metadata", result)
}

func getApplicabilityStatusFromRule(rule *sarif.ReportingDescriptor) jasutils.ApplicabilityStatus {
	if rule.Properties[jasutils.ApplicabilitySarifPropertyKey] != nil {
		status, ok := rule.Properties[jasutils.ApplicabilitySarifPropertyKey].(string)
		if !ok {
			log.Debug(fmt.Sprintf("Failed to get applicability status from rule properties for rule_id %s", rule.ID))
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
	return ""
}

func GetDependencyId(depName, version string) string {
	return fmt.Sprintf("%s:%s", depName, version)
}

func GetScaIssueId(depName, version, issueId string) string {
	return fmt.Sprintf("%s_%s_%s", issueId, depName, version)
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
		dependencyName, _, _ := techutils.SplitComponentId(key)
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
