package results

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
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
	rootIndex                  = 0
	directDependencyIndex      = 1
	directDependencyPathLength = 2
	nodeModules                = "node_modules"
)

var (
	ConvertorResetErr   = fmt.Errorf("Reset must be called before parsing new scan results metadata")
	ConvertorNewScanErr = fmt.Errorf("ParseNewScanResultsMetadata must be called before starting to parse issues")
)

func NewFailBuildError() error {
	return coreutils.CliError{ExitCode: coreutils.ExitCodeVulnerableBuild, ErrorMsg: "One or more of the violations found are set to fail builds that include them"}
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

type PrepareScaVulnerabilityFunc func(vulnerability services.Vulnerability, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type PrepareScaViolationFunc func(violation services.Violation, cves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus, severity severityutils.Severity, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, fixedVersion []string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type PrepareLicensesFunc func(license services.License, impactedPackagesName, impactedPackagesVersion, impactedPackagesType string, directComponents []formats.ComponentRow, impactPaths [][]formats.ComponentRow) error
type PrepareJasFunc func(run *sarif.Run, rule *sarif.ReportingDescriptor, severity severityutils.Severity, result *sarif.Result, location *sarif.Location) error

func PrepareJasIssues(target string, runs []*sarif.Run, entitledForJas bool, handler PrepareJasFunc) error {
	if !entitledForJas || handler == nil {
		return nil
	}
	for _, run := range runs {
		for _, result := range run.Results {
			severity, err := severityutils.ParseSeverity(sarifutils.GetResultLevel(result), true)
			if err != nil {
				return err
			}
			rule, err := run.GetRuleById(*result.RuleID)
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

func PrepareScaVulnerabilities(target string, vulnerabilities []services.Vulnerability, pretty, entitledForJas bool, applicabilityRuns []*sarif.Run, handler PrepareScaVulnerabilityFunc) error {
	if handler == nil {
		return nil
	}
	for _, vulnerability := range vulnerabilities {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, fixedVersions, directComponents, impactPaths, err := SplitComponents(target, vulnerability.Components)
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

func PrepareScaViolations(target string, violations []services.Violation, pretty, entitledForJas bool, applicabilityRuns []*sarif.Run, securityHandler PrepareScaViolationFunc, licenseHandler PrepareScaViolationFunc, operationalRiskHandler PrepareScaViolationFunc) error {
	for _, violation := range violations {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, fixedVersions, directComponents, impactPaths, err := SplitComponents(target, violation.Components)
		if err != nil {
			return err
		}
		cves, applicabilityStatus := ConvertCvesWithApplicability(violation.Cves, entitledForJas, applicabilityRuns, violation.Components)
		severity, err := severityutils.ParseSeverity(violation.Severity, false)
		if err != nil {
			return err
		}
		switch violation.ViolationType {
		case formats.ViolationTypeSecurity.String():
			if securityHandler == nil {
				continue
			}
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				if err := securityHandler(
					violation, cves, applicabilityStatus, severity,
					impactedPackagesNames[compIndex], impactedPackagesVersions[compIndex], impactedPackagesTypes[compIndex],
					fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex],
				); err != nil {
					return err
				}
			}
		case formats.ViolationTypeLicense.String():
			if licenseHandler == nil {
				continue
			}
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				if err := licenseHandler(
					violation, cves, applicabilityStatus, severity,
					impactedPackagesNames[compIndex], impactedPackagesVersions[compIndex], impactedPackagesTypes[compIndex],
					fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex],
				); err != nil {
					return err
				}
			}
		case formats.ViolationTypeOperationalRisk.String():
			if operationalRiskHandler == nil {
				continue
			}
			for compIndex := 0; compIndex < len(impactedPackagesNames); compIndex++ {
				if err := operationalRiskHandler(
					violation, cves, applicabilityStatus, severity,
					impactedPackagesNames[compIndex], impactedPackagesVersions[compIndex], impactedPackagesTypes[compIndex],
					fixedVersions[compIndex], directComponents[compIndex], impactPaths[compIndex],
				); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func PrepareLicenses(target string, licenses []services.License, handler PrepareLicensesFunc) error {
	if handler == nil {
		return nil
	}
	for _, license := range licenses {
		impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes, _, directComponents, impactPaths, err := SplitComponents(target, license.Components)
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
			componentsMap[componentId] = formats.ComponentRow{Name: compName, Version: compVersion, Location: getComponentLocation(target)}
		}

		// Convert the impact path
		var compImpactPathRows []formats.ComponentRow
		for _, pathNode := range impactPath {
			nodeCompName, nodeCompVersion, _ := techutils.SplitComponentId(pathNode.ComponentId)
			compImpactPathRows = append(compImpactPathRows, formats.ComponentRow{
				Name:    nodeCompName,
				Version: nodeCompVersion,
			})
		}
		impactPathsRows = append(impactPathsRows, compImpactPathRows)
	}

	for _, row := range componentsMap {
		components = append(components, row)
	}
	return
}

func getComponentLocation(target string) *formats.Location {
	if target == "" {
		return nil
	}
	return &formats.Location{File: target}
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

func GetScaIssueId(depName, version, issueId string) string {
	return fmt.Sprintf("%s_%s_%s", issueId, depName, version)
}

func ConvertCvesWithApplicability(cves []services.Cve, entitledForJas bool, applicabilityRuns []*sarif.Run, components map[string]services.Component) (convertedCves []formats.CveRow, applicabilityStatus jasutils.ApplicabilityStatus) {
	convertedCves = convertCves(cves)
	applicabilityStatus = jasutils.ApplicabilityUndetermined
	if entitledForJas {
		for i := range convertedCves {
			convertedCves[i].Applicability = GetCveApplicabilityField(convertedCves[i].Id, applicabilityRuns, components)
		}
		applicabilityStatus = GetApplicableCveStatus(entitledForJas, applicabilityRuns, convertedCves)
	}
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
				ViolationType: formats.ViolationTypeLicense.String(),
			})
		}
	}
	return
}

// appendUniqueImpactPathsForMultipleRoots appends the source impact path to the target impact path while avoiding duplicates.
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
	key := path[rootIndex].ComponentId
	if len(path) == directDependencyPathLength {
		key = path[directDependencyIndex].ComponentId
	}
	return key
}

func SplitScaScanResults(results *SecurityCommandResults) ([]services.Violation, []services.Vulnerability, []services.License) {
	var violations []services.Violation
	var vulnerabilities []services.Vulnerability
	var licenses []services.License
	for _, scanTarget := range results.Targets {
		for _, scaScan := range scanTarget.ScaResults.XrayResults {
			violations = append(violations, scaScan.Violations...)
			vulnerabilities = append(vulnerabilities, scaScan.Vulnerabilities...)
			licenses = append(licenses, scaScan.Licenses...)
		}
	}
	return violations, vulnerabilities, licenses
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
			fileName := sarifutils.GetRelativeLocationFileName(location, applicabilityRun.Invocations)
			// TODO: maybe, move this logic to the convertor
			if shouldDisqualifyEvidence(components, fileName) {
				continue
			}
			applicability.Evidence = append(applicability.Evidence, formats.Evidence{
				Location: formats.Location{
					File:        fileName,
					StartLine:   sarifutils.GetLocationStartLine(location),
					StartColumn: sarifutils.GetLocationStartColumn(location),
					EndLine:     sarifutils.GetLocationEndLine(location),
					EndColumn:   sarifutils.GetLocationEndColumn(location),
					Snippet:     sarifutils.GetLocationSnippet(location),
				},
				Reason: sarifutils.GetResultMsgText(result),
			})
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

func GetApplicableCvesStatus(entitledForJas bool, applicabilityScanResults []*sarif.Run, cves ...services.Cve) jasutils.ApplicabilityStatus {
	if !entitledForJas || len(applicabilityScanResults) == 0 {
		return jasutils.NotScanned
	}
	if len(cves) == 0 {
		return jasutils.NotCovered
	}
	var applicableStatuses []jasutils.ApplicabilityStatus
	for _, cve := range cves {
		for _, applicabilityRun := range applicabilityScanResults {
			if rule, _ := applicabilityRun.GetRuleById(jasutils.CveToApplicabilityRuleId(cve.Id)); rule != nil {
				status := getApplicabilityStatusFromRule(rule)
				if status != "" {
					applicableStatuses = append(applicableStatuses, status)
				}
			}
		}
	}
	return getFinalApplicabilityStatus(applicableStatuses)

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
		}
	}
	return ""
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
		dependencyName := extractDependencyNameFromComponent(key, techutils.Npm.GetPackageTypeId())
		// Check both Unix & Windows paths.
		if strings.Contains(evidenceFilePath, nodeModules+"/"+dependencyName) || strings.Contains(evidenceFilePath, filepath.Join(nodeModules, dependencyName)) {
			return true
		}
	}
	return
}

func extractDependencyNameFromComponent(key string, techIdentifier string) (dependencyName string) {
	packageAndVersion := strings.TrimPrefix(key, techIdentifier)
	split := strings.Split(packageAndVersion, ":")
	if len(split) < 2 {
		return
	}
	dependencyName = split[0]
	return
}

// If we don't get any statues it means the applicability scanner didn't run -> final value is not scanned
// If at least one cve is applicable -> final value is applicable
// Else if at least one cve is undetermined -> final value is undetermined
// Else if all cves are not covered -> final value is not covered
// Else (case when all cves aren't applicable) -> final value is not applicable
func getFinalApplicabilityStatus(applicabilityStatuses []jasutils.ApplicabilityStatus) jasutils.ApplicabilityStatus {
	if len(applicabilityStatuses) == 0 {
		return jasutils.NotScanned
	}
	foundUndetermined := false
	foundNotCovered := false
	for _, status := range applicabilityStatuses {
		if status == jasutils.Applicable {
			return jasutils.Applicable
		}
		if status == jasutils.ApplicabilityUndetermined {
			foundUndetermined = true
		}
		if status == jasutils.NotCovered {
			foundNotCovered = true
		}
	}
	if foundUndetermined {
		return jasutils.ApplicabilityUndetermined
	}
	if foundNotCovered {
		return jasutils.NotCovered
	}
	return jasutils.NotApplicable
}
