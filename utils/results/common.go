package results

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	rootIndex                  = 0
	directDependencyIndex      = 1
	directDependencyPathLength = 2
	nodeModules                = "node_modules"
	NpmPackageTypeIdentifier   = "npm://"
)

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

func SplitComponents(impactedPackages map[string]services.Component) (impactedPackagesNames, impactedPackagesVersions, impactedPackagesTypes []string, fixedVersions [][]string, directComponents [][]formats.ComponentRow, impactPaths [][][]formats.ComponentRow, err error) {
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
		currDirectComponents, currImpactPaths := getDirectComponentsAndImpactPaths(currComp.ImpactPaths)
		directComponents = append(directComponents, currDirectComponents)
		impactPaths = append(impactPaths, currImpactPaths)
	}
	return
}

// Gets a slice of the direct dependencies or packages of the scanned component, that depends on the vulnerable package, and converts the impact paths.
func getDirectComponentsAndImpactPaths(impactPaths [][]services.ImpactPathNode) (components []formats.ComponentRow, impactPathsRows [][]formats.ComponentRow) {
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
			componentsMap[componentId] = formats.ComponentRow{Name: compName, Version: compVersion}
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

func SplitScaScanResults(results *ScanCommandResults) ([]services.Violation, []services.Vulnerability, []services.License) {
	var violations []services.Violation
	var vulnerabilities []services.Vulnerability
	var licenses []services.License
	for _, scan := range results.Scans {
		for _, scaScan := range scan.ScaResults {
			violations = append(violations, scaScan.XrayResult.Violations...)
			vulnerabilities = append(vulnerabilities, scaScan.XrayResult.Vulnerabilities...)
			licenses = append(licenses, scaScan.XrayResult.Licenses...)
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
		if rule, _ := applicabilityRun.GetRuleById(sarifutils.CveToApplicabilityRuleId(cveId)); rule != nil {
			applicability.ScannerDescription = sarifutils.GetRuleFullDescription(rule)
			status := getApplicabilityStatusFromRule(rule)
			if status != "" {
				applicabilityStatuses = append(applicabilityStatuses, status)
			}
		}
		result, _ := applicabilityRun.GetResultByRuleId(sarifutils.CveToApplicabilityRuleId(cveId))
		if result == nil {
			continue
		}
		resultFound = true
		// Add new evidences from locations
		for _, location := range result.Locations {
			fileName := sarifutils.GetRelativeLocationFileName(location, applicabilityRun.Invocations)
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
	if rule.Properties["applicability"] != nil {
		status, ok := rule.Properties["applicability"].(string)
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
		if !strings.HasPrefix(key, NpmPackageTypeIdentifier) {
			return
		}
		dependencyName := extractDependencyNameFromComponent(key, NpmPackageTypeIdentifier)
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
