package sca

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	buildInfoUtils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	"github.com/jfrog/jfrog-client-go/artifactory/services/fspatterns"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	// Visual Studio inner directory.
	DotVsRepoSuffix = ".vs"
)

var CurationErrorMsgToUserTemplate = "Failed to retrieve the dependencies tree for the %s project. Please contact your " +
	"Artifactory administrator to verify pass-through for Curation audit is enabled for your project"

func GetExcludePattern(params utils.AuditParams) string {
	exclusions := params.Exclusions()
	if configProfile := params.GetConfigProfile(); configProfile != nil {
		exclusions = append(exclusions, configProfile.Modules[0].ScanConfig.ScaScannerConfig.ExcludePatterns...)
	}

	if len(exclusions) == 0 {
		exclusions = append(exclusions, utils.DefaultScaExcludePatterns...)
	}
	return fspatterns.PrepareExcludePathPattern(exclusions, clientutils.WildCardPattern, params.IsRecursiveScan())
}

func RunXrayDependenciesTreeScanGraph(scanGraphParams *scangraph.ScanGraphParams) (results []services.ScanResponse, err error) {
	var scanResults *services.ScanResponse
	technology := scanGraphParams.Technology()
	xrayManager, err := xray.CreateXrayServiceManager(scanGraphParams.ServerDetails())
	if err != nil {
		return nil, err
	}
	scanResults, err = scangraph.RunScanGraphAndGetResults(scanGraphParams, xrayManager)
	if err != nil {
		err = errorutils.CheckErrorf("scanning %s dependencies failed with error: %s", technology.ToFormal(), err.Error())
		return
	}
	for i := range scanResults.Vulnerabilities {
		if scanResults.Vulnerabilities[i].Technology == "" {
			scanResults.Vulnerabilities[i].Technology = technology.String()
		}
	}
	for i := range scanResults.Violations {
		if scanResults.Violations[i].Technology == "" {
			scanResults.Violations[i].Technology = technology.String()
		}
	}
	results = append(results, *scanResults)
	return
}

// Infer the status code of SCA Xray scan, must have at least one result, if err occurred or any of the results is `failed` return 1, otherwise return 0.
func GetScaScansStatusCode(err error, results ...services.ScanResponse) int {
	if err != nil || len(results) == 0 {
		return 1
	}
	for _, result := range results {
		if result.ScannedStatus == "Failed" {
			return 1
		}
	}
	return 0
}

func CreateTestWorkspace(t *testing.T, sourceDir string) (string, func()) {
	return tests.CreateTestWorkspace(t, filepath.Join("..", "..", "..", "..", "tests", "testdata", sourceDir))
}

// GetExecutableVersion gets an executable version and prints to the debug log if possible.
// Only supported for package managers that use "--version".
func LogExecutableVersion(executable string) {
	verBytes, err := exec.Command(executable, "--version").CombinedOutput()
	if err != nil {
		log.Debug(fmt.Sprintf("'%q --version' command received an error: %s", executable, err.Error()))
		return
	}
	if len(verBytes) == 0 {
		log.Debug(fmt.Sprintf("'%q --version' command received an empty response", executable))
		return
	}
	version := strings.TrimSpace(string(verBytes))
	log.Debug(fmt.Sprintf("Used %q version: %s", executable, version))
}

// BuildImpactPathsForScanResponse builds the full impact paths for each vulnerability found in the scanResult argument, using the dependencyTrees argument.
// Returns the updated services.ScanResponse slice.
func BuildImpactPathsForScanResponse(scanResult []services.ScanResponse, dependencyTree []*xrayUtils.GraphNode) []services.ScanResponse {
	for _, result := range scanResult {
		if len(result.Vulnerabilities) > 0 {
			buildVulnerabilitiesImpactPaths(result.Vulnerabilities, dependencyTree)
		}
		if len(result.Violations) > 0 {
			buildViolationsImpactPaths(result.Violations, dependencyTree)
		}
		if len(result.Licenses) > 0 {
			buildLicensesImpactPaths(result.Licenses, dependencyTree)
		}
	}
	return scanResult
}

// Initialize a map of issues empty impact paths
func fillIssuesMapWithEmptyImpactPaths(issuesImpactPathsMap map[string][][]services.ImpactPathNode, components map[string]services.Component) {
	for dependencyName := range components {
		issuesImpactPathsMap[dependencyName] = [][]services.ImpactPathNode{}
	}
}

// Set the impact paths for each issue in the map
func buildImpactPaths(issuesImpactPathsMap map[string][][]services.ImpactPathNode, dependencyTrees []*xrayUtils.GraphNode) {
	for _, dependency := range dependencyTrees {
		setPathsForIssues(dependency, issuesImpactPathsMap, []services.ImpactPathNode{})
	}
}

func buildVulnerabilitiesImpactPaths(vulnerabilities []services.Vulnerability, dependencyTrees []*xrayUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, vulnerability := range vulnerabilities {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, vulnerability.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range vulnerabilities {
		updateComponentsWithImpactPaths(vulnerabilities[i].Components, issuesMap)
	}
}

func buildViolationsImpactPaths(violations []services.Violation, dependencyTrees []*xrayUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, violation := range violations {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, violation.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range violations {
		updateComponentsWithImpactPaths(violations[i].Components, issuesMap)
	}
}

func buildLicensesImpactPaths(licenses []services.License, dependencyTrees []*xrayUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, license := range licenses {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, license.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range licenses {
		updateComponentsWithImpactPaths(licenses[i].Components, issuesMap)
	}
}

func updateComponentsWithImpactPaths(components map[string]services.Component, issuesMap map[string][][]services.ImpactPathNode) {
	for dependencyName := range components {
		updatedComponent := services.Component{
			FixedVersions: components[dependencyName].FixedVersions,
			ImpactPaths:   issuesMap[dependencyName],
			Cpes:          components[dependencyName].Cpes,
		}
		components[dependencyName] = updatedComponent
	}
}

func setPathsForIssues(dependency *xrayUtils.GraphNode, issuesImpactPathsMap map[string][][]services.ImpactPathNode, pathFromRoot []services.ImpactPathNode) {
	pathFromRoot = append(pathFromRoot, services.ImpactPathNode{ComponentId: dependency.Id})
	if _, exists := issuesImpactPathsMap[dependency.Id]; exists {
		// Create a copy of pathFromRoot to avoid modifying the original slice
		pathCopy := make([]services.ImpactPathNode, len(pathFromRoot))
		copy(pathCopy, pathFromRoot)
		issuesImpactPathsMap[dependency.Id] = append(issuesImpactPathsMap[dependency.Id], pathCopy)
	}
	for _, depChild := range dependency.Nodes {
		setPathsForIssues(depChild, issuesImpactPathsMap, pathFromRoot)
	}
}

func GetMsgToUserForCurationBlock(isCurationCmd bool, tech techutils.Technology, cmdOutput string) (msgToUser string) {
	if isCurationCmd && buildInfoUtils.IsForbiddenOutput(buildInfoUtils.PackageManager(tech.String()), cmdOutput) {
		msgToUser = fmt.Sprintf(CurationErrorMsgToUserTemplate, tech)
	}
	return
}
