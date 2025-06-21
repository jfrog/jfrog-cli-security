package audit

import (
	"encoding/json"
	"fmt"

	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"

	"golang.org/x/exp/slices"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-security/utils"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	noComponentsFound = "Couldn't determine a package manager or build tool used by this project. Skipping the SCA scan"
)

func AddScaScansToRunner(auditParallelRunner *utils.SecurityParallelRunner, auditParams *AuditParams, cmdResults *results.SecurityCommandResults) (generalError error) {
	if !shouldRunScaScan(auditParams, cmdResults) {
		return
	}
	serverDetails, generalError := auditParams.ServerDetails()
	if generalError != nil {
		return
	}
	// Perform SCA scans
	for _, targetResult := range cmdResults.Targets {
		treeResult := getTargetCompTree(targetResult, auditParams, cmdResults)
		if treeResult == nil {
			// No tree, no scan
			continue
		}
		// Create sca scan task
		auditParallelRunner.ScaScansWg.Add(1)
		_, taskErr := auditParallelRunner.Runner.AddTaskWithError(executeScaScanTask(auditParallelRunner, serverDetails, auditParams, targetResult, treeResult), func(err error) {
			_ = targetResult.AddTargetError(fmt.Errorf("failed to execute SCA scan: %s", err.Error()), auditParams.AllowPartialResults())
		})
		if taskErr != nil {
			_ = targetResult.AddTargetError(fmt.Errorf("failed to create SCA scan task: %s", taskErr.Error()), auditParams.AllowPartialResults())
			auditParallelRunner.ScaScansWg.Done()
		}
	}
	return
}

func shouldRunScaScan(auditParams *AuditParams, cmdResults *results.SecurityCommandResults) bool {
	if len(auditParams.ScansToPerform()) > 0 && !slices.Contains(auditParams.ScansToPerform(), xrayutils.ScaScan) {
		log.Debug("Skipping SCA scan as requested by input...")
		return false
	}
	if configProfile := auditParams.AuditBasicParams.GetConfigProfile(); configProfile != nil {
		if !configProfile.Modules[0].ScanConfig.ScaScannerConfig.EnableScaScan {
			log.Debug(fmt.Sprintf("Skipping SCA scan as requested by '%s' config profile...", configProfile.ProfileName))
			return false
		}
	}
	if !hasAtLeastOneTech(cmdResults) {
		log.Info(noComponentsFound)
		return false
	}
	return true
}

func getTargetCompTree(targetResult *results.TargetResults, auditParams *AuditParams, cmdResults *results.SecurityCommandResults) (treeResult *buildinfo.DependencyTreeResult) {
	if targetResult.ScaResults == nil || targetResult.ScaResults.Sbom == nil {
		log.Warn(fmt.Sprintf("%s in '%s'...", noComponentsFound, targetResult.Target))
		return
	}
	treeResult = &buildinfo.DependencyTreeResult{}
	treeResult.FlatTree, treeResult.FullDepTrees = results.BomToTree(targetResult.ScaResults.Sbom)
	if treeResult.FlatTree == nil || len(treeResult.FlatTree.Nodes) == 0 {
		// No dependencies were found. We don't want to run the scan in this case.
		log.Debug(fmt.Sprintf("No dependencies were found in target %s. Skipping SCA", targetResult.Target))
		return nil
	}
	if !auditParams.DiffMode() {
		return
	}
	if auditParams.ResultsToCompare() == nil {
		// First scan, no diff to compare
		log.Debug(fmt.Sprintf("Diff scan - calculated dependencies tree for target %s, skipping scan part", targetResult.Target))
		return nil
	}
	// Second scan, we need to compare the dependency tree with the one from the first scan.
	treeResult, err := buildinfo.GetDiffDependencyTree(targetResult, results.SearchTargetResultsByRelativePath(utils.GetRelativePath(targetResult.Target, cmdResults.GetCommonParentPath()), auditParams.ResultsToCompare()), treeResult.FullDepTrees...)
	if err != nil {
		_ = targetResult.AddTargetError(fmt.Errorf("failed to build diff dependency tree in source branch: %s", err.Error()), auditParams.AllowPartialResults())
		return nil
	}
	return
}

// We can only perform SCA scan if we identified at least one technology for a target.
func hasAtLeastOneTech(cmdResults *results.SecurityCommandResults) bool {
	if len(cmdResults.Targets) == 0 {
		return false
	}
	for _, scan := range cmdResults.Targets {
		if scan.Technology != techutils.NoTech {
			return true
		}
	}
	return false
}

// Perform the SCA scan for the given scan information.
func executeScaScanTask(auditParallelRunner *utils.SecurityParallelRunner, serverDetails *config.ServerDetails, auditParams *AuditParams,
	scan *results.TargetResults, treeResult *buildinfo.DependencyTreeResult) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer auditParallelRunner.ScaScansWg.Done()
		log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Running SCA scan for", scan.ScanTarget.String(), "vulnerable dependencies in", scan.Target, "directory...")
		// Scan the dependency tree.
		scanResults, xrayErr := runScaWithTech(scan.Technology, auditParams, serverDetails, *treeResult.FlatTree, treeResult.FullDepTrees)

		auditParallelRunner.ResultsMu.Lock()
		defer auditParallelRunner.ResultsMu.Unlock()
		// We add the results before checking for errors, so we can display the results even if an error occurred.
		scan.NewScaScanResults(technologies.GetScaScansStatusCode(xrayErr, scanResults...), scanResults...).IsMultipleRootProject = clientutils.Pointer(len(treeResult.FullDepTrees) > 1)
		addThirdPartyDependenciesToParams(auditParams, scan.Technology, treeResult.FlatTree, treeResult.FullDepTrees)

		if xrayErr != nil {
			return fmt.Errorf("%s Xray dependency tree scan request on '%s' failed:\n%s", clientutils.GetLogMsgPrefix(threadId, false), scan.Technology, xrayErr.Error())
		}
		err = dumpScanResponseToFileIfNeeded(scanResults, auditParams.scanResultsOutputDir, utils.ScaScan, threadId)
		return
	}
}

func runScaWithTech(tech techutils.Technology, params *AuditParams, serverDetails *config.ServerDetails,
	flatTree xrayUtils.GraphNode, fullDependencyTrees []*xrayUtils.GraphNode) (techResults []services.ScanResponse, err error) {
	// Create the scan graph parameters.
	xrayScanGraphParams := params.createXrayGraphScanParams()
	xrayScanGraphParams.MultiScanId = params.GetMultiScanId()
	xrayScanGraphParams.XrayVersion = params.GetXrayVersion()
	xrayScanGraphParams.XscVersion = params.GetXscVersion()
	xrayScanGraphParams.Technology = tech.String()

	xrayScanGraphParams.DependenciesGraph = &flatTree
	scanGraphParams := scangraph.NewScanGraphParams().
		SetServerDetails(serverDetails).
		SetXrayGraphScanParams(xrayScanGraphParams).
		SetTechnology(tech).
		SetFixableOnly(params.fixableOnly).
		SetSeverityLevel(params.minSeverityFilter.String())

	log.Info(fmt.Sprintf("Scanning %d %s dependencies", len(flatTree.Nodes), tech) + "...")
	techResults, err = technologies.RunXrayDependenciesTreeScanGraph(scanGraphParams)
	if err != nil {
		return
	}
	log.Info(fmt.Sprintf("Finished '%s' dependency tree scan. %s", tech.ToFormal(), utils.GetScanFindingsLog(utils.ScaScan, len(techResults[0].Vulnerabilities), len(techResults[0].Violations))))
	techResults = BuildImpactPathsForScanResponse(techResults, fullDependencyTrees)
	return
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

func addThirdPartyDependenciesToParams(params *AuditParams, tech techutils.Technology, flatTree *xrayUtils.GraphNode, fullDependencyTrees []*xrayUtils.GraphNode) {
	var dependenciesForApplicabilityScan []string
	if shouldUseAllDependencies(params.thirdPartyApplicabilityScan, tech) {
		dependenciesForApplicabilityScan = getDirectDependenciesFromTree([]*xrayUtils.GraphNode{flatTree})
	} else {
		dependenciesForApplicabilityScan = getDirectDependenciesFromTree(fullDependencyTrees)
	}
	params.AppendDependenciesForApplicabilityScan(dependenciesForApplicabilityScan)
}

// When building pip dependency tree using pipdeptree, some of the direct dependencies are recognized as transitive and missed by the CA scanner.
// Our solution for this case is to send all dependencies to the CA scanner.
// When thirdPartyApplicabilityScan is true, use flatten graph to include all the dependencies in applicability scanning.
// Only npm is supported for this flag.
func shouldUseAllDependencies(thirdPartyApplicabilityScan bool, tech techutils.Technology) bool {
	return tech == techutils.Pip || (thirdPartyApplicabilityScan && tech == techutils.Npm)
}

// This function retrieves the dependency trees of the scanned project and extracts a set that contains only the direct dependencies.
func getDirectDependenciesFromTree(dependencyTrees []*xrayUtils.GraphNode) []string {
	directDependencies := datastructures.MakeSet[string]()
	for _, tree := range dependencyTrees {
		for _, node := range tree.Nodes {
			directDependencies.Add(node.Id)
		}
	}
	return directDependencies.ToSlice()
}

// If an output dir was provided through --output-dir flag, we create in the provided path new file containing the scan results
func dumpScanResponseToFileIfNeeded(results []services.ScanResponse, scanResultsOutputDir string, scanType utils.SubScanType, threadId int) (err error) {
	if scanResultsOutputDir == "" || results == nil {
		return
	}
	fileContent, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
	}
	return utils.DumpContentToFile(fileContent, scanResultsOutputDir, scanType.String(), threadId)
}
