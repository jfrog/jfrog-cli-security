package scangraph

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/sca/scan"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
)

type ScanGraphStrategy struct {
	scangraph.ScanGraphParams
}

func NewScanGraphStrategy() *ScanGraphStrategy {
	return &ScanGraphStrategy{
		ScanGraphParams: scangraph.ScanGraphParams{},
	}
}

func WithParams(params scangraph.ScanGraphParams) scan.SbomScanOption {
	return func(ss scan.SbomScanStrategy) {
		if sg, ok := ss.(*ScanGraphStrategy); ok {
			sg.ScanGraphParams = params
		}
	}
}

func (sg *ScanGraphStrategy) WithOptions(options ...scan.SbomScanOption) scan.SbomScanStrategy {
	for _, option := range options {
		option(sg)
	}
	return sg
}

func (sg *ScanGraphStrategy) PrepareStrategy() error {
	return clientutils.ValidateMinimumVersion(clientutils.Xray, sg.XrayGraphScanParams().XrayVersion, scangraph.GraphScanMinXrayVersion)
}

func (sg *ScanGraphStrategy) SbomEnrichTask(target *cyclonedx.BOM) (enriched *cyclonedx.BOM, err error) {
	scanResponse, err := sg.DeprecatedScanTask(target)
	if err != nil {
		return
	}
	// Convert the scan results to CycloneDX BOM
	enriched = target
	err = results.ScanResponseToSbom(enriched, scanResponse)
	return
}

func (sg *ScanGraphStrategy) DeprecatedScanTask(target *cyclonedx.BOM) (techResults services.ScanResponse, err error) {
	if sg.ScanGraphParams.XrayGraphScanParams().ScanType != services.Dependency {
		return services.ScanResponse{}, fmt.Errorf("scanning %s components is not supported", sg.ScanGraphParams.XrayGraphScanParams().ScanType)
	}
	// Transform the target BOM to the information needed for the scan graph.
	flatTree, fullTree := results.BomToTree(target)
	if flatTree == nil || len(flatTree.Nodes) == 0 {
		// If there is no tree, or a tree without any non-root dependencies - we don't need to scan it
		return services.ScanResponse{}, nil
	}
	sg.ScanGraphParams.XrayGraphScanParams().DependenciesGraph = flatTree
	if targetTechnology := resolveTechnologyFromBOM(target); targetTechnology != techutils.NoTech {
		// Report the technology to Xray.
		sg.ScanGraphParams.SetTechnology(targetTechnology)
		sg.ScanGraphParams.XrayGraphScanParams().Technology = targetTechnology.String()
	}
	// Send the scan graph params to run the scan.
	return runXrayDependenciesTreeScanGraph(&sg.ScanGraphParams, fullTree)
}

func resolveTechnologyFromBOM(target *cyclonedx.BOM) (tech techutils.Technology) {
	// Try to resolve the technology from the root dependencies of the BOM.
	for _, root := range cdxutils.GetRootDependenciesEntries(target, true) {
		rootTech := getDependencyTechnology(target, root)
		if rootTech != techutils.NoTech {
			return rootTech
		}
	}
	return techutils.NoTech
}

func getDependencyTechnology(target *cyclonedx.BOM, dependency cyclonedx.Dependency) (tech techutils.Technology) {
	component := cdxutils.SearchComponentByRef(target.Components, dependency.Ref)
	if component == nil {
		return techutils.NoTech
	}
	// If the component is set, we can extract the technology from its package URL.
	_, _, comType := techutils.SplitPackageURL(component.PackageURL)
	if comType != "" && comType != "generic" {
		return techutils.CdxPackageTypeToTechnology(comType)
	}
	return techutils.NoTech
}

func runXrayDependenciesTreeScanGraph(scanGraphParams *scangraph.ScanGraphParams, fullTree []*xrayClientUtils.GraphNode) (results services.ScanResponse, err error) {
	var scanResults *services.ScanResponse
	technology := scanGraphParams.Technology()
	xrayManager, err := xray.CreateXrayServiceManager(scanGraphParams.ServerDetails(), xray.WithScopedProjectKey(scanGraphParams.XrayGraphScanParams().ProjectKey))
	if err != nil {
		return
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
	// For Source code, we sent flat tree to save time, convert component flat graph and build impact paths to the scan response.
	results = buildImpactPathsForScanResponse(*scanResults, fullTree)
	return
}

// BuildImpactPathsForScanResponse builds the full impact paths for each vulnerability found in the scanResult argument, using the dependencyTrees argument.
// Returns the updated services.ScanResponse slice.
func buildImpactPathsForScanResponse(scanResult services.ScanResponse, dependencyTree []*xrayClientUtils.GraphNode) services.ScanResponse {
	if len(scanResult.Vulnerabilities) > 0 {
		buildVulnerabilitiesImpactPaths(scanResult.Vulnerabilities, dependencyTree)
	}
	if len(scanResult.Violations) > 0 {
		buildViolationsImpactPaths(scanResult.Violations, dependencyTree)
	}
	if len(scanResult.Licenses) > 0 {
		buildLicensesImpactPaths(scanResult.Licenses, dependencyTree)
	}
	return scanResult
}

func buildVulnerabilitiesImpactPaths(vulnerabilities []services.Vulnerability, dependencyTrees []*xrayClientUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, vulnerability := range vulnerabilities {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, vulnerability.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range vulnerabilities {
		updateComponentsWithImpactPaths(vulnerabilities[i].Components, issuesMap)
	}
}

func buildViolationsImpactPaths(violations []services.Violation, dependencyTrees []*xrayClientUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, violation := range violations {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, violation.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range violations {
		updateComponentsWithImpactPaths(violations[i].Components, issuesMap)
	}
}

func buildLicensesImpactPaths(licenses []services.License, dependencyTrees []*xrayClientUtils.GraphNode) {
	issuesMap := make(map[string][][]services.ImpactPathNode)
	for _, license := range licenses {
		fillIssuesMapWithEmptyImpactPaths(issuesMap, license.Components)
	}
	buildImpactPaths(issuesMap, dependencyTrees)
	for i := range licenses {
		updateComponentsWithImpactPaths(licenses[i].Components, issuesMap)
	}
}

// Initialize a map of issues empty impact paths
func fillIssuesMapWithEmptyImpactPaths(issuesImpactPathsMap map[string][][]services.ImpactPathNode, components map[string]services.Component) {
	for dependencyName := range components {
		issuesImpactPathsMap[dependencyName] = [][]services.ImpactPathNode{}
	}
}

// Set the impact paths for each issue in the map
func buildImpactPaths(issuesImpactPathsMap map[string][][]services.ImpactPathNode, dependencyTrees []*xrayClientUtils.GraphNode) {
	for _, dependency := range dependencyTrees {
		setPathsForIssues(dependency, issuesImpactPathsMap, []services.ImpactPathNode{})
	}
}

func setPathsForIssues(dependency *xrayClientUtils.GraphNode, issuesImpactPathsMap map[string][][]services.ImpactPathNode, pathFromRoot []services.ImpactPathNode) {
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
