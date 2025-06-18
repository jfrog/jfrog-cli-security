package buildinfo

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	biUtils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/artifactory"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"

	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/cocoapods"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/conan"
	_go "github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/go"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/java"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/npm"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/nuget"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/pnpm"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/python"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/swift"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/yarn"
)

type BuildInfoBomGenerator struct {
	Params technologies.BuildInfoBomGeneratorParams
}

func NewBuildInfoBomGenerator() *BuildInfoBomGenerator {
	return &BuildInfoBomGenerator{
		Params: technologies.BuildInfoBomGeneratorParams{},
	}
}

func WithParams(params technologies.BuildInfoBomGeneratorParams) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) error {
		bi, ok := sg.(*BuildInfoBomGenerator)
		if !ok {
			return nil
		}
		bi.Params = params
		return nil
	}
}

func (b *BuildInfoBomGenerator) PrepareGenerator(options ...bom.SbomGeneratorOption) error {
	for _, option := range options {
		if err := option(b); err != nil {
			return err
		}
	}
	return nil
}

func (b *BuildInfoBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	// Create the CycloneDX BOM
	sbom = cyclonedx.NewBOM()
	wdComponent := cdxutils.CreateFileOrDirComponent(target.Target)
	sbom.Metadata = &cyclonedx.Metadata{Component: &wdComponent}

	// Make sure to return to the original working directory, buildDependencyTree may change it
	if currentWorkingDir, generalError := os.Getwd(); errorutils.CheckError(generalError) != nil {
		err = fmt.Errorf("failed to get current working directory: %w", generalError)
		return
	} else {
		defer func() {
			generalError = errors.Join(generalError, errorutils.CheckError(os.Chdir(currentWorkingDir)))
		}()
	}
	if target.Technology == techutils.NoTech {
		log.Debug(fmt.Sprintf("No technology was detected for target '%s'. Skipping dependency tree generation.", target.Target))
		return
	}
	log.Debug(fmt.Sprintf("Generating '%s' dependency tree...", target.Target))
	treeResult, bdtErr := b.buildDependencyTree(target)
	if bdtErr != nil {
		var projectNotInstalledErr *biUtils.ErrProjectNotInstalled
		if errors.As(bdtErr, &projectNotInstalledErr) {
			log.Warn(bdtErr.Error())
			return
		}
		err = fmt.Errorf("failed to build dependency tree: %s", bdtErr.Error())
		return
	}
	sbom.Components, sbom.Dependencies = results.DepsTreeToSbom(treeResult.FullDepTrees...)
	return
}

// This method will change the working directory to the scan's working directory.
func (b *BuildInfoBomGenerator) buildDependencyTree(scan results.ScanTarget) (*DependencyTreeResult, error) {
	if err := os.Chdir(scan.Target); err != nil {
		return nil, errorutils.CheckError(err)
	}
	serverDetails, err := SetResolutionRepoInParamsIfExists(&b.Params, scan.Technology)
	if err != nil {
		return nil, err
	}
	treeResult, techErr := GetTechDependencyTree(b.Params, serverDetails, scan.Technology)
	if techErr != nil {
		return nil, fmt.Errorf("failed while building '%s' dependency tree: %w", scan.Technology, techErr)
	}
	if treeResult.FlatTree == nil || len(treeResult.FlatTree.Nodes) == 0 {
		return nil, errorutils.CheckErrorf("no dependencies were found. Please try to build your project and re-run the audit command")
	}
	return &treeResult, nil
}

type DependencyTreeResult struct {
	FlatTree     *xrayUtils.GraphNode
	FullDepTrees []*xrayUtils.GraphNode
	DownloadUrls map[string]string
}

func GetTechDependencyTree(params technologies.BuildInfoBomGeneratorParams, artifactoryServerDetails *config.ServerDetails, tech techutils.Technology) (depTreeResult DependencyTreeResult, err error) {
	logMessage := fmt.Sprintf("Calculating %s dependencies", tech.ToFormal())
	curationLogMsg, curationCacheFolder, err := getCurationCacheFolderAndLogMsg(params, tech)
	if err != nil {
		return
	}
	// In case it's not curation command these 'curationLogMsg' be empty
	logMessage += curationLogMsg
	log.Info(logMessage + "...")
	if params.Progress != nil {
		params.Progress.SetHeadlineMsg(logMessage)
	}

	var uniqueDeps []string
	var uniqDepsWithTypes map[string]*xray.DepTreeNode
	startTime := time.Now()

	switch tech {
	case techutils.Maven, techutils.Gradle:
		depTreeResult.FullDepTrees, uniqDepsWithTypes, err = java.BuildDependencyTree(java.DepTreeParams{
			Server:                  artifactoryServerDetails,
			DepsRepo:                params.DependenciesRepository,
			IsMavenDepTreeInstalled: params.IsMavenDepTreeInstalled,
			UseWrapper:              params.UseWrapper,
			IsCurationCmd:           params.IsCurationCmd,
			CurationCacheFolder:     curationCacheFolder,
		}, tech)
	case techutils.Npm:
		depTreeResult.FullDepTrees, uniqueDeps, err = npm.BuildDependencyTree(params)
	case techutils.Pnpm:
		depTreeResult.FullDepTrees, uniqueDeps, err = pnpm.BuildDependencyTree(params)
	case techutils.Conan:
		depTreeResult.FullDepTrees, uniqueDeps, err = conan.BuildDependencyTree(params)
	case techutils.Yarn:
		depTreeResult.FullDepTrees, uniqueDeps, err = yarn.BuildDependencyTree(params)
	case techutils.Go:
		depTreeResult.FullDepTrees, uniqueDeps, err = _go.BuildDependencyTree(params)
	case techutils.Pipenv, techutils.Pip, techutils.Poetry:
		depTreeResult.FullDepTrees, uniqueDeps,
			depTreeResult.DownloadUrls, err = python.BuildDependencyTree(params, tech)
	case techutils.Nuget:
		depTreeResult.FullDepTrees, uniqueDeps, err = nuget.BuildDependencyTree(params)
	case techutils.Cocoapods:
		err = clientutils.ValidateMinimumVersion(clientutils.Xray, params.XrayVersion, scangraph.CocoapodsScanMinXrayVersion)
		if err != nil {
			return depTreeResult, fmt.Errorf("your xray version %s does not allow cocoapods scanning", params.XrayVersion)
		}
		depTreeResult.FullDepTrees, uniqueDeps, err = cocoapods.BuildDependencyTree(params)
	case techutils.Swift:
		err = clientutils.ValidateMinimumVersion(clientutils.Xray, params.XrayVersion, scangraph.SwiftScanMinXrayVersion)
		if err != nil {
			return depTreeResult, fmt.Errorf("your xray version %s does not allow swift scanning", params.XrayVersion)
		}
		depTreeResult.FullDepTrees, uniqueDeps, err = swift.BuildDependencyTree(params)
	default:
		err = errorutils.CheckErrorf("%s is currently not supported", string(tech))
	}
	if err != nil || (len(uniqueDeps) == 0 && len(uniqDepsWithTypes) == 0) {
		return
	}
	log.Debug(fmt.Sprintf("Created '%s' dependency tree with %d nodes. Elapsed time: %.1f seconds.", tech.ToFormal(), getUniqueDepsCount(uniqueDeps, uniqDepsWithTypes), time.Since(startTime).Seconds()))
	if len(uniqDepsWithTypes) > 0 {
		depTreeResult.FlatTree = createFlatTreeWithTypes(uniqDepsWithTypes)
		return
	}
	depTreeResult.FlatTree = createFlatTree(uniqueDeps)
	return
}

func getUniqueDepsCount(uniqueDeps []string, uniqDepsWithTypes map[string]*xray.DepTreeNode) int {
	if len(uniqDepsWithTypes) > 0 {
		return len(uniqDepsWithTypes)
	}
	return len(uniqueDeps)
}

func getCurationCacheFolderAndLogMsg(params technologies.BuildInfoBomGeneratorParams, tech techutils.Technology) (logMessage string, curationCacheFolder string, err error) {
	if !params.IsCurationCmd {
		return
	}
	if curationCacheFolder, err = getCurationCacheByTech(tech); err != nil || curationCacheFolder == "" {
		return
	}

	dirExist, err := fileutils.IsDirExists(curationCacheFolder, false)
	if err != nil {
		return
	}

	if dirExist {
		if dirIsEmpty, scopErr := fileutils.IsDirEmpty(curationCacheFolder); scopErr != nil || !dirIsEmpty {
			err = scopErr
			return
		}
	}

	logMessage = ". Quick note: we're running our first scan on the project with curation-audit. Expect this one to take a bit longer. Subsequent scans will be faster. Thanks for your patience"

	return logMessage, curationCacheFolder, err
}

func getCurationCacheByTech(tech techutils.Technology) (string, error) {
	if tech == techutils.Maven || tech == techutils.Go {
		return utils.GetCurationCacheFolderByTech(tech)
	}
	return "", nil
}

func SetResolutionRepoInParamsIfExists(params *technologies.BuildInfoBomGeneratorParams, tech techutils.Technology) (serverDetails *config.ServerDetails, err error) {
	serverDetails = params.ServerDetails
	if params.DependenciesRepository != "" || params.IgnoreConfigFile {
		// If the depsRepo is already set or the configuration file is ignored, there is no need to search for the configuration file.
		return
	}
	artifactoryDetails, err := artifactory.GetResolutionRepoIfExists(tech)
	if err != nil {
		return
	}
	if artifactoryDetails == nil {
		return params.ServerDetails, nil
	}
	// If the configuration file is found, the server details and the target repository are extracted from it.
	params.DependenciesRepository = artifactoryDetails.TargetRepository
	params.ServerDetails = artifactoryDetails.ServerDetails
	serverDetails = artifactoryDetails.ServerDetails
	return
}

func createFlatTreeWithTypes(uniqueDeps map[string]*xray.DepTreeNode) *xrayUtils.GraphNode {
	var uniqueNodes []*xrayUtils.GraphNode
	for uniqueDep, nodeAttr := range uniqueDeps {
		node := &xrayUtils.GraphNode{Id: uniqueDep}
		if nodeAttr != nil {
			node.Types = nodeAttr.Types
			node.Classifier = nodeAttr.Classifier
		}
		uniqueNodes = append(uniqueNodes, node)
	}
	return &xrayUtils.GraphNode{Id: "root", Nodes: uniqueNodes}
}

func createFlatTree(uniqueDeps []string) *xrayUtils.GraphNode {
	uniqueNodes := []*xrayUtils.GraphNode{}
	for _, uniqueDep := range uniqueDeps {
		uniqueNodes = append(uniqueNodes, &xrayUtils.GraphNode{Id: uniqueDep})
	}
	return &xrayUtils.GraphNode{Id: "root", Nodes: uniqueNodes}
}

// Collect dependencies exists in target and not in resultsToCompare
func GetDiffDependencyTree(scanResults *results.TargetResults, resultsToCompare *results.TargetResults, fullDepTrees ...*xrayUtils.GraphNode) (*DependencyTreeResult, error) {
	if resultsToCompare == nil || resultsToCompare.ScaResults == nil || resultsToCompare.ScaResults.Sbom == nil || resultsToCompare.ScaResults.Sbom.Components == nil {
		return nil, fmt.Errorf("failed to get diff dependency tree: no results to compare")
	}
	if scanResults == nil || scanResults.ScaResults == nil || scanResults.ScaResults.Sbom == nil || scanResults.ScaResults.Sbom.Components == nil {
		return nil, fmt.Errorf("failed to get diff dependency tree: no scan results found for target %s", scanResults.Target)
	}
	log.Debug(fmt.Sprintf("Comparing %s SBOM with %s to get diff", scanResults.Target, resultsToCompare.Target))
	// Compare the dependency trees
	filterDepsMap := datastructures.MakeSet[string]()
	for _, component := range *resultsToCompare.ScaResults.Sbom.Components {
		filterDepsMap.Add(techutils.PurlToXrayComponentId(component.PackageURL))
	}
	addedDepsMap := datastructures.MakeSet[string]()
	for _, component := range *scanResults.ScaResults.Sbom.Components {
		id := techutils.PurlToXrayComponentId(component.PackageURL)
		if exists := filterDepsMap.Exists(id); !exists {
			// Dependency in scan results but not in results to compare
			addedDepsMap.Add(id)
		}
	}
	diffDepTree := DependencyTreeResult{
		FlatTree:     createFlatTree(addedDepsMap.ToSlice()),
		FullDepTrees: fullDepTrees,
	}
	return &diffDepTree, nil
}
