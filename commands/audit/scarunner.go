package audit

import (
	"encoding/json"
	"errors"
	"fmt"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/build-info-go/utils/pythonutils"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/conan"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"golang.org/x/exp/slices"

	"os"
	"time"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/cocoapods"
	_go "github.com/jfrog/jfrog-cli-security/commands/audit/sca/go"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/java"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/npm"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/nuget"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/pnpm"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/python"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/yarn"
	"github.com/jfrog/jfrog-cli-security/utils"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/artifactory"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayCmdUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

// We can only preform SCA scan if we identified at least one technology for a target.
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

func buildDepTreeAndRunScaScan(auditParallelRunner *utils.SecurityParallelRunner, auditParams *AuditParams, cmdResults *results.SecurityCommandResults) (generalError error) {
	if len(auditParams.ScansToPerform()) > 0 && !slices.Contains(auditParams.ScansToPerform(), xrayutils.ScaScan) {
		log.Debug("Skipping SCA scan as requested by input...")
		return
	}
	if auditParams.configProfile != nil {
		if len(auditParams.configProfile.Modules) < 1 {
			// Verify Modules are not nil and contain at least one modules
			return fmt.Errorf("config profile %s has no modules. A config profile must contain at least one modules", auditParams.configProfile.ProfileName)
		}
		if !auditParams.configProfile.Modules[0].ScanConfig.EnableScaScan {
			log.Debug(fmt.Sprintf("Skipping SCA scan as requested by '%s' config profile...", auditParams.configProfile.ProfileName))
			return
		}
	}
	// Prepare
	currentWorkingDir, generalError := os.Getwd()
	if errorutils.CheckError(generalError) != nil {
		return
	}
	serverDetails, generalError := auditParams.ServerDetails()
	if generalError != nil {
		return
	}
	if !hasAtLeastOneTech(cmdResults) {
		log.Info("Couldn't determine a package manager or build tool used by this project. Skipping the SCA scan...")
		return
	}
	defer func() {
		// Make sure to return to the original working directory, buildDependencyTree may change it
		generalError = errors.Join(generalError, errorutils.CheckError(os.Chdir(currentWorkingDir)))
	}()
	// Preform SCA scans
	for _, targetResult := range cmdResults.Targets {
		if targetResult.Technology == "" {
			log.Warn(fmt.Sprintf("Couldn't determine a package manager or build tool used by this project. Skipping the SCA scan in '%s'...", targetResult.Target))
			continue
		}
		// Get the dependency tree for the technology in the working directory.
		treeResult, bdtErr := buildDependencyTree(targetResult, auditParams)
		if bdtErr != nil {
			var projectNotInstalledErr *biutils.ErrProjectNotInstalled
			if errors.As(bdtErr, &projectNotInstalledErr) {
				log.Warn(bdtErr.Error())
				continue
			}
			_ = targetResult.AddTargetError(fmt.Errorf("Failed to build dependency tree: %s", bdtErr.Error()), auditParams.AllowPartialResults())
			continue
		}
		// Create sca scan task
		auditParallelRunner.ScaScansWg.Add(1)
		// defer auditParallelRunner.ScaScansWg.Done()
		_, taskErr := auditParallelRunner.Runner.AddTaskWithError(executeScaScanTask(auditParallelRunner, serverDetails, auditParams, targetResult, treeResult), func(err error) {
			_ = targetResult.AddTargetError(fmt.Errorf("Failed to execute SCA scan: %s", err.Error()), auditParams.AllowPartialResults())
		})
		if taskErr != nil {
			_ = targetResult.AddTargetError(fmt.Errorf("Failed to create SCA scan task: %s", taskErr.Error()), auditParams.AllowPartialResults())
			auditParallelRunner.ScaScansWg.Done()
		}
	}
	return
}

func getRequestedDescriptors(params *AuditParams) map[techutils.Technology][]string {
	requestedDescriptors := map[techutils.Technology][]string{}
	if params.PipRequirementsFile() != "" {
		requestedDescriptors[techutils.Pip] = []string{params.PipRequirementsFile()}
	}
	return requestedDescriptors
}

// Preform the SCA scan for the given scan information.
func executeScaScanTask(auditParallelRunner *utils.SecurityParallelRunner, serverDetails *config.ServerDetails, auditParams *AuditParams,
	scan *results.TargetResults, treeResult *DependencyTreeResult) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer auditParallelRunner.ScaScansWg.Done()
		log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Running SCA scan for", scan.Target, "vulnerable dependencies in", scan.Target, "directory...")
		// Scan the dependency tree.
		scanResults, xrayErr := runScaWithTech(scan.Technology, auditParams, serverDetails, *treeResult.FlatTree, treeResult.FullDepTrees)
		if xrayErr != nil {
			return fmt.Errorf("%s Xray dependency tree scan request on '%s' failed:\n%s", clientutils.GetLogMsgPrefix(threadId, false), scan.Technology, xrayErr.Error())
		}
		auditParallelRunner.ResultsMu.Lock()
		scan.NewScaScanResults(scanResults...).IsMultipleRootProject = clientutils.Pointer(len(treeResult.FullDepTrees) > 1)
		addThirdPartyDependenciesToParams(auditParams, scan.Technology, treeResult.FlatTree, treeResult.FullDepTrees)
		err = dumpScanResponseToFileIfNeeded(scanResults, auditParams.scanResultsOutputDir, utils.ScaScan)
		auditParallelRunner.ResultsMu.Unlock()
		return
	}
}

func runScaWithTech(tech techutils.Technology, params *AuditParams, serverDetails *config.ServerDetails,
	flatTree xrayCmdUtils.GraphNode, fullDependencyTrees []*xrayCmdUtils.GraphNode) (techResults []services.ScanResponse, err error) {
	xrayScanGraphParams := params.createXrayGraphScanParams()
	xrayScanGraphParams.MultiScanId = params.GetMultiScanId()
	xrayScanGraphParams.XscVersion = params.GetXscVersion()

	scanGraphParams := scangraph.NewScanGraphParams().
		SetServerDetails(serverDetails).
		SetXrayGraphScanParams(xrayScanGraphParams).
		SetXrayVersion(params.GetXrayVersion()).
		SetFixableOnly(params.fixableOnly).
		SetSeverityLevel(params.minSeverityFilter.String())
	techResults, err = sca.RunXrayDependenciesTreeScanGraph(flatTree, tech, scanGraphParams)
	if err != nil {
		return
	}
	techResults = sca.BuildImpactPathsForScanResponse(techResults, fullDependencyTrees)
	return
}

func addThirdPartyDependenciesToParams(params *AuditParams, tech techutils.Technology, flatTree *xrayCmdUtils.GraphNode, fullDependencyTrees []*xrayCmdUtils.GraphNode) {
	var dependenciesForApplicabilityScan []string
	if shouldUseAllDependencies(params.thirdPartyApplicabilityScan, tech) {
		dependenciesForApplicabilityScan = getDirectDependenciesFromTree([]*xrayCmdUtils.GraphNode{flatTree})
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
func getDirectDependenciesFromTree(dependencyTrees []*xrayCmdUtils.GraphNode) []string {
	directDependencies := datastructures.MakeSet[string]()
	for _, tree := range dependencyTrees {
		for _, node := range tree.Nodes {
			directDependencies.Add(node.Id)
		}
	}
	return directDependencies.ToSlice()
}

func getCurationCacheByTech(tech techutils.Technology) (string, error) {
	if tech == techutils.Maven || tech == techutils.Go {
		return xrayutils.GetCurationCacheFolderByTech(tech)
	}
	return "", nil
}

type DependencyTreeResult struct {
	FlatTree     *xrayCmdUtils.GraphNode
	FullDepTrees []*xrayCmdUtils.GraphNode
	DownloadUrls map[string]string
}

func GetTechDependencyTree(params xrayutils.AuditParams, artifactoryServerDetails *config.ServerDetails, tech techutils.Technology) (depTreeResult DependencyTreeResult, err error) {
	logMessage := fmt.Sprintf("Calculating %s dependencies", tech.ToFormal())
	curationLogMsg, curationCacheFolder, err := getCurationCacheFolderAndLogMsg(params, tech)
	if err != nil {
		return
	}
	// In case it's not curation command these 'curationLogMsg' be empty
	logMessage += curationLogMsg
	log.Info(logMessage + "...")
	if params.Progress() != nil {
		params.Progress().SetHeadlineMsg(logMessage)
	}

	var uniqueDeps []string
	var uniqDepsWithTypes map[string]*xray.DepTreeNode
	startTime := time.Now()

	switch tech {
	case techutils.Maven, techutils.Gradle:
		depTreeResult.FullDepTrees, uniqDepsWithTypes, err = java.BuildDependencyTree(java.DepTreeParams{
			Server:                  artifactoryServerDetails,
			DepsRepo:                params.DepsRepo(),
			IsMavenDepTreeInstalled: params.IsMavenDepTreeInstalled(),
			UseWrapper:              params.UseWrapper(),
			IsCurationCmd:           params.IsCurationCmd(),
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
			depTreeResult.DownloadUrls, err = python.BuildDependencyTree(&python.AuditPython{
			Server:              artifactoryServerDetails,
			Tool:                pythonutils.PythonTool(tech),
			RemotePypiRepo:      params.DepsRepo(),
			PipRequirementsFile: params.PipRequirementsFile(),
			InstallCommandArgs:  params.InstallCommandArgs(),
			IsCurationCmd:       params.IsCurationCmd(),
		})
	case techutils.Nuget:
		depTreeResult.FullDepTrees, uniqueDeps, err = nuget.BuildDependencyTree(params)
	case techutils.Cocoapods:
		depTreeResult.FullDepTrees, uniqueDeps, err = cocoapods.BuildDependencyTree(params)
	default:
		err = errorutils.CheckErrorf("%s is currently not supported", string(tech))
	}
	if err != nil || (len(uniqueDeps) == 0 && len(uniqDepsWithTypes) == 0) {
		return
	}
	log.Debug(fmt.Sprintf("Created '%s' dependency tree with %d nodes. Elapsed time: %.1f seconds.", tech.ToFormal(), len(uniqueDeps), time.Since(startTime).Seconds()))
	if len(uniqDepsWithTypes) > 0 {
		depTreeResult.FlatTree, err = createFlatTreeWithTypes(uniqDepsWithTypes)
		return
	}
	depTreeResult.FlatTree, err = createFlatTree(uniqueDeps)
	return
}

func getCurationCacheFolderAndLogMsg(params xrayutils.AuditParams, tech techutils.Technology) (logMessage string, curationCacheFolder string, err error) {
	if !params.IsCurationCmd() {
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

func SetResolutionRepoInAuditParamsIfExists(params utils.AuditParams, tech techutils.Technology) (serverDetails *config.ServerDetails, err error) {
	if serverDetails, err = params.ServerDetails(); err != nil {
		return
	}
	if params.DepsRepo() != "" || params.IgnoreConfigFile() {
		// If the depsRepo is already set or the configuration file is ignored, there is no need to search for the configuration file.
		return
	}
	artifactoryDetails, err := artifactory.GetResolutionRepoIfExists(tech)
	if err != nil {
		return
	}
	if artifactoryDetails == nil {
		return params.ServerDetails()
	}
	// If the configuration file is found, the server details and the target repository are extracted from it.
	params.SetDepsRepo(artifactoryDetails.TargetRepository)
	params.SetServerDetails(artifactoryDetails.ServerDetails)
	serverDetails = artifactoryDetails.ServerDetails
	return
}

func createFlatTreeWithTypes(uniqueDeps map[string]*xray.DepTreeNode) (*xrayCmdUtils.GraphNode, error) {
	if err := logDeps(uniqueDeps); err != nil {
		return nil, err
	}
	var uniqueNodes []*xrayCmdUtils.GraphNode
	for uniqueDep, nodeAttr := range uniqueDeps {
		node := &xrayCmdUtils.GraphNode{Id: uniqueDep}
		if nodeAttr != nil {
			node.Types = nodeAttr.Types
			node.Classifier = nodeAttr.Classifier
		}
		uniqueNodes = append(uniqueNodes, node)
	}
	return &xrayCmdUtils.GraphNode{Id: "root", Nodes: uniqueNodes}, nil
}

func createFlatTree(uniqueDeps []string) (*xrayCmdUtils.GraphNode, error) {
	if err := logDeps(uniqueDeps); err != nil {
		return nil, err
	}
	uniqueNodes := []*xrayCmdUtils.GraphNode{}
	for _, uniqueDep := range uniqueDeps {
		uniqueNodes = append(uniqueNodes, &xrayCmdUtils.GraphNode{Id: uniqueDep})
	}
	return &xrayCmdUtils.GraphNode{Id: "root", Nodes: uniqueNodes}, nil
}

func logDeps(uniqueDeps any) (err error) {
	if log.GetLogger().GetLogLevel() != log.DEBUG {
		// Avoid printing and marshaling if not on DEBUG mode.
		return
	}
	jsonList, err := json.Marshal(uniqueDeps)
	if errorutils.CheckError(err) != nil {
		return err
	}
	log.Debug("Unique dependencies list:\n" + clientutils.IndentJsonArray(jsonList))

	return
}

// This method will change the working directory to the scan's working directory.
func buildDependencyTree(scan *results.TargetResults, params *AuditParams) (*DependencyTreeResult, error) {
	if err := os.Chdir(scan.Target); err != nil {
		return nil, errorutils.CheckError(err)
	}
	serverDetails, err := SetResolutionRepoInAuditParamsIfExists(params.AuditBasicParams, scan.Technology)
	if err != nil {
		return nil, err
	}
	treeResult, techErr := GetTechDependencyTree(params.AuditBasicParams, serverDetails, scan.Technology)
	if techErr != nil {
		return nil, fmt.Errorf("failed while building '%s' dependency tree: %w", scan.Technology, techErr)
	}
	if treeResult.FlatTree == nil || len(treeResult.FlatTree.Nodes) == 0 {
		return nil, errorutils.CheckErrorf("no dependencies were found. Please try to build your project and re-run the audit command")
	}
	return &treeResult, nil
}

// If an output dir was provided through --output-dir flag, we create in the provided path new file containing the scan results
func dumpScanResponseToFileIfNeeded(results []services.ScanResponse, scanResultsOutputDir string, scanType utils.SubScanType) (err error) {
	if scanResultsOutputDir == "" || results == nil {
		return
	}
	fileContent, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
	}
	return utils.DumpContentToFile(fileContent, scanResultsOutputDir, scanType.String())
}
