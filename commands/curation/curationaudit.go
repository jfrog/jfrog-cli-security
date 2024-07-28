package curation

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/formats"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	config "github.com/jfrog/jfrog-cli-core/v2/utils/config"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/parallel"
	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	outFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/commands/audit/sca/python"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/jfrog/jfrog-client-go/auth"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	// The "blocked" represents the unapproved status that can be returned by the Curation Service for dependencies..
	blocked                = "blocked"
	BlockingReasonPolicy   = "Policy violations"
	BlockingReasonNotFound = "Package pending update"

	directRelation   = "direct"
	indirectRelation = "indirect"

	BlockMessageKey  = "jfrog packages curation"
	NotBeingFoundKey = "not being found"

	extractPoliciesRegexTemplate = "({.*?})"

	errorTemplateHeadRequest = "failed sending HEAD request to %s for package '%s:%s'. Status-code: %v. Cause: %v"

	errorTemplateUnsupportedTech = "It looks like this project uses '%s' to download its dependencies. " +
		"This package manager however isn't supported by this command."

	TotalConcurrentRequests = 10

	MinArtiPassThroughSupport = "7.82.0"
	MinArtiGolangSupport      = "7.87.0"
	MinXrayPassTHroughSupport = "3.92.0"
)

var CurationOutputFormats = []string{string(outFormat.Table), string(outFormat.Json)}

var supportedTech = map[techutils.Technology]func(ca *CurationAuditCommand) (bool, error){
	techutils.Npm: func(ca *CurationAuditCommand) (bool, error) { return true, nil },
	techutils.Pip: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Pip, utils.CurationSupportFlag, MinArtiPassThroughSupport)
	},
	techutils.Maven: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Maven, utils.CurationSupportFlag, MinArtiPassThroughSupport)
	},
	techutils.Go: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Go, utils.CurationSupportFlag, MinArtiGolangSupport)
	},
}

func (ca *CurationAuditCommand) checkSupportByVersionOrEnv(tech techutils.Technology, envName string, minArtiVersion string) (bool, error) {
	if flag, err := clientutils.GetBoolEnvValue(envName, false); flag {
		return true, nil
	} else if err != nil {
		log.Error(err)
	}
	artiVersion, serverDetails, err := ca.getRtVersionAndServiceDetails(tech)
	if err != nil {
		return false, err
	}

	_, xrayVersion, err := xray.CreateXrayServiceManagerAndGetVersion(serverDetails)
	if err != nil {
		return false, err
	}

	xrayVersionErr := clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, MinXrayPassTHroughSupport)
	rtVersionErr := clientutils.ValidateMinimumVersion(clientutils.Artifactory, artiVersion, minArtiVersion)
	if xrayVersionErr != nil || rtVersionErr != nil {
		return false, errors.Join(xrayVersionErr, rtVersionErr)
	}
	return true, nil
}

func (ca *CurationAuditCommand) getRtVersionAndServiceDetails(tech techutils.Technology) (string, *config.ServerDetails, error) {
	rtManager, serveDetails, err := ca.getRtManagerAndAuth(tech)
	if err != nil {
		return "", nil, err
	}
	rtVersion, err := rtManager.GetVersion()
	if err != nil {
		return "", nil, err
	}
	return rtVersion, serveDetails, err
}

type ErrorsResp struct {
	Errors []ErrorResp `json:"errors"`
}

type ErrorResp struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type PackageStatus struct {
	Action            string   `json:"action"`
	ParentName        string   `json:"direct_dependency_package_name"`
	ParentVersion     string   `json:"direct_dependency_package_version"`
	BlockedPackageUrl string   `json:"blocked_package_url,omitempty"`
	PackageName       string   `json:"blocked_package_name"`
	PackageVersion    string   `json:"blocked_package_version"`
	BlockingReason    string   `json:"blocking_reason"`
	DepRelation       string   `json:"dependency_relation"`
	PkgType           string   `json:"type"`
	Policy            []Policy `json:"policies,omitempty"`
}

type Policy struct {
	Policy         string `json:"policy"`
	Condition      string `json:"condition"`
	Explanation    string `json:"explanation"`
	Recommendation string `json:"recommendation"`
}

type PackageStatusTable struct {
	ParentName     string `col-name:"Direct\nDependency\nPackage\nName" auto-merge:"true"`
	ParentVersion  string `col-name:"Direct\nDependency\nPackage\nVersion" auto-merge:"true"`
	PackageName    string `col-name:"Blocked\nPackage\nName" auto-merge:"true"`
	PackageVersion string `col-name:"Blocked\nPackage\nVersion" auto-merge:"true"`
	BlockingReason string `col-name:"Blocking Reason" auto-merge:"true"`
	PkgType        string `col-name:"Package\nType" auto-merge:"true"`
	Policy         string `col-name:"Violated\nPolicy\nName"`
	Condition      string `col-name:"Violated Condition\nName"`
	Explanation    string `col-name:"Explanation"`
	Recommendation string `col-name:"Recommendation"`
}

type treeAnalyzer struct {
	rtManager            artifactory.ArtifactoryServicesManager
	extractPoliciesRegex *regexp.Regexp
	rtAuth               auth.ServiceDetails
	httpClientDetails    httputils.HttpClientDetails
	url                  string
	repo                 string
	tech                 techutils.Technology
	parallelRequests     int
	downloadUrls         map[string]string
}

type CurationAuditCommand struct {
	PackageManagerConfig *project.RepositoryConfig
	extractPoliciesRegex *regexp.Regexp
	workingDirs          []string
	OriginPath           string
	parallelRequests     int
	utils.AuditParams
}

type CurationReport struct {
	packagesStatus        []*PackageStatus
	totalNumberOfPackages int
}

func NewCurationAuditCommand() *CurationAuditCommand {
	return &CurationAuditCommand{
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		AuditParams:          &utils.AuditBasicParams{},
	}
}

func (ca *CurationAuditCommand) setPackageManagerConfig(pkgMangerConfig *project.RepositoryConfig) {
	ca.PackageManagerConfig = pkgMangerConfig
}

func (ca *CurationAuditCommand) SetWorkingDirs(dirs []string) *CurationAuditCommand {
	ca.workingDirs = dirs
	return ca
}

func (ca *CurationAuditCommand) SetParallelRequests(threads int) *CurationAuditCommand {
	ca.parallelRequests = threads
	return ca
}

func (ca *CurationAuditCommand) Run() (err error) {
	rootDir, err := os.Getwd()
	if err != nil {
		return errorutils.CheckError(err)
	}
	if len(ca.workingDirs) > 0 {
		defer func() {
			if e := errorutils.CheckError(os.Chdir(rootDir)); err == nil {
				err = e
			}
		}()
	} else {
		ca.workingDirs = append(ca.workingDirs, rootDir)
	}
	results := map[string]*CurationReport{}
	for _, workDir := range ca.workingDirs {
		var absWd string
		absWd, err = filepath.Abs(workDir)
		if err != nil {
			return errorutils.CheckError(err)
		}
		log.Info("Running curation audit on project:", absWd)
		if absWd != rootDir {
			if err = os.Chdir(absWd); err != nil {
				return errorutils.CheckError(err)
			}
		}
		// If error returned, continue to print results(if any), and return error at the end.
		if e := ca.doCurateAudit(results); e != nil {
			err = errors.Join(err, e)
		}
	}
	if ca.Progress() != nil {
		err = errors.Join(err, ca.Progress().Quit())
	}

	for projectPath, packagesStatus := range results {
		err = errors.Join(err, printResult(ca.OutputFormat(), projectPath, packagesStatus.packagesStatus))
	}

	err = errors.Join(err, utils.RecordSecurityCommandOutput(utils.ScanCommandSummaryResult{Results: convertResultsToSummary(results), Section: utils.Curation}))
	return
}

func convertResultsToSummary(results map[string]*CurationReport) formats.SummaryResults {
	summaryResults := formats.SummaryResults{}
	for projectPath, packagesStatus := range results {
		blocked := convertBlocked(packagesStatus.packagesStatus)
		approved := packagesStatus.totalNumberOfPackages - blocked.GetCountOfKeys(false)

		summaryResults.Scans = append(summaryResults.Scans, formats.ScanSummaryResult{Target: projectPath,
			CuratedPackages: &formats.CuratedPackages{
				Blocked:  blocked,
				Approved: approved,
			}})
	}
	return summaryResults
}

func convertBlocked(pkgStatus []*PackageStatus) formats.TwoLevelSummaryCount {
	blocked := formats.TwoLevelSummaryCount{}
	for _, pkg := range pkgStatus {
		for _, policy := range pkg.Policy {
			polAndCond := formatPolicyAndCond(policy.Policy, policy.Condition)
			if _, ok := blocked[polAndCond]; !ok {
				blocked[polAndCond] = formats.SummaryCount{}
			}
			uniqId := getPackageId(pkg.PackageName, pkg.PackageVersion)
			blocked[polAndCond][uniqId]++
		}
	}
	return blocked
}

func formatPolicyAndCond(policy, cond string) string {
	return fmt.Sprintf("Policy: %s, Condition: %s", policy, cond)
}

// The unique identifier of a package includes both the package name with its version and the parent package with its version
func getPackageId(packageName, packageVersion string) string {
	return fmt.Sprintf("%s:%s", packageName, packageVersion)
}

func (ca *CurationAuditCommand) doCurateAudit(results map[string]*CurationReport) error {
	techs := techutils.DetectedTechnologiesList()
	for _, tech := range techs {
		supportedFunc, ok := supportedTech[techutils.Technology(tech)]
		if !ok {
			log.Info(fmt.Sprintf(errorTemplateUnsupportedTech, tech))
			continue
		}
		supported, err := supportedFunc(ca)
		if err != nil {
			return err
		}
		if !supported {
			log.Info(fmt.Sprintf(errorTemplateUnsupportedTech, tech))
			continue
		}

		if err := ca.auditTree(techutils.Technology(tech), results); err != nil {
			return err
		}
		// clear the package manager config to avoid using the same config for the next tech
		ca.setPackageManagerConfig(nil)
		ca.AuditParams = ca.SetDepsRepo("")

	}
	return nil
}

func (ca *CurationAuditCommand) getRtManagerAndAuth(tech techutils.Technology) (rtManager artifactory.ArtifactoryServicesManager, serverDetails *config.ServerDetails, err error) {
	if ca.PackageManagerConfig == nil {
		if err = ca.SetRepo(tech); err != nil {
			return
		}
	}
	serverDetails, err = ca.PackageManagerConfig.ServerDetails()
	if err != nil {
		return
	}
	rtManager, err = rtUtils.CreateServiceManager(serverDetails, 2, 0, false)
	if err != nil {
		return
	}
	return
}

func (ca *CurationAuditCommand) getAuditParamsByTech(tech techutils.Technology) utils.AuditParams {
	switch tech {
	case techutils.Npm:
		return utils.AuditNpmParams{AuditParams: ca.AuditParams}.
			SetNpmIgnoreNodeModules(true).
			SetNpmOverwritePackageLock(true)
	case techutils.Maven:
		ca.AuditParams.SetIsMavenDepTreeInstalled(true)
	}

	return ca.AuditParams
}

func (ca *CurationAuditCommand) auditTree(tech techutils.Technology, results map[string]*CurationReport) error {
	params := ca.getAuditParamsByTech(tech)
	serverDetails, err := audit.SetResolutionRepoIfExists(params, tech)
	if err != nil {
		return err
	}
	depTreeResult, err := audit.GetTechDependencyTree(params, serverDetails, tech)
	if err != nil {
		return err
	}
	// Validate the graph isn't empty.
	if len(depTreeResult.FullDepTrees) == 0 {
		return errorutils.CheckErrorf("found no dependencies for the audited project using '%v' as the package manager", tech.String())
	}
	rtManager, serverDetails, err := ca.getRtManagerAndAuth(tech)
	if err != nil {
		return err
	}
	rtAuth, err := serverDetails.CreateArtAuthConfig()
	if err != nil {
		return err
	}
	rootNode := depTreeResult.FullDepTrees[0]
	// we don't pass artiUrl and repo as we don't want to download the package, only to get the name and version.
	_, projectName, projectScope, projectVersion := getUrlNameAndVersionByTech(tech, rootNode, nil, "", "")
	if projectName == "" {
		workPath, err := os.Getwd()
		if err != nil {
			return err
		}
		projectName = filepath.Base(workPath)
	}
	fullProjectName := projectName
	if projectVersion != "" {
		fullProjectName += ":" + projectVersion
	}
	if ca.Progress() != nil {
		ca.Progress().SetHeadlineMsg(fmt.Sprintf("Fetch curation status for %s graph with %v nodes project name: %s", tech.ToFormal(), len(depTreeResult.FlatTree.Nodes)-1, fullProjectName))
	}
	if projectScope != "" {
		projectName = projectScope + "/" + projectName
	}
	if ca.parallelRequests == 0 {
		ca.parallelRequests = cliutils.Threads
	}
	var packagesStatus []*PackageStatus
	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: ca.extractPoliciesRegex,
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 ca.PackageManagerConfig.TargetRepo(),
		tech:                 tech,
		parallelRequests:     ca.parallelRequests,
		downloadUrls:         depTreeResult.DownloadUrls,
	}

	rootNodes := map[string]struct{}{}
	for _, tree := range depTreeResult.FullDepTrees {
		rootNodes[tree.Id] = struct{}{}
	}
	// Fetch status for each node from a flatten graph which, has no duplicate nodes.
	packagesStatusMap := sync.Map{}
	// if error returned we still want to produce a report, so we don't fail the next step
	err = analyzer.fetchNodesStatus(depTreeResult.FlatTree, &packagesStatusMap, rootNodes)
	analyzer.GraphsRelations(depTreeResult.FullDepTrees, &packagesStatusMap,
		&packagesStatus)
	sort.Slice(packagesStatus, func(i, j int) bool {
		return packagesStatus[i].ParentName < packagesStatus[j].ParentName
	})
	results[strings.TrimSuffix(fmt.Sprintf("%s:%s", projectName, projectVersion), ":")] = &CurationReport{
		packagesStatus: packagesStatus,
		// We subtract 1 because the root node is not a package.
		totalNumberOfPackages: len(depTreeResult.FlatTree.Nodes) - 1,
	}
	return err
}

func printResult(format outFormat.OutputFormat, projectPath string, packagesStatus []*PackageStatus) error {
	if format == "" {
		format = outFormat.Table
	}
	log.Output(fmt.Sprintf("Found %v blocked packages for project %s", len(packagesStatus), projectPath))
	switch format {
	case outFormat.Json:
		if len(packagesStatus) > 0 {
			err := utils.PrintJson(packagesStatus)
			if err != nil {
				return err
			}
		}
	case outFormat.Table:
		pkgStatusTable := convertToPackageStatusTable(packagesStatus)
		err := coreutils.PrintTable(pkgStatusTable, "Curation", "Found 0 blocked packages", true)
		if err != nil {
			return err
		}
	}
	log.Output("\n")
	return nil
}

func convertToPackageStatusTable(packagesStatus []*PackageStatus) []PackageStatusTable {
	var pkgStatusTable []PackageStatusTable
	for index, pkgStatus := range packagesStatus {
		// We use auto-merge supported by the 'go-pretty' library. It doesn't have an option to merge lines by a group of unique fields.
		// In order to so, we make each group merge only with itself by adding or not adding space. This way, it won't be merged with the next group.
		uniqLineSep := ""
		if index%2 == 0 {
			uniqLineSep = " "
		}
		pkgTable := PackageStatusTable{
			ParentName:     pkgStatus.ParentName + uniqLineSep,
			ParentVersion:  pkgStatus.ParentVersion + uniqLineSep,
			PackageName:    pkgStatus.PackageName + uniqLineSep,
			PackageVersion: pkgStatus.PackageVersion + uniqLineSep,
			BlockingReason: pkgStatus.BlockingReason + uniqLineSep,
			PkgType:        pkgStatus.PkgType + uniqLineSep,
		}
		if len(pkgStatus.Policy) == 0 {
			pkgStatusTable = append(pkgStatusTable, pkgTable)
			continue
		}
		for _, policyCond := range pkgStatus.Policy {
			pkgTable.Policy = policyCond.Policy
			pkgTable.Explanation = policyCond.Explanation
			pkgTable.Recommendation = policyCond.Recommendation
			pkgTable.Condition = policyCond.Condition
			pkgStatusTable = append(pkgStatusTable, pkgTable)
		}
	}

	return pkgStatusTable
}

func (ca *CurationAuditCommand) CommandName() string {
	return "curation_audit"
}

func (ca *CurationAuditCommand) SetRepo(tech techutils.Technology) error {
	resolverParams, err := ca.getRepoParams(techutils.TechToProjectType[tech])
	if err != nil {
		return err
	}
	ca.setPackageManagerConfig(resolverParams)
	return nil
}

func (ca *CurationAuditCommand) getRepoParams(projectType project.ProjectType) (*project.RepositoryConfig, error) {
	configFilePath, exists, err := project.GetProjectConfFilePath(projectType)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errorutils.CheckErrorf("no config file was found! Before running the " + projectType.String() + " command on a " +
			"project for the first time, the project should be configured using the 'jf " + projectType.String() + "c' command")
	}
	vConfig, err := project.ReadConfigFile(configFilePath, project.YAML)
	if err != nil {
		return nil, err
	}
	return project.GetRepoConfigByPrefix(configFilePath, project.ProjectConfigResolverPrefix, vConfig)
}

func (nc *treeAnalyzer) GraphsRelations(fullDependenciesTrees []*xrayUtils.GraphNode, preProcessMap *sync.Map, packagesStatus *[]*PackageStatus) {
	visited := datastructures.MakeSet[string]()
	for _, node := range fullDependenciesTrees {
		nc.fillGraphRelations(node, preProcessMap,
			packagesStatus, "", "", visited, true)
	}
}

func (nc *treeAnalyzer) fillGraphRelations(node *xrayUtils.GraphNode, preProcessMap *sync.Map,
	packagesStatus *[]*PackageStatus, parent, parentVersion string, visited *datastructures.Set[string], isRoot bool) {
	for _, child := range node.Nodes {
		packageUrls, name, scope, version := getUrlNameAndVersionByTech(nc.tech, child, nc.downloadUrls, nc.url, nc.repo)
		if isRoot {
			parent = name
			parentVersion = version
			if scope != "" {
				parent = scope + "/" + parent
			}
		}
		if visited.Exists(scope + name + version + "-" + parent + parentVersion) {
			continue
		}

		visited.Add(scope + name + version + "-" + parent + parentVersion)
		for _, packageUrl := range packageUrls {
			if pkgStatus, exist := preProcessMap.Load(packageUrl); exist {
				relation := indirectRelation
				if isRoot {
					relation = directRelation
				}
				pkgStatusCast, isPkgStatus := pkgStatus.(*PackageStatus)
				if isPkgStatus {
					pkgStatusClone := *pkgStatusCast
					pkgStatusClone.DepRelation = relation
					pkgStatusClone.ParentName = parent
					pkgStatusClone.ParentVersion = parentVersion
					*packagesStatus = append(*packagesStatus, &pkgStatusClone)
				}
			}
		}
		nc.fillGraphRelations(child, preProcessMap, packagesStatus, parent, parentVersion, visited, false)
	}
}

func (nc *treeAnalyzer) fetchNodesStatus(graph *xrayUtils.GraphNode, p *sync.Map, rootNodeIds map[string]struct{}) error {
	var multiErrors error
	consumerProducer := parallel.NewBounedRunner(nc.parallelRequests, false)
	errorsQueue := clientutils.NewErrorsQueue(1)
	go func() {
		defer consumerProducer.Done()
		for _, node := range graph.Nodes {
			if _, ok := rootNodeIds[node.Id]; ok {
				continue
			}
			getTask := func(node xrayUtils.GraphNode) func(threadId int) error {
				return func(threadId int) (err error) {
					return nc.fetchNodeStatus(node, p)
				}
			}
			if _, err := consumerProducer.AddTaskWithError(getTask(*node), errorsQueue.AddError); err != nil {
				multiErrors = errors.Join(err, multiErrors)
			}
		}
	}()
	consumerProducer.Run()
	if err := errorsQueue.GetError(); err != nil {
		multiErrors = errors.Join(err, multiErrors)
	}
	return multiErrors
}

func (nc *treeAnalyzer) fetchNodeStatus(node xrayUtils.GraphNode, p *sync.Map) error {
	packageUrls, name, scope, version := getUrlNameAndVersionByTech(nc.tech, &node, nc.downloadUrls, nc.url, nc.repo)
	if len(packageUrls) == 0 {
		return nil
	}
	if scope != "" {
		name = scope + "/" + name
	}
	for _, packageUrl := range packageUrls {
		resp, _, err := nc.rtManager.Client().SendHead(packageUrl, &nc.httpClientDetails)
		if err != nil {
			if resp != nil && resp.StatusCode >= 400 {
				return errorutils.CheckErrorf(errorTemplateHeadRequest, packageUrl, name, version, resp.StatusCode, err)
			}
			if resp == nil || resp.StatusCode != http.StatusForbidden {
				return err
			}
		}
		if resp != nil && resp.StatusCode >= 400 && resp.StatusCode != http.StatusForbidden {
			return errorutils.CheckErrorf(errorTemplateHeadRequest, packageUrl, name, version, resp.StatusCode, err)
		}
		if resp.StatusCode == http.StatusForbidden {
			pkStatus, err := nc.getBlockedPackageDetails(packageUrl, name, version)
			if err != nil {
				return err
			}
			if pkStatus != nil {
				p.Store(pkStatus.BlockedPackageUrl, pkStatus)
			}
		}
	}
	return nil
}

// We try to collect curation details from GET response after HEAD request got forbidden status code.
func (nc *treeAnalyzer) getBlockedPackageDetails(packageUrl string, name string, version string) (*PackageStatus, error) {
	getResp, respBody, _, err := nc.rtManager.Client().SendGet(packageUrl, true, &nc.httpClientDetails)
	if err != nil {
		if getResp == nil {
			return nil, err
		}
		if getResp.StatusCode != http.StatusForbidden {
			return nil, errorutils.CheckErrorf(errorTemplateHeadRequest, packageUrl, name, version, getResp.StatusCode, err)
		}
	}
	if getResp.StatusCode == http.StatusForbidden {
		respError := &ErrorsResp{}
		if err := json.Unmarshal(respBody, respError); err != nil {
			return nil, errorutils.CheckError(err)
		}
		if len(respError.Errors) == 0 {
			return nil, errorutils.CheckErrorf("received 403 for unknown reason, no curation status will be presented for this package. "+
				"package name: %s, version: %s, download url: %s ", name, version, packageUrl)
		}
		// if the error message contains the curation string key, then we can be sure it got blocked by Curation service.
		if strings.Contains(strings.ToLower(respError.Errors[0].Message), BlockMessageKey) {
			blockingReason := BlockingReasonPolicy
			if strings.Contains(strings.ToLower(respError.Errors[0].Message), NotBeingFoundKey) {
				blockingReason = BlockingReasonNotFound
			}
			policies := nc.extractPoliciesFromMsg(respError)
			return &PackageStatus{
				PackageName:       name,
				PackageVersion:    version,
				BlockedPackageUrl: packageUrl,
				Action:            blocked,
				Policy:            policies,
				BlockingReason:    blockingReason,
				PkgType:           string(nc.tech),
			}, nil
		}
	}
	return nil, nil
}

// Return policies and conditions names from the FORBIDDEN HTTP error message.
// Message structure: Package %s:%s download was blocked by JFrog Packages Curation service due to the following policies violated {%s, %s, %s, %s},{%s, %s, %s, %s}.
func (nc *treeAnalyzer) extractPoliciesFromMsg(respError *ErrorsResp) []Policy {
	var policies []Policy
	msg := respError.Errors[0].Message
	allMatches := nc.extractPoliciesRegex.FindAllString(msg, -1)
	for _, match := range allMatches {
		match = strings.TrimSuffix(strings.TrimPrefix(match, "{"), "}")
		polCond := strings.Split(match, ",")
		if len(polCond) >= 2 {
			pol := polCond[0]
			cond := polCond[1]

			if len(polCond) == 4 {
				exp, rec := makeLegiblePolicyDetails(polCond[2], polCond[3])
				policies = append(policies, Policy{Policy: strings.TrimSpace(pol),
					Condition: strings.TrimSpace(cond), Explanation: strings.TrimSpace(exp), Recommendation: strings.TrimSpace(rec)})
				continue
			}
			policies = append(policies, Policy{Policy: strings.TrimSpace(pol), Condition: strings.TrimSpace(cond)})
		}
	}
	return policies
}

// Adding a new line after the headline and replace every "|" with a new line.
func makeLegiblePolicyDetails(explanation, recommendation string) (string, string) {
	explanation = strings.ReplaceAll(strings.Replace(explanation, ": ", ":\n", 1), " | ", "\n")
	recommendation = strings.ReplaceAll(strings.Replace(recommendation, ": ", ":\n", 1), " | ", "\n")
	return explanation, recommendation
}

func getUrlNameAndVersionByTech(tech techutils.Technology, node *xrayUtils.GraphNode, downloadUrlsMap map[string]string, artiUrl, repo string) (downloadUrls []string, name string, scope string, version string) {
	switch tech {
	case techutils.Npm:
		return getNpmNameScopeAndVersion(node.Id, artiUrl, repo, techutils.Npm.String())
	case techutils.Maven:
		return getMavenNameScopeAndVersion(node.Id, artiUrl, repo, node)

	case techutils.Pip:
		downloadUrls, name, version = getPythonNameVersion(node.Id, downloadUrlsMap)
		return
	case techutils.Go:
		return getGoNameScopeAndVersion(node.Id, artiUrl, repo)
	}
	return
}

func getPythonNameVersion(id string, downloadUrlsMap map[string]string) (downloadUrls []string, name, version string) {
	if downloadUrlsMap != nil {
		if dl, ok := downloadUrlsMap[id]; ok {
			downloadUrls = []string{dl}
		} else {
			log.Warn(fmt.Sprintf("couldn't find download url for node id %s", id))
		}
	}
	id = strings.TrimPrefix(id, python.PythonPackageTypeIdentifier)
	allParts := strings.Split(id, ":")
	if len(allParts) >= 2 {
		name = allParts[0]
		version = allParts[1]
	}
	return
}

// input - id: go://github.com/kennygrant/sanitize:v1.2.4
// input - repo: go
// output: downloadUrl: <artiUrl>/api/go/go/github.com/kennygrant/sanitize/@v/v1.2.4.zip
func getGoNameScopeAndVersion(id, artiUrl, repo string) (downloadUrls []string, name, scope, version string) {
	id = strings.TrimPrefix(id, techutils.Go.String()+"://")
	nameVersion := strings.Split(id, ":")
	name = nameVersion[0]
	if len(nameVersion) > 1 {
		version = nameVersion[1]
	}
	url := strings.TrimSuffix(artiUrl, "/") + "/api/go/" + repo + "/" + name + "/@v/" + version + ".zip"
	return []string{url}, name, "", version
}

// input(with classifier) - id: gav://org.apache.tomcat.embed:tomcat-embed-jasper:8.0.33-jdk15
// input - repo: libs-release
// output - downloadUrl: <arti-url>/libs-release/org/apache/tomcat/embed/tomcat-embed-jasper/8.0.33/tomcat-embed-jasper-8.0.33-jdk15.jar
func getMavenNameScopeAndVersion(id, artiUrl, repo string, node *xrayUtils.GraphNode) (downloadUrls []string, name, scope, version string) {
	id = strings.TrimPrefix(id, "gav://")
	allParts := strings.Split(id, ":")
	if len(allParts) < 3 {
		return
	}
	nameVersion := allParts[1] + "-" + allParts[2]
	versionDir := allParts[2]
	if node != nil && node.Classifier != nil && *node.Classifier != "" {
		versionDir = strings.TrimSuffix(versionDir, "-"+*node.Classifier)
	}
	packagePath := strings.Join(strings.Split(allParts[0], "."), "/") + "/" +
		allParts[1] + "/" + versionDir + "/" + nameVersion
	if node.Types != nil {
		for _, fileType := range *node.Types {
			// curation service supports maven only for jar and war file types.
			if fileType == "jar" || fileType == "war" {
				downloadUrls = append(downloadUrls, strings.TrimSuffix(artiUrl, "/")+"/"+repo+"/"+packagePath+"."+fileType)
			}

		}
	}
	return downloadUrls, strings.Join(allParts[:2], ":"), "", allParts[2]
}

// The graph holds, for each node, the component ID (xray representation)
// from which we extract the package name, version, and construct the Artifactory download URL.
func getNpmNameScopeAndVersion(id, artiUrl, repo, tech string) (downloadUrl []string, name, scope, version string) {
	id = strings.TrimPrefix(id, tech+"://")

	nameVersion := strings.Split(id, ":")
	name = nameVersion[0]
	if len(nameVersion) > 1 {
		version = nameVersion[1]
	}
	scopeSplit := strings.Split(name, "/")
	if len(scopeSplit) > 1 {
		scope = scopeSplit[0]
		name = scopeSplit[1]
	}
	return buildNpmDownloadUrl(artiUrl, repo, name, scope, version), name, scope, version
}

func buildNpmDownloadUrl(url, repo, name, scope, version string) []string {
	var packageUrl string
	if scope != "" {
		packageUrl = fmt.Sprintf("%s/api/npm/%s/%s/%s/-/%s-%s.tgz", strings.TrimSuffix(url, "/"), repo, scope, name, name, version)
	} else {
		packageUrl = fmt.Sprintf("%s/api/npm/%s/%s/-/%s-%s.tgz", strings.TrimSuffix(url, "/"), repo, name, name, version)
	}
	return []string{packageUrl}
}

func GetCurationOutputFormat(formatFlagVal string) (format outFormat.OutputFormat, err error) {
	// Default print format is table.
	format = outFormat.Table
	if formatFlagVal != "" {
		switch strings.ToLower(formatFlagVal) {
		case string(outFormat.Table):
			format = outFormat.Table
		case string(outFormat.Json):
			format = outFormat.Json
		default:
			err = errorutils.CheckErrorf("only the following output formats are supported: " + coreutils.ListToText(CurationOutputFormats))
		}
	}
	return
}
