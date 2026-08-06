package curation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/gofrog/parallel"
	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	outFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"golang.org/x/exp/maps"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/ioutils"

	"github.com/jfrog/jfrog-client-go/artifactory"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/http/redirect"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayClient "github.com/jfrog/jfrog-client-go/xray"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/docker"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/huggingface"
	hfdiscovery "github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/huggingface/discovery"
	npmtech "github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/npm"
	pnpmtech "github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/pnpm"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/python"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"

	"github.com/jfrog/build-info-go/build/utils/dotnet/dependencies"

	bibuildutils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/gofrog/version"
	uvtech "github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/uv"
	yarntech "github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/yarn"
)

const (
	// The "blocked" represents the unapproved status that can be returned by the Curation Service for dependencies..
	blocked                    = "blocked"
	notEvaluated               = "not evaluated"
	BlockingReasonPolicy       = "Policy violations"
	BlockingReasonNotFound     = "Package pending update"
	BlockingReasonOnDemand     = "Package pending — Curation on-demand scan in progress"
	BlockingReasonUnknown      = "Blocked by curation (response could not be parsed)"
	BlockingReasonNotEvaluated = "Not evaluated — non-registry dependency"

	directRelation   = "direct"
	indirectRelation = "indirect"

	BlockMessageKey  = "jfrog packages curation"
	NotBeingFoundKey = "not being found"
	IsOnDemand       = "on-demand"

	extractPoliciesRegexTemplate = "({.*?})"

	errorTemplateHeadRequest = "failed sending HEAD request to %s for package '%s:%s'. Status-code: %v. Cause: %v"

	errorTemplateUnsupportedTech = "It looks like this project uses '%s' to download its dependencies. " +
		"This package manager however isn't supported by this command."

	WaiverRequestForbidden = "One or more policies blocking this package do not allow waiver requests."
	WaiverRequestApproved  = "The waiver request was automatically granted; you can use this package.\nNOTE: The policy owner may review this waiver more thoroughly and contact you if issues are found."
	WaiverRequestPending   = "A waiver request was opened for review, and the owner was notified.\nYou will receive an email with an update once the status changes."
	WaiverRequestError     = "An error occurred while processing the waiver request. Please try again later."

	TotalConcurrentRequests = 10

	MinArtiPassThroughSupport = "7.82.0"
	MinArtiGolangSupport      = "7.87.0"
	MinArtiNuGetSupport       = "7.93.0"
	MinXrayPassThroughSupport = "3.92.0"
	MinArtiGradleGemSupport   = "7.63.5"

	// cvsPartialReportWarning is shown when pip or poetry resolution failed because CVS
	// stripped a required version from the simple index, but the metadata-API
	// fallback succeeded in recovering at least one policy violation.
	cvsPartialReportWarning = "The curation audit was unable to fully resolve the dependency tree because one or more pinned package versions " +
		"are blocked by the curation policy. Details of the policy violations are shown in the table below.\n" +
		"Dependency analysis cannot proceed until these issues are addressed.\n" +
		"Once you switch to an approved version and re-run the audit, additional results will be available."

	// hfUnresolvedReportKey is used when an HF scan found only dynamic references — no table, just warnings.
	hfUnresolvedReportKey = "huggingface (unresolved references)"

	// npmLogPartialReportWarning is shown when runNpmLogFallback recovers a partial report.
	// npmLogOriginalErr (the real underlying npm error) goes to log.Debug only, not here —
	// npm's own error text can include its full captured stdout/stderr, far too noisy for a
	// console warning.
	npmLogPartialReportWarning = "npm install could not fully resolve the dependency tree because one or more packages " +
		"are blocked by the curation policy. This report was reconstructed from npm's debug log after the installation " +
		"failed, so it may be incomplete. Dependencies of blocked packages could not be analyzed because their metadata " +
		"was unavailable."
)

var CurationOutputFormats = []string{string(outFormat.Table), string(outFormat.Json)}
var osGetwd = os.Getwd
var npmGetConfigValue = npmtech.GetNpmConfigValue

var supportedTech = map[techutils.Technology]func(ca *CurationAuditCommand) (bool, error){
	techutils.Npm:  func(ca *CurationAuditCommand) (bool, error) { return true, nil },
	techutils.Yarn: func(ca *CurationAuditCommand) (bool, error) { return true, nil },
	techutils.Pnpm: func(ca *CurationAuditCommand) (bool, error) { return true, nil },
	techutils.Pip: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Pip, MinArtiPassThroughSupport)
	},
	techutils.Maven: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Maven, MinArtiPassThroughSupport)
	},
	techutils.Go: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Go, MinArtiGolangSupport)
	},
	techutils.Nuget: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Nuget, MinArtiNuGetSupport)
	},
	techutils.Gradle: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Gradle, MinArtiGradleGemSupport)
	},
	techutils.Gem: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Gem, MinArtiGradleGemSupport)
	},
	techutils.Docker:        func(ca *CurationAuditCommand) (bool, error) { return true, nil },
	techutils.HuggingFaceML: func(ca *CurationAuditCommand) (bool, error) { return true, nil },
	techutils.Poetry: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Poetry, MinArtiPassThroughSupport)
	},
	techutils.Uv: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Uv, MinArtiPassThroughSupport)
	},
	techutils.Pipenv: func(ca *CurationAuditCommand) (bool, error) {
		return ca.checkSupportByVersionOrEnv(techutils.Pipenv, MinArtiPassThroughSupport)
	},
}

func (ca *CurationAuditCommand) checkSupportByVersionOrEnv(tech techutils.Technology, minArtiVersion string) (bool, error) {
	if flag, err := clientutils.GetBoolEnvValue(utils.CurationSupportFlag, false); flag {
		return true, nil
	} else if err != nil {
		log.Error(err)
	}
	artiVersion, err := ca.getRtVersion(tech)
	if err != nil {
		return false, err
	}

	xrayVersion, err := ca.getXrayVersion()
	if err != nil {
		return false, err
	}

	xrayVersionErr := clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, MinXrayPassThroughSupport)
	rtVersionErr := clientutils.ValidateMinimumVersion(clientutils.Artifactory, artiVersion, minArtiVersion)
	if xrayVersionErr != nil || rtVersionErr != nil {
		return false, errors.Join(xrayVersionErr, rtVersionErr)
	}
	return true, nil
}

func (ca *CurationAuditCommand) getRtVersion(tech techutils.Technology) (string, error) {
	rtManager, _, err := ca.getRtManagerAndAuth(tech)
	if err != nil {
		return "", err
	}
	rtVersion, err := rtManager.GetVersion()
	if err != nil {
		return "", err
	}
	return rtVersion, err
}

func (ca *CurationAuditCommand) getXrayVersion() (string, error) {
	serverDetails, err := ca.ServerDetails()
	if err != nil {
		return "", err
	}
	xrayManager, err := xray.CreateXrayServiceManager(serverDetails)
	if err != nil {
		return "", err
	}
	xrayVersion, err := xrayManager.GetVersion()
	if err != nil {
		return "", err
	}
	return xrayVersion, nil
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
	WaiverAllowed     bool     `json:"waiver_allowed"`
	Policy            []Policy `json:"policies,omitempty"`
}

type Policy struct {
	Policy         string `json:"policy"`
	Condition      string `json:"condition"`
	Explanation    string `json:"explanation"`
	Recommendation string `json:"recommendation"`
}

type PackageStatusTable struct {
	ID             string `col-name:"ID" auto-merge:"true"`
	ParentName     string `col-name:"Direct\nDependency\nPackage\nName" auto-merge:"true"`
	ParentVersion  string `col-name:"Direct\nDependency\nPackage\nVersion" auto-merge:"true"`
	PackageName    string `col-name:"Blocked\nPackage\nName" auto-merge:"true"`
	PackageVersion string `col-name:"Blocked\nPackage\nVersion" auto-merge:"true"`
	PkgType        string `col-name:"Package\nType" auto-merge:"true"`
	Policy         string `col-name:"Violated\nPolicy\nName"`
	Condition      string `col-name:"Violated Condition\nName"`
	Explanation    string `col-name:"Explanation"`
	Recommendation string `col-name:"Recommendation"`
}

type treeAnalyzer struct {
	rtManager             artifactory.ArtifactoryServicesManager
	extractPoliciesRegex  *regexp.Regexp
	rtAuth                auth.ServiceDetails
	httpClientDetails     httputils.HttpClientDetails
	url                   string
	repo                  string
	tech                  techutils.Technology
	parallelRequests      int
	downloadUrls          map[string]string
	includeCachedPackages bool
	// cancelled is set to true when an unrecoverable error (e.g. 401) occurs so that
	// the producer goroutine stops queuing new tasks and in-flight tasks bail out early.
	cancelled atomic.Bool
	// authErr holds the first authentication error encountered during HEAD requests.
	// Stored via atomic.Value so it can be retrieved after the parallel runner finishes
	// and returned once — avoiding double-printing via errorsQueue.AddError.
	authErr atomic.Value
	// hfExplicitModel is true for --hugging-face-model (vs auto-discovery).
	hfExplicitModel bool
	// hfUnresolvedMu guards hfUnresolvedNodes, appended concurrently.
	hfUnresolvedMu    sync.Mutex
	hfUnresolvedNodes []string
}

type CurationAuditCommand struct {
	PackageManagerConfig *project.RepositoryConfig
	extractPoliciesRegex *regexp.Regexp
	workingDirs          []string
	OriginPath           string
	parallelRequests     int
	dockerImageName      string
	huggingFaceModel     string
	// hfProjectNameHint is the collision-free HF root-node name for the current working dir.
	hfProjectNameHint     string
	includeCachedPackages bool
	mvnIncludePluginDeps  bool
	scriptPath            string
	// pendingWarnings collects log.Warn messages that must be emitted after the
	// progress spinner stops; otherwise the spinner's ANSI clear codes overwrite them.
	pendingWarnings []string
	audit.AuditParamsInterface
}

type CurationReport struct {
	packagesStatus        []*PackageStatus
	totalNumberOfPackages int
	// isPartial is set when the dependency tree could not be fully resolved
	// (e.g. CVS blocked a pip version from the simple index) and the report
	// was produced via the metadata-API fallback. The partial-report warning
	// is printed after the spinner stops so it is not swallowed by the spinner.
	isPartial bool
	// hfPartial marks unresolved (404) HF nodes excluded from totalNumberOfPackages.
	// Kept separate from isPartial, which also triggers the CVS-specific warning
	// and skips the waiver flow.
	hfPartial bool
	// npmLogPartial marks a report produced by runNpmLogFallback. Set alongside isPartial
	// (to reuse its waiver-skip gate), but kept distinct for its own warning text and
	// partialReason.
	npmLogPartial bool
	// npmLogOriginalErr is the real install error, surfaced alongside npmLogPartialReportWarning.
	npmLogOriginalErr string
	// warnings holds user-facing messages from tree-build (e.g. unresolved HF references).
	warnings []string
	// huggingFaceReport marks reports produced by the Hugging Face audit path (including
	// warning-only unresolved-reference placeholders), for deterministic output ordering.
	huggingFaceReport bool
}

// uniqueReportKey returns key, or a tech-suffixed variant if key is already taken by another
// tech's report — e.g. pip's CVS-fallback and HF auto-discovery can both default to the same
// directory-basename key. This keeps them as two separate tables instead of one clobbering
// (or being fused into) the other.
func uniqueReportKey(results map[string]*CurationReport, key string, tech techutils.Technology) string {
	if _, exists := results[key]; !exists {
		return key
	}
	candidate := fmt.Sprintf("%s (%s)", key, tech)
	for i := 2; ; i++ {
		if _, exists := results[candidate]; !exists {
			return candidate
		}
		candidate = fmt.Sprintf("%s (%s) #%d", key, tech, i)
	}
}

type WaiverResponse struct {
	PkgName     string `col-name:"Package Name"`
	Status      string `col-name:"Status"`
	Explanation string `col-name:"Explanation"`
	WaiverID    string `col-name:"Waiver ID"`
}

func NewCurationAuditCommand() *CurationAuditCommand {
	return &CurationAuditCommand{
		extractPoliciesRegex: regexp.MustCompile(extractPoliciesRegexTemplate),
		AuditParamsInterface: &audit.AuditBasicParams{},
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

func (ca *CurationAuditCommand) DockerImageName() string {
	return ca.dockerImageName
}

func (ca *CurationAuditCommand) SetDockerImageName(dockerImageName string) *CurationAuditCommand {
	ca.dockerImageName = dockerImageName
	return ca
}

func (ca *CurationAuditCommand) HuggingFaceModel() string {
	return ca.huggingFaceModel
}

func (ca *CurationAuditCommand) SetHuggingFaceModel(huggingFaceModel string) *CurationAuditCommand {
	ca.huggingFaceModel = huggingFaceModel
	return ca
}

func (ca *CurationAuditCommand) SetIncludeCachedPackages(includeCachedPackages bool) *CurationAuditCommand {
	ca.includeCachedPackages = includeCachedPackages
	return ca
}

func (ca *CurationAuditCommand) SetMvnIncludePluginDeps(mvnIncludePluginDeps bool) *CurationAuditCommand {
	ca.mvnIncludePluginDeps = mvnIncludePluginDeps
	return ca
}

func (ca *CurationAuditCommand) SetScriptPath(scriptPath string) *CurationAuditCommand {
	ca.scriptPath = scriptPath
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
	// Ensures dirs sharing a basename still get distinct HF root-node names.
	hfProjectNames := huggingface.DisambiguateRootNodeNames(ca.workingDirs)
	// Resolved up front, before any chdir below — each iteration chdir's into its
	// own absWd, so resolving relative dirs one at a time inside the loop would
	// resolve later entries against an earlier entry's cwd instead of rootDir.
	absWorkingDirs := make([]string, len(ca.workingDirs))
	for i, workDir := range ca.workingDirs {
		if absWorkingDirs[i], err = filepath.Abs(workDir); err != nil {
			return errorutils.CheckError(err)
		}
	}
	results := map[string]*CurationReport{}
	var scanErr error
	for _, absWd := range absWorkingDirs {
		log.Info("Running curation audit on project:", absWd)
		if absWd != rootDir {
			if err = os.Chdir(absWd); err != nil {
				return errorutils.CheckError(err)
			}
		}
		// OriginPath scopes hasPythonFiles and params.HFWorkingDirectory to this working directory.
		ca.OriginPath = absWd
		ca.hfProjectNameHint = hfProjectNames[absWd]
		// If error returned, continue to print results(if any), and return error at the end.
		if e := ca.doCurateAudit(results); e != nil {
			scanErr = errors.Join(scanErr, e)
			err = errors.Join(err, e)
		}
	}
	if ca.Progress() != nil {
		err = errors.Join(err, ca.Progress().Quit())
	}
	// Print after the spinner has stopped so messages are not overwritten by ANSI clear codes.
	for _, w := range ca.pendingWarnings {
		log.Warn(w)
	}
	// Don't include scanErr.Error() here — it is in the returned err and the CLI framework
	// prints it once; printing it here too would duplicate the full error message.
	if scanErr != nil {
		log.Error("Curation audit encountered errors while checking some packages; the report below may be incomplete:")
	}
	for projectPath, report := range results {
		if report.isPartial {
			warningText := cvsPartialReportWarning
			if report.npmLogPartial {
				warningText = npmLogPartialReportWarning
				log.Debug(fmt.Sprintf("[%s] underlying npm error: %s", projectPath, report.npmLogOriginalErr))
			}
			log.Warn(fmt.Sprintf("[%s] %s", projectPath, warningText))
		}
	}

	// Non-HF tables first, then HF — deterministic order regardless of map iteration.
	var nonHFKeys, hfKeys []string
	for k, report := range results {
		if isHuggingFaceReport(report) {
			hfKeys = append(hfKeys, k)
		} else {
			nonHFKeys = append(nonHFKeys, k)
		}
	}
	sort.Strings(nonHFKeys)
	sort.Strings(hfKeys)
	projectPaths := slices.Concat(nonHFKeys, hfKeys)

	var allWarnings []string
	for _, projectPath := range projectPaths {
		packagesStatus := results[projectPath]
		if !isWarningsOnlyReport(packagesStatus) {
			err = errors.Join(err, printResult(ca.OutputFormat(), projectPath, packagesStatus.packagesStatus))
		}
		allWarnings = append(allWarnings, packagesStatus.warnings...)

		// A partial report comes from the CVS fallback: the dependency tree could
		// not be fully resolved. Never offers a waiver when the full tree wasn't built.
		if packagesStatus.isPartial {
			continue
		}

		for _, ps := range packagesStatus.packagesStatus {
			if ps.WaiverAllowed && !utils.IsCI() {
				// If at least one package allows waiver requests, we will ask the user if they want to request a waiver
				err = errors.Join(ca.requestWaiver(packagesStatus.packagesStatus))
				break
			}
		}
	}
	for _, w := range allWarnings {
		log.Warn(w)
	}
	err = errors.Join(err, output.RecordSecurityCommandSummary(output.NewCurationSummary(convertResultsToSummary(results))))
	return
}

func convertResultsToSummary(results map[string]*CurationReport) formats.ResultsSummary {
	summaryResults := formats.ResultsSummary{}
	for projectPath, packagesStatus := range results {
		// hfPartial/npmLogPartial reports must still be recorded, not treated as "not attempted".
		if isWarningsOnlyReport(packagesStatus) && !packagesStatus.hfPartial && !packagesStatus.npmLogPartial {
			continue
		}
		var partialReason string
		switch {
		// npmLogPartial is checked before isPartial: an npm-log-fallback report sets both
		// (isPartial to reuse the existing waiver-skip gate below), so npmLogPartial must
		// win here or it would incorrectly report "cvs_fallback".
		case packagesStatus.npmLogPartial:
			// jfrog-ignore: categorical tag, not hardcoded credentials
			partialReason = "npm_log_fallback"
		case packagesStatus.isPartial:
			partialReason = "cvs_fallback"
		case packagesStatus.hfPartial:
			partialReason = "hf_unresolved"
		}
		// npmLogPartial's totalNumberOfPackages includes non-remediable "not evaluated" rows, so use the blocked-row count instead.
		packageCount := packagesStatus.totalNumberOfPackages
		if packagesStatus.npmLogPartial {
			packageCount = countBlockedPackages(packagesStatus.packagesStatus)
		}
		summaryResults.Scans = append(summaryResults.Scans, formats.ScanSummary{Target: projectPath,
			CuratedPackages: &formats.CuratedPackages{
				PackageCount:  packageCount,
				Blocked:       getBlocked(packagesStatus.packagesStatus),
				IsPartial:     packagesStatus.isPartial || packagesStatus.hfPartial,
				PartialReason: partialReason,
			},
		})
	}
	return summaryResults
}

// countBlockedPackages counts only rows with Action == blocked, excluding "not evaluated" rows.
func countBlockedPackages(packagesStatus []*PackageStatus) int {
	count := 0
	for _, ps := range packagesStatus {
		if ps.Action == blocked {
			count++
		}
	}
	return count
}

func getBlocked(pkgStatus []*PackageStatus) []formats.BlockedPackages {
	blockedMap := map[string]formats.BlockedPackages{}
	for _, pkg := range pkgStatus {
		if pkg.Action != blocked {
			continue
		}
		for _, policy := range pkg.Policy {
			polAndCondKey := getPolicyAndConditionId(policy.Policy, policy.Condition)
			if _, ok := blockedMap[polAndCondKey]; !ok {
				blockedMap[polAndCondKey] = formats.BlockedPackages{
					Policy:    policy.Policy,
					Condition: policy.Condition,
					Packages:  make(map[string]int),
				}
			}
			uniqId := getPackageId(pkg.PackageName, pkg.PackageVersion)
			if _, ok := blockedMap[polAndCondKey].Packages[uniqId]; !ok {
				blockedMap[polAndCondKey].Packages[uniqId] = 0
			}
			blockedMap[polAndCondKey].Packages[uniqId]++
		}
	}
	return maps.Values(blockedMap)
}

// The unique identifier of a package includes the package name with its version
func getPackageId(packageName, packageVersion string) string {
	return fmt.Sprintf("%s:%s", packageName, packageVersion)
}

func getPolicyAndConditionId(policy, condition string) string {
	return fmt.Sprintf("%s:%s", policy, condition)
}

// promotePnpmWorkspaceMember replaces "npm" with "pnpm" in the detected technologies
// list when the current directory is a pnpm workspace member — it has no pnpm marker
// itself, but an ancestor directory contains pnpm-workspace.yaml or pnpm-lock.yaml.
// This lets `jf ca --working-dirs=<member>` audit the member as part of its pnpm
// workspace, consistently with the lockfile resolution which also walks up to the root.
func promotePnpmWorkspaceMember(techs []string) []string {
	hasPnpm, hasNpm := false, false
	for _, t := range techs {
		switch t {
		case techutils.Pnpm.String():
			hasPnpm = true
		case techutils.Npm.String():
			hasNpm = true
		}
	}
	if hasPnpm || !hasNpm {
		return techs
	}
	dir, err := os.Getwd()
	if err != nil {
		return techs
	}
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return techs
		}
		dir = parent
		for _, indicator := range []string{"pnpm-workspace.yaml", "pnpm-lock.yaml"} {
			if _, statErr := os.Stat(filepath.Join(dir, indicator)); statErr == nil {
				log.Debug(fmt.Sprintf("Detected pnpm workspace root at %s via %s; promoting current directory from npm to pnpm.", dir, indicator))
				promoted := make([]string, 0, len(techs))
				for _, t := range techs {
					if t == techutils.Npm.String() {
						t = techutils.Pnpm.String()
					}
					promoted = append(promoted, t)
				}
				return promoted
			}
		}
	}
}

// promoteYarnWorkspaceMember replaces "npm" with "yarn" in the detected technologies
// list when the current directory is a yarn workspace member — it has no yarn marker
// itself, but an ancestor directory contains .yarnrc.yml or yarn.lock.
// This lets `jf ca --working-dirs=<member>` audit the member as part of its yarn
// workspace, consistently with how pnpm workspace members are promoted via
// promotePnpmWorkspaceMember.
func promoteYarnWorkspaceMember(techs []string) []string {
	hasYarn, hasNpm := false, false
	for _, t := range techs {
		switch t {
		case techutils.Yarn.String():
			hasYarn = true
		case techutils.Npm.String():
			hasNpm = true
		}
	}
	if hasYarn || !hasNpm {
		return techs
	}
	dir, err := os.Getwd()
	if err != nil {
		return techs
	}
	// Stop at $HOME: a personal ~/.yarnrc.yml (created by 'jf c'/yarn setup) must
	// not misclassify every npm project under $HOME as a yarn workspace member.
	home, _ := os.UserHomeDir()
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return techs
		}
		dir = parent
		if home != "" && dir == home {
			return techs
		}
		if techutils.DirectoryHasYarnIndicator(dir) {
			log.Debug(fmt.Sprintf("Detected yarn workspace root at %s; promoting current directory from npm to yarn.", dir))
			promoted := make([]string, 0, len(techs))
			for _, t := range techs {
				if t == techutils.Npm.String() {
					t = techutils.Yarn.String()
				}
				promoted = append(promoted, t)
			}
			return promoted
		}
	}
}

// Rule, in order:
//  1. Pip-exclusive file present (requirements.txt, setup.py, setup.cfg, Pipfile,
//     poetry.lock) → Pip wins, Uv is dropped.
//  2. Otherwise, any uv signal (uv.lock, pyproject.toml [tool.uv]/[[tool.uv.index]], or
//     ~/.config/uv/uv.toml) → Uv wins, Pip is dropped.
func promotePipToUv(techs []string) []string {
	if !slices.Contains(techs, techutils.Pip.String()) {
		return techs
	}
	dir, err := os.Getwd()
	if err != nil {
		return techs
	}
	for _, pipOnlyFile := range []string{"requirements.txt", "setup.py", "setup.cfg", "Pipfile", "poetry.lock"} {
		if _, statErr := os.Stat(filepath.Join(dir, pipOnlyFile)); statErr == nil {
			return removeTech(techs, techutils.Uv.String())
		}
	}

	uvSignal := ""
	if _, statErr := os.Stat(filepath.Join(dir, "uv.lock")); statErr == nil {
		uvSignal = "uv.lock detected"
	} else if data, readErr := os.ReadFile(filepath.Join(dir, "pyproject.toml")); readErr == nil &&
		(strings.Contains(string(data), "[tool.uv]") || strings.Contains(string(data), "[[tool.uv.index]]")) {
		uvSignal = "pyproject.toml has uv configuration ([tool.uv] or [[tool.uv.index]])"
	} else if home, homeErr := os.UserHomeDir(); homeErr == nil {
		if _, statErr := os.Stat(filepath.Join(home, ".config", "uv", "uv.toml")); statErr == nil {
			uvSignal = "~/.config/uv/uv.toml detected"
		}
	}
	if uvSignal == "" {
		return techs
	}
	log.Info(uvSignal + " — treating project as uv.")
	techs = removeTech(techs, techutils.Pip.String())
	if !slices.Contains(techs, techutils.Uv.String()) {
		techs = append(techs, techutils.Uv.String())
	}
	return techs
}

// removeTech returns techs without any entry equal to tech.
func removeTech(techs []string, tech string) []string {
	filtered := make([]string, 0, len(techs))
	for _, t := range techs {
		if t != tech {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// techsToAudit picks doCurateAudit's technologies, in priority order: --script, then
// --hugging-face-model, then --docker-image, then file-based detection (with npm→yarn,
// pip→uv, and Hugging Face auto-discovery promotion).
func (ca *CurationAuditCommand) techsToAudit() []string {
	switch {
	case ca.scriptPath != "":
		log.Debug(fmt.Sprintf("--script %q was provided, auditing it directly as a uv PEP 723 script — skipping project detection.", ca.scriptPath))
		return []string{techutils.Uv.String()}
	case ca.HuggingFaceModel() != "":
		log.Debug(fmt.Sprintf("Hugging Face models '%s' were provided explicitly — running HF-only audit.", ca.HuggingFaceModel()))
		return []string{techutils.HuggingFaceML.String()}
	case ca.DockerImageName() != "":
		log.Debug(fmt.Sprintf("Docker image name '%s' was provided, running Docker curation audit.", ca.DockerImageName()))
		return []string{techutils.Docker.String()}
	default:
		techs := promotePnpmWorkspaceMember(techutils.DetectedTechnologiesListForCurationAudit())
		techs = promoteYarnWorkspaceMember(techs)
		techs = promotePipToUv(techs)
		// Auto-discovery: if HF_ENDPOINT is set and .py/.ipynb files exist, append HF to the tech list.
		if os.Getenv("HF_ENDPOINT") != "" && hasPythonFiles(ca.OriginPath) {
			hfTech := techutils.HuggingFaceML.String()
			if !slices.Contains(techs, hfTech) {
				techs = append(techs, hfTech)
			}
		}
		for i, tech := range techs {
			techs[i] = resolveNpmYarnTech(tech)
		}
		// Logged here, after all promotions, so it reflects what's actually audited —
		// logging right after file-based detection could show a technology (e.g. "pip")
		// that a promotion below immediately supersedes (e.g. "...treating project as uv.").
		if len(techs) > 0 {
			log.Info(fmt.Sprintf("Detected: %s.", strings.Join(techs, ", ")))
		}
		ca.queuePep723HintIfUv(techs)
		return techs
	}
}

func (ca *CurationAuditCommand) queuePep723HintIfUv(techs []string) {
	if !slices.Contains(techs, techutils.Uv.String()) {
		return
	}
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	if hint := techutils.Pep723ScriptUnauditedHint(wd); hint != "" {
		ca.pendingWarnings = append(ca.pendingWarnings, hint)
	}
}

func (ca *CurationAuditCommand) doCurateAudit(results map[string]*CurationReport) error {
	if err := validateCurationAuditFlags(ca); err != nil {
		return err
	}
	techs := ca.techsToAudit()
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
			// If HF is the only tech being audited (no other package manager was detected
			// in this working dir — e.g. a subdirectory with .py files but no manifest of
			// its own), there's nothing else this leniency protects: swallowing the error
			// would let the whole audit silently check nothing and still exit 0.
			if techutils.Technology(tech) == techutils.HuggingFaceML && ca.HuggingFaceModel() == "" && len(techs) > 1 {
				// HF auto-discovery is additive — config/connectivity failures must not abort other techs.
				log.Warn(fmt.Sprintf("Hugging Face curation audit skipped: %v", err))
				ca.setPackageManagerConfig(nil)
				ca.AuditParamsInterface = ca.SetDepsRepo("")
				continue
			}
			return err
		}
		// clear the package manager config to avoid using the same config for the next tech
		ca.setPackageManagerConfig(nil)
		ca.AuditParamsInterface = ca.SetDepsRepo("")

	}
	return nil
}

// isWarningsOnlyReport is true for HF unresolved-reference placeholders that carry
// warnings but no curation table rows (e.g. hfUnresolvedReportKey).
// isWarningsOnlyReport reports whether report represents the placeholder created when
// no packages were resolved/audited at all (e.g. every HF reference was unresolved) —
// not merely a report where nothing happened to be blocked. packagesStatus only holds
// blocked packages (see fetchNodeStatus), so an all-clean audit of N real packages also
// has an empty packagesStatus; totalNumberOfPackages distinguishes that case (N) from
// the true warnings-only placeholder (0, never set).
func isWarningsOnlyReport(report *CurationReport) bool {
	return report.totalNumberOfPackages == 0 && len(report.warnings) > 0
}

// isHuggingFaceReport reports whether a result belongs to the Hugging Face audit path.
func isHuggingFaceReport(report *CurationReport) bool {
	if report.huggingFaceReport {
		return true
	}
	if len(report.packagesStatus) == 0 {
		return false
	}
	for _, ps := range report.packagesStatus {
		if ps.PkgType != techutils.HuggingFaceML.String() {
			return false
		}
	}
	return true
}

// hasPythonFiles returns true if dir contains at least one .py or .ipynb file,
// indicating the project may have Hugging Face model references to discover.
func hasPythonFiles(dir string) bool {
	if dir == "" {
		dir = "."
	}
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			log.Debug(fmt.Sprintf("hasPythonFiles: skipping %s: %v", path, walkErr))
			return nil
		}
		if d.IsDir() {
			if hfdiscovery.IsExcludedWalkDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".py" || ext == ".ipynb" {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func validateCurationAuditFlags(ca *CurationAuditCommand) error {
	if ca.DockerImageName() != "" && ca.HuggingFaceModel() != "" {
		return errorutils.CheckErrorf(
			"--docker-image and --hugging-face-model cannot be used together; run separate curation-audit commands for each",
		)
	}

	return nil
}

// resolveNpmYarnTech upgrades npm→yarn when the project has yarn.yaml but no npm.yaml
// (the developer ran 'jf yarn-config' but the file-system detector fell back to npm),
// or when the project has a yarn indicator file (.yarnrc.yml / yarn.lock / .yarnrc / .yarn)
// without a yarn.yaml — which is the V4 native mode case where no jf yarn-config is needed.
func resolveNpmYarnTech(tech string) string {
	if techutils.Technology(tech) != techutils.Npm {
		return tech
	}
	_, npmConfigExists, _ := project.GetProjectConfFilePath(techutils.Npm.GetProjectType())
	if npmConfigExists {
		return tech
	}
	_, yarnConfigExists, _ := project.GetProjectConfFilePath(techutils.Yarn.GetProjectType())
	if yarnConfigExists {
		log.Info("No npm.yaml config found but yarn.yaml detected — treating project as yarn.")
		return techutils.Yarn.String()
	}
	// V4 native mode: no yarn.yaml, but project may have a local yarn indicator
	// (.yarnrc.yml / yarn.lock / .yarnrc / .yarn) OR only a global ~/.yarnrc.yml
	// (set via 'yarn config set --home', as the Artifactory "Set Up" page instructs).
	// Guard against false-positives: if package-lock.json exists the project is npm.
	workingDir, wdErr := coreutils.GetWorkingDirectory()
	if wdErr == nil {
		if _, err := os.Stat(filepath.Join(workingDir, "package-lock.json")); err == nil {
			// package-lock.json present — this is an npm project.
			return tech
		}
		if techutils.DirectoryHasYarnIndicator(workingDir) {
			log.Info("No npm.yaml or yarn.yaml found but yarn indicator file detected (.yarnrc.yml / yarn.lock / .yarnrc / .yarn) — treating project as yarn.")
			return techutils.Yarn.String()
		}
		// Check global ~/.yarnrc.yml — customers using 'yarn config set --home'
		// (as shown in the Artifactory "Set Up" page for Yarn V4) have no project-level
		// .yarnrc.yml but a global one that carries the registry and auth token.
		// Gate on package.json pinning yarn (Corepack "packageManager"): a personal
		// global ~/.yarnrc.yml must not promote an npm-only project to yarn.
		if projectPinsYarnPackageManager(workingDir) {
			if homeDir, err := os.UserHomeDir(); err == nil {
				if _, err := os.Stat(filepath.Join(homeDir, ".yarnrc.yml")); err == nil {
					log.Info("No npm.yaml or yarn.yaml found but package.json pins yarn and global ~/.yarnrc.yml detected — treating project as yarn (V4 native mode).")
					return techutils.Yarn.String()
				}
			}
		}
	}
	return tech
}

// projectPinsYarnPackageManager reports whether package.json pins yarn via the
// Corepack "packageManager" field (e.g. "yarn@4.1.0").
func projectPinsYarnPackageManager(workingDir string) bool {
	data, err := os.ReadFile(filepath.Join(workingDir, "package.json"))
	if err != nil {
		return false
	}
	var pkg struct {
		PackageManager string `json:"packageManager"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(pkg.PackageManager), "yarn@")
}

// resolveResolverTechForCuration returns the tech whose *.yaml config drives
// SetResolutionRepoInParamsIfExists. For yarn with no yarn.yaml, falls back to
// npm.yaml — npm and yarn share the same Artifactory npm API.
func resolveResolverTechForCuration(tech techutils.Technology) techutils.Technology {
	if tech != techutils.Yarn {
		return tech
	}
	if _, yarnConfigExists, _ := project.GetProjectConfFilePath(techutils.Yarn.GetProjectType()); yarnConfigExists {
		return tech
	}
	if _, npmConfigExists, _ := project.GetProjectConfFilePath(techutils.Npm.GetProjectType()); !npmConfigExists {
		return tech
	}
	log.Info("No yarn.yaml found; using npm.yaml for resolver configuration (npm and yarn share the same Artifactory npm API).")
	return techutils.Npm
}

func (ca *CurationAuditCommand) getRtManagerAndAuth(tech techutils.Technology) (rtManager artifactory.ArtifactoryServicesManager, serverDetails *config.ServerDetails, err error) {
	serverDetails, err = ca.GetAuth(tech)
	if err != nil {
		return
	}
	rtManager, err = rtUtils.CreateServiceManager(serverDetails, 2, 0, false)
	if err != nil {
		return
	}
	return
}

// boundedRedirectManager must use zero retries: HttpClient.Send retries
// on CheckRedirect errors, desyncing SendWithBoundedRedirects's hop counter.
func boundedRedirectManager(serverDetails *config.ServerDetails) (artifactory.ArtifactoryServicesManager, error) {
	return rtUtils.CreateServiceManager(serverDetails, 0, 0, false)
}

func (ca *CurationAuditCommand) GetAuth(tech techutils.Technology) (serverDetails *config.ServerDetails, err error) {
	if ca.PackageManagerConfig == nil {
		if err = ca.SetRepo(tech); err != nil {
			return
		}
	}
	serverDetails, err = ca.PackageManagerConfig.ServerDetails()
	if err != nil {
		return
	}
	return
}

// getBuildInfoParamsByTech resolves install-time server details. For Pipenv, prefers an
// already-set ca.PackageManagerConfig (native detection) over the generic server so install
// and the later GetAuth-based probes hit the same endpoint. Other techs keep using the
// generic server, matching their pre-existing behavior.
func (ca *CurationAuditCommand) getBuildInfoParamsByTech(tech techutils.Technology) (technologies.BuildInfoBomGeneratorParams, error) {
	var serverDetails *config.ServerDetails
	var err error
	if tech == techutils.Pipenv && ca.PackageManagerConfig != nil {
		serverDetails, err = ca.PackageManagerConfig.ServerDetails()
	} else {
		serverDetails, err = ca.ServerDetails()
	}
	return technologies.BuildInfoBomGeneratorParams{
		XrayVersion:      ca.GetXrayVersion(),
		ExclusionPattern: technologies.GetScaExcludePattern(ca.GetConfigProfile(), ca.IsRecursiveScan(), ca.Exclusions()...),
		Progress:         ca.Progress(),
		// Artifactory Repository params
		ServerDetails:          serverDetails,
		DependenciesRepository: ca.DepsRepo(),
		IgnoreConfigFile:       ca.IgnoreConfigFile(),
		InsecureTls:            ca.InsecureTls(),
		// Install params
		InstallCommandName: ca.InstallCommandName(),
		Args:               ca.Args(),
		InstallCommandArgs: ca.InstallCommandArgs(),
		// Curation params
		IsCurationCmd:        true,
		MvnIncludePluginDeps: ca.mvnIncludePluginDeps,
		ParallelRequests:     ca.parallelRequests,
		OutputFormat:         ca.OutputFormat(),
		// Java params
		IsMavenDepTreeInstalled: true,
		UseWrapper:              ca.UseWrapper(),
		// Npm params
		NpmIgnoreNodeModules:    true,
		NpmOverwritePackageLock: true,
		NpmRunNative:            ca.RunNative(),
		NpmLegacyPeerDeps:       ca.LegacyPeerDeps(),
		// Yarn: always refresh yarn.lock when older than package.json (mirrors NpmOverwritePackageLock).
		YarnOverwriteYarnLock: true,
		// Pnpm params
		MaxTreeDepth: ca.MaxTreeDepth(),
		// Python params
		PipRequirementsFile: ca.PipRequirementsFile(),
		// Docker params
		DockerImageName: ca.DockerImageName(),
		// Hugging Face params
		HuggingFaceModel:   ca.HuggingFaceModel(),
		HFWorkingDirectory: ca.OriginPath,
		HFProjectName:      ca.hfProjectNameHint,
		// NuGet params
		SolutionFilePath: ca.SolutionFilePath(),
		// Uv params
		ScriptPath: ca.scriptPath,
	}, err
}

// countPackageNodes returns the number of real dependency nodes in flatTreeNodes,
// excluding root self-entries. FlatTree.Nodes includes each root's own self-entry
// alongside real dependencies for most techs (its ID matches a rootNodes entry),
// but Hugging Face's BuildDependencyTree never adds one (a scanned directory isn't
// itself a package) — so root entries are only subtracted when actually present,
// rather than assuming exactly one and undercounting a single-dependency HF project to 0.
func countPackageNodes(rootNodes map[string]struct{}, flatTreeNodes []*xrayUtils.GraphNode) int {
	count := len(flatTreeNodes)
	for _, node := range flatTreeNodes {
		if _, ok := rootNodes[node.Id]; ok {
			count--
		}
	}
	return count
}

func (ca *CurationAuditCommand) auditTree(tech techutils.Technology, results map[string]*CurationReport) error {
	// --run-native is meaningful for npm; pnpm/yarn/uv accept it as a no-op; reject it
	// early for every other tech.
	if err := validateRunNativeForTech(tech, ca.RunNative()); err != nil {
		return err
	}
	// Must run before getBuildInfoParamsByTech so params carry the correct repo and server details.
	// Usually already set by checkSupportByVersionOrEnv's GetAuth(Uv) call before auditTree;
	// only re-read here if that didn't happen (e.g. CurationSupportFlag skips GetAuth).
	if tech == techutils.Uv && ca.PackageManagerConfig == nil {
		if err := ca.setRepoFromUvToml(); err != nil {
			return err
		}
	}
	// Resolve Pipenv's native repo/server before getBuildInfoParamsByTech so install and the
	// later probes share an endpoint. Other techs resolve later via SetResolutionRepoInParamsIfExists
	// and must not be forced through SetRepo this early (they tolerate having no config file yet).
	if tech == techutils.Pipenv && ca.PackageManagerConfig == nil {
		if err := ca.SetRepo(tech); err != nil {
			return err
		}
	}
	params, err := ca.getBuildInfoParamsByTech(tech)
	if err != nil {
		return errorutils.CheckErrorf("failed to get build info params for %s: %v", tech.String(), err)
	}
	// When --run-native is set for npm, or for pnpm (always .npmrc-based), the Artifactory
	// details are already populated from .npmrc. Skip the yaml config file lookup.
	if (ca.RunNative() && tech == techutils.Npm) || tech == techutils.Pnpm {
		params.IgnoreConfigFile = true
	}
	// uv has no jf uv-config yaml; skip config file lookup and use server details
	// from uv.toml so BuildDependencyTree builds correct Artifactory download URLs.
	if tech == techutils.Uv {
		params.IgnoreConfigFile = true
		if ca.PackageManagerConfig != nil {
			if uvSD, sdErr := ca.PackageManagerConfig.ServerDetails(); sdErr == nil && uvSD != nil {
				params.ServerDetails = uvSD
			}
		}
	}
	// Pnpm always resolves natively from .npmrc — --run-native is redundant and has no effect.
	// Deferred: emitted after the spinner stops so the message is not overwritten.
	if ca.RunNative() && tech == techutils.Pnpm {
		ca.pendingWarnings = append(ca.pendingWarnings, "--run-native has no effect for pnpm; pnpm always resolves natively from .npmrc")
	}
	// --run-native has no effect for yarn regardless of version; the registry is
	// always read from the yarn-specific config (yarn.yaml for V2/V3, .yarnrc.yml for V4).
	// Deferred: emitted after the spinner stops so the message is not overwritten.
	if ca.RunNative() && tech == techutils.Yarn {
		ca.pendingWarnings = append(ca.pendingWarnings, "--run-native has no effect for yarn")
	}
	// --run-native has no effect for uv; it always resolves natively (there is no
	// 'jf uv-config' to opt out of).
	if ca.RunNative() && tech == techutils.Uv {
		ca.pendingWarnings = append(ca.pendingWarnings, "--run-native has no effect for uv; uv always resolves natively from uv.toml/pyproject.toml")
	}
	// For yarn with no yarn.yaml, fall back to npm.yaml — npm and yarn share the same Artifactory npm API.
	resolverTech := resolveResolverTechForCuration(tech)
	serverDetails, err := buildinfo.SetResolutionRepoInParamsIfExists(&params, resolverTech)
	if err != nil {
		return err
	}
	// Discovered before installing, not after: npm writes a log on every invocation, so running
	// this after a crash would make its own log newer than the crash's. Failure isn't fatal.
	//
	// Uses logs-dir, not cache: <cache>/_logs is only npm's default, overridable independently.
	// "npm config get logs-dir" prints the literal string "null" when unset, hence the fallback.
	var npmLogsDir string
	var npmLogsMaxWasZero bool
	var npmLogBaselineKey int64
	var npmConfigLookupErr error
	if tech == techutils.Npm {
		if workDir, wdErr := osGetwd(); wdErr != nil {
			npmConfigLookupErr = fmt.Errorf("failed to determine working directory for npm config lookup: %w", wdErr)
		} else if logsDirValue, logsDirErr := npmGetConfigValue(workDir, "logs-dir"); logsDirErr != nil {
			npmConfigLookupErr = fmt.Errorf("failed to determine npm logs-dir: %w", logsDirErr)
		} else if logsMaxValue, logsMaxErr := npmGetConfigValue(workDir, "logs-max"); logsMaxErr != nil {
			npmConfigLookupErr = fmt.Errorf("failed to determine npm logs-max config: %w", logsMaxErr)
		} else if logsDirValue != "" && logsDirValue != "null" {
			npmLogsDir, npmLogsMaxWasZero = logsDirValue, logsMaxValue == "0"
		} else if cacheDir, cacheErr := npmGetConfigValue(workDir, "cache"); cacheErr != nil {
			npmConfigLookupErr = fmt.Errorf("failed to determine npm cache directory: %w", cacheErr)
		} else {
			npmLogsDir, npmLogsMaxWasZero = filepath.Join(cacheDir, "_logs"), logsMaxValue == "0"
		}
		if npmConfigLookupErr != nil {
			log.Debug(fmt.Sprintf("npm curation debug-log fallback will be unavailable if the install fails: %v", npmConfigLookupErr))
		}
		if npmLogsMaxWasZero {
			// Only override when the ambient config would otherwise suppress the debug log
			// entirely — never force a value that prunes a user's own nonzero retention setting.
			params.NpmForceLogsMax = "1"
		}
		if npmLogsDir != "" {
			// Snapshotted last so the baseline includes the config-lookup calls' own logs too.
			npmLogBaselineKey, _ = npmDebugLogNewestKey(npmLogsDir)
		}
	}
	depTreeResult, err := buildinfo.GetTechDependencyTree(params, serverDetails, tech)
	if err != nil {
		// When CVS strips a pinned version from the simple index, pip/poetry/uv
		// can't resolve the project and GetTechDependencyTree returns a CvsBlockedError.
		// Instead of aborting with no output, run the metadata-API fallback to
		// recover the curation policy and render a partial table.
		var cvsErr *python.CvsBlockedError
		if (tech == techutils.Pip || tech == techutils.Poetry || tech == techutils.Uv || tech == techutils.Pipenv) && errors.As(err, &cvsErr) {
			return ca.runCvsFallback(cvsErr, tech, results)
		}
		// npm's install error is a plain opaque error, nothing to type-match on — trigger the
		// debug-log fallback unconditionally, unless the config lookup above already failed.
		if tech == techutils.Npm {
			if npmConfigLookupErr != nil {
				return err
			}
			return ca.runNpmLogFallback(npmLogsDir, tech, results, err, npmLogsMaxWasZero, npmLogBaselineKey)
		}
		return err
	}
	if tech == techutils.Npm {
		defer cleanupForcedNpmDebugLog(npmLogsDir, npmLogsMaxWasZero, npmLogBaselineKey)
	}
	// Validate the graph isn't empty.
	if len(depTreeResult.FullDepTrees) == 0 {
		// For HF auto-discovery, an empty tree is normal (no HF call sites found).
		if tech == techutils.HuggingFaceML {
			log.Debug("Hugging Face: no model references discovered in source — skipping HF curation probe")
			if len(depTreeResult.Warnings) > 0 {
				results[uniqueReportKey(results, hfUnresolvedReportKey, tech)] = &CurationReport{
					warnings:          depTreeResult.Warnings,
					huggingFaceReport: true,
				}
			}
			return nil
		}
		return errorutils.CheckErrorf("found no dependencies for the audited project using '%v' as the package manager", tech.String())
	}
	rtManager, serverDetails, err := ca.getRtManagerAndAuth(tech)
	if err != nil {
		return err
	}
	if tech == techutils.Pip || tech == techutils.Poetry || tech == techutils.Pipenv {
		rtManager, err = boundedRedirectManager(serverDetails)
		if err != nil {
			return err
		}
	}
	rtAuth, err := serverDetails.CreateArtAuthConfig()
	if err != nil {
		return err
	}
	rootNode := depTreeResult.FullDepTrees[0]
	// Extract project name from the dependency tree
	_, projectName, projectScope, projectVersion := getUrlNameAndVersionByTech(tech, rootNode, nil, "", "")
	if tech == techutils.HuggingFaceML {
		// rootNode.Id is a directory/project name, not a "repo_id:revision" model
		// reference — getHuggingFaceNameAndVersion defaults a missing revision to
		// "main", which would otherwise tack on a spurious ":main" here.
		projectName, projectVersion = rootNode.Id, ""
	}
	// If the project name is not set, fall back to the script name (--script) or the
	// current working directory name.
	if projectName == "" {
		if params.ScriptPath != "" {
			projectName = filepath.Base(params.ScriptPath)
		} else {
			workPath, err := os.Getwd()
			if err != nil {
				return err
			}
			projectName = filepath.Base(workPath)
		}
	}
	fullProjectName := projectName
	if projectVersion != "" {
		fullProjectName += ":" + projectVersion
	}
	rootNodes := map[string]struct{}{}
	for _, tree := range depTreeResult.FullDepTrees {
		rootNodes[tree.Id] = struct{}{}
	}
	packageNodeCount := countPackageNodes(rootNodes, depTreeResult.FlatTree.Nodes)
	if ca.Progress() != nil {
		ca.Progress().SetHeadlineMsg(fmt.Sprintf("Fetch curation status for %s graph with %v nodes project name: %s", tech.ToFormal(), packageNodeCount, fullProjectName))
	}
	if projectScope != "" {
		projectName = projectScope + "/" + projectName
	}
	if ca.parallelRequests == 0 {
		ca.parallelRequests = cliutils.Threads
	}
	var packagesStatus []*PackageStatus
	analyzer := treeAnalyzer{
		rtManager:             rtManager,
		extractPoliciesRegex:  ca.extractPoliciesRegex,
		rtAuth:                rtAuth,
		httpClientDetails:     rtAuth.CreateHttpClientDetails(),
		url:                   rtAuth.GetUrl(),
		repo:                  ca.PackageManagerConfig.TargetRepo(),
		tech:                  tech,
		parallelRequests:      ca.parallelRequests,
		downloadUrls:          depTreeResult.DownloadUrls,
		includeCachedPackages: ca.includeCachedPackages,
		hfExplicitModel:       tech == techutils.HuggingFaceML && ca.huggingFaceModel != "",
	}

	// Fetch status for each node from a flatten graph which, has no duplicate nodes.
	packagesStatusMap := sync.Map{}
	err = analyzer.fetchNodesStatus(depTreeResult.FlatTree, &packagesStatusMap, rootNodes)
	// Auth errors are unrecoverable — abort before building a misleading partial report.
	if analyzer.cancelled.Load() {
		return err
	}
	analyzer.GraphsRelations(depTreeResult.FullDepTrees, &packagesStatusMap,
		&packagesStatus)
	sort.Slice(packagesStatus, func(i, j int) bool {
		return packagesStatus[i].ParentName < packagesStatus[j].ParentName
	})
	warnings := depTreeResult.Warnings
	if len(analyzer.hfUnresolvedNodes) > 0 {
		sort.Strings(analyzer.hfUnresolvedNodes)
		warnings = append(warnings, fmt.Sprintf(
			"Hugging Face: %d model reference(s) could not be resolved against the registry (HTTP 404) and were NOT audited:\n  %s\nVerify the repo id/revision are correct and the repo is accessible from this Artifactory instance.",
			len(analyzer.hfUnresolvedNodes), strings.Join(analyzer.hfUnresolvedNodes, "\n  ")))
		// Excluded from the total — unresolved nodes were never actually audited.
		packageNodeCount -= len(analyzer.hfUnresolvedNodes)
	}
	key := strings.TrimSuffix(fmt.Sprintf("%s:%s", projectName, projectVersion), ":")
	results[uniqueReportKey(results, key, tech)] = &CurationReport{
		packagesStatus:        packagesStatus,
		totalNumberOfPackages: packageNodeCount,
		hfPartial:             len(analyzer.hfUnresolvedNodes) > 0,
		warnings:              warnings,
		huggingFaceReport:     tech == techutils.HuggingFaceML,
	}
	return err
}

func getSelectedPackages(requestedRows string, blockedPackages []*PackageStatus) (selectedPackages []*PackageStatus, ok bool) {
	// Accepts the following formats: "all", or a comma-separated list of row numbers, or ranges of row numbers."
	validFormat := regexp.MustCompile(`^(all|(\d+(-\d+)?)(,\d+(-\d+)?)*$)`)
	if !validFormat.MatchString(requestedRows) {
		log.Output("Invalid request format.\n\n")
		return nil, false
	}

	if requestedRows == "all" {
		return blockedPackages, true
	}

	var indices = make(map[int]bool)
	parts := strings.Split(requestedRows, ",")
	// Iterate over the parts and add the indices to the list. Relies on the fact that the format is valid.
	for _, part := range parts {
		// If the part is a range, mark all the indices in the range as selected
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			startRow, _ := strconv.Atoi(rangeParts[0])
			endRow, _ := strconv.Atoi(rangeParts[1])
			for i := startRow; i <= endRow; i++ {
				indices[i] = true
			}
		} else {
			// If the part is a single index, mark it as selected
			i, _ := strconv.Atoi(part)
			indices[i] = true
		}
	}

	// Check if the indices are valid
	for i := range indices {
		if i < 1 || i > len(blockedPackages) {
			log.Error("Invalid row number: %d", i)
			return nil, false
		}
	}

	// Prepare response, preserve original order
	for i, pkg := range blockedPackages {
		if indices[i+1] {
			selectedPackages = append(selectedPackages, pkg)
		}
	}
	return selectedPackages, true
}

func (ca *CurationAuditCommand) sendWaiverRequests(pkgs []*PackageStatus, msg string, serverDetails *config.ServerDetails) (requestStatuses []WaiverResponse, err error) {
	log.Output("Submitting waiver request...\n\n")
	rtAuth, err := serverDetails.CreateArtAuthConfig()
	if err != nil {
		return nil, err
	}
	rtManager, err := rtUtils.CreateServiceManager(serverDetails, 2, 0, false)
	if err != nil {
		return nil, err
	}
	clientDetails := rtAuth.CreateHttpClientDetails()
	clientDetails.Headers["X-Artifactory-Curation-Request-Waiver"] = msg
	for _, pkg := range pkgs {
		response, body, _, err := rtManager.Client().SendGet(pkg.BlockedPackageUrl, true, &clientDetails)
		if err != nil {
			return nil, fmt.Errorf("failed sending waiver request %v", err)
		}
		if err = errorutils.CheckResponseStatusWithBody(response, body, http.StatusForbidden); err != nil {
			return nil, fmt.Errorf("recieived unexpected response while sending waiver request: %v", err)
		}
		var resp struct {
			Errors []struct {
				Status  int    `json:"status"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed decoding waiver request status %v", err)
		}

		if len(resp.Errors) != 1 {
			return nil, fmt.Errorf("got unexpected response structure while sending waiver request: %s", body)
		}
		parts := strings.Split(resp.Errors[0].Message, "|")
		if len(parts) != 2 {
			return nil, fmt.Errorf("failed decoding waiver request response: %s", resp.Errors[0].Message)
		}

		waiverResponse := WaiverResponse{PkgName: pkg.PackageName}
		waiverResponse.WaiverID, waiverResponse.Status = parts[0], parts[1]

		switch waiverResponse.Status {
		case "pending":
			waiverResponse.Explanation = WaiverRequestPending
		case "approved":
			waiverResponse.Explanation = WaiverRequestApproved
		case "forbidden":
			waiverResponse.Explanation = WaiverRequestForbidden
		case "error":
			waiverResponse.Explanation = WaiverRequestError
		}
		requestStatuses = append(requestStatuses, waiverResponse)
	}
	return requestStatuses, nil
}

func getWaiverRequestParams(blockedPackages []*PackageStatus) (selectedPackages []*PackageStatus, requestMsg string) {
	for {
		requestedRows := ioutils.AskStringWithDefault("", "Please enter the row number(s) for which you want to request a waiver (comma-separated for multiple, range, or “all”)", "all")
		if pkgs, ok := getSelectedPackages(requestedRows, blockedPackages); ok {
			selectedPackages = pkgs
			break
		}
	}
	for {
		requestMsg = ioutils.AskString("", "Please enter the reason for the waiver request:", false, false)
		if len(requestMsg) >= 5 && len(requestMsg) <= 300 {
			break
		}
		log.Output("The reason must be between 5 and 300 characters.\n\n")
	}
	return selectedPackages, requestMsg
}

func (ca *CurationAuditCommand) requestWaiver(blockedPackages []*PackageStatus) error {
	if !coreutils.AskYesNo("Do you want to request a waiver for any of the listed packages?", false) {
		return nil
	}
	selectedPackages, requestMsg := getWaiverRequestParams(blockedPackages)
	if len(selectedPackages) == 0 {
		return nil
	}
	serverDetails, _ := ca.ServerDetails()
	if serverDetails == nil {
		return errorutils.CheckError(errors.New("server details are missing"))
	}
	pkgStatusTable, err := ca.sendWaiverRequests(selectedPackages, requestMsg, serverDetails)
	if err != nil {
		return errorutils.CheckErrorf("failed sending waiver request: %v", err)
	}

	return coreutils.PrintTable(pkgStatusTable, "Waiver request submitted!", "Requested 0 waivers", true)
}

func printResult(format outFormat.OutputFormat, projectPath string, packagesStatus []*PackageStatus) error {
	if format == "" {
		format = outFormat.Table
	}
	log.Output(fmt.Sprintf("Found %v blocked packages for project %s", countBlockedPackages(packagesStatus), projectPath))
	switch format {
	case outFormat.Json:
		if len(packagesStatus) > 0 {
			err := output.PrintJson(packagesStatus)
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
			ID:             fmt.Sprintf("%d%s", index+1, uniqLineSep),
			ParentName:     pkgStatus.ParentName + uniqLineSep,
			ParentVersion:  pkgStatus.ParentVersion + uniqLineSep,
			PackageName:    pkgStatus.PackageName + uniqLineSep,
			PackageVersion: pkgStatus.PackageVersion + uniqLineSep,
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
	// If the technology is Docker, we need to get the repository config from the Docker image name
	if tech == techutils.Docker {
		repoConfig, err := docker.GetDockerRepositoryConfig(ca.DockerImageName())
		if err != nil {
			return err
		}
		ca.setPackageManagerConfig(repoConfig)
		return nil
	}

	// Hugging Face derives its repo from HF_ENDPOINT, not from a 'jf <tech>-config' file.
	// Pass in the already-resolved (--server-id-aware) server, rather than letting
	// GetHuggingFaceRepositoryConfig reload the CLI default and potentially probe a
	// different Artifactory instance than the one this command was invoked against.
	if tech == techutils.HuggingFaceML {
		serverDetails, err := ca.ServerDetails()
		if err != nil {
			return err
		}
		repoConfig, err := huggingface.GetHuggingFaceRepositoryConfig(serverDetails)
		if err != nil {
			return err
		}
		ca.setPackageManagerConfig(repoConfig)
		return nil
	}

	// When --run-native is set for npm, read the Artifactory URL and repo name from the
	// project's .npmrc via native npm config — no jf npm-config/npm.yaml required.
	if ca.RunNative() && tech == techutils.Npm {
		return ca.setRepoFromNpmrc()
	}

	// Pnpm always reads from .npmrc — there is no 'jf pnpm-config' command.
	// pnpm shares the npm registry protocol, so the same .npmrc key/URL format applies.
	if tech == techutils.Pnpm {
		return ca.setRepoFromNpmrcForPnpm()
	}

	// uv reads Artifactory repo details from ~/.config/uv/uv.toml — no 'jf uv-config' required.
	if tech == techutils.Uv {
		return ca.setRepoFromUvToml()
	}

	if tech == techutils.Pipenv {
		return ca.setRepoFromPipfile()
	}

	// Yarn V4 uses native mode: no jf yarn-config / yarn.yaml required.
	// Detect the running yarn version and route to the appropriate path.
	// Version detection failures are fatal — silently falling through to the
	// V2/V3 path would use different flags and break the audit.
	if tech == techutils.Yarn {
		yarnExecPath, yarnExecErr := bibuildutils.GetYarnExecutable()
		if yarnExecErr != nil {
			return fmt.Errorf("could not locate the yarn executable: %w. Ensure yarn is installed and available on PATH before running 'jf ca'", yarnExecErr)
		}
		workingDir, wdErr := coreutils.GetWorkingDirectory()
		if wdErr != nil {
			return fmt.Errorf("could not determine working directory for yarn version detection: %w", wdErr)
		}
		versionStr, versionErr := bibuildutils.GetVersion(yarnExecPath, workingDir)
		if versionErr != nil {
			return fmt.Errorf("could not detect yarn version: %w. Ensure the yarn binary at %q is functional (try 'yarn --version') before running 'jf ca'", versionErr, yarnExecPath)
		}
		yarnVersion := version.NewVersion(versionStr)
		if yarnVersion.Compare(yarntech.YarnV4Version) <= 0 {
			return ca.setRepoFromYarnrcForYarnV4(yarnExecPath, workingDir)
		}
		// V2/V3: fall through to getRepoParams (yarn.yaml / npm.yaml).
	}

	resolverParams, err := ca.getRepoParams(tech.GetProjectType())
	if err != nil {
		// npm and yarn share the same Artifactory npm API for curation, so their
		// repository configs are interchangeable. Fall back to the sibling tech's
		// config when the primary one is missing (e.g. the project was configured
		// with 'jf yarn-config' but is detected as npm because yarn.lock is absent).
		primaryErr := err
		switch tech {
		case techutils.Npm:
			resolverParams, err = ca.getRepoParams(techutils.Yarn.GetProjectType())
		case techutils.Yarn:
			resolverParams, err = ca.getRepoParams(techutils.Npm.GetProjectType())
		}
		if err != nil {
			// Return the primary tech's error so the user sees the correct command.
			// Yarn's CLI config command is 'jf yarn-config', not 'jf yarn c'.
			if tech == techutils.Yarn {
				return errorutils.CheckErrorf("no config file was found! Before running jf ca on a yarn project for the first time, the project should be configured using the 'jf yarn-config' command")
			}
			return primaryErr
		}
	}
	ca.setPackageManagerConfig(resolverParams)
	return nil
}

// setRepoFromPipfile detects the Artifactory PyPI source for pipenv curation.
//
// Detection priority:
//  1. pipenv.yaml — explicit 'jf pipenv-config'.
//  2. User pip.conf index-url — Artifactory "Set me up" for pip.
//  3. Pipfile [[source]] — Artifactory URL declared directly in the Pipfile.
func (ca *CurationAuditCommand) setRepoFromPipfile() error {
	projectType := techutils.Pipenv.GetProjectType()
	_, configExists, err := project.GetProjectConfFilePath(projectType)
	if err != nil {
		return err
	}

	if configExists {
		resolverParams, err := ca.getRepoParams(projectType)
		if err != nil {
			return err
		}
		configuredServer, err := resolverParams.ServerDetails()
		if err != nil {
			return err
		}
		fallbackServer, _ := ca.ServerDetails()
		server, repo, err := python.ResolvePipfileArtifactorySource("Pipfile", configuredServer, resolverParams.TargetRepo(), fallbackServer)
		if err != nil {
			return err
		}
		repoConfig := (&project.RepositoryConfig{}).SetTargetRepo(repo).SetServerDetails(server)
		ca.setPackageManagerConfig(repoConfig)
		ca.SetDepsRepo(repo)
		return nil
	}

	configuredServer, configuredRepo, pipConfPath, err := python.ParsePipConfigIndexUrl(python.DefaultPipConfPaths()...)
	if err != nil {
		return err
	}
	fallbackServer, _ := ca.ServerDetails()
	if configuredRepo != "" && configuredServer != nil {
		server, repo, err := python.ResolvePipfileArtifactorySource("Pipfile", configuredServer, configuredRepo, fallbackServer)
		if err != nil {
			return err
		}
		repoConfig := (&project.RepositoryConfig{}).
			SetTargetRepo(repo).
			SetServerDetails(server)
		ca.setPackageManagerConfig(repoConfig)
		ca.SetDepsRepo(repo)
		log.Info(fmt.Sprintf("pipenv: using Artifactory repository %q from %s", repo, pipConfPath))
		return nil
	}

	server, repo, err := python.ResolvePipfileArtifactorySource("Pipfile", nil, "", fallbackServer)
	if err != nil {
		return err
	}
	if repo != "" && server != nil {
		repoConfig := (&project.RepositoryConfig{}).
			SetTargetRepo(repo).
			SetServerDetails(server)
		ca.setPackageManagerConfig(repoConfig)
		ca.SetDepsRepo(repo)
		log.Info(fmt.Sprintf("pipenv: using Artifactory repository %q from Pipfile [[source]]", repo))
		return nil
	}

	return errorutils.CheckErrorf(
		"curation-audit for pipenv requires an Artifactory PyPI resolver. " +
			"Either run 'jf pipenv-config', configure index-url in your user pip.conf via " +
			"Artifactory 'Set me up', or add an Artifactory [[source]] entry to your Pipfile.")
}

// validateRunNativeForTech rejects --run-native for techs that don't implement
// native-config semantics. npm uses it to read Artifactory details from .npmrc;
// pnpm/yarn/uv accept it as a no-op (they always resolve natively). Extend the
// allow-list below when a new tech adds the matching native-config flow.
func validateRunNativeForTech(tech techutils.Technology, runNative bool) error {
	if !runNative {
		return nil
	}
	// Extend this set when a new tech grows native-config semantics on
	// both 'jf <tech>' and 'jf ca'.
	supported := map[techutils.Technology]struct{}{
		techutils.Npm: {},
		// pnpm always resolves from .npmrc, so --run-native is a redundant no-op
		// rather than an error (a warning is emitted in auditTree).
		techutils.Pnpm: {},
		// --run-native has no effect for yarn regardless of version; a warning is emitted in auditTree.
		techutils.Yarn: {},
		// uv always resolves natively; no 'jf uv-config' exists,
		// so --run-native is a redundant no-op.
		techutils.Uv: {},
	}
	if _, ok := supported[tech]; ok {
		return nil
	}
	if tech == techutils.Pipenv {
		return errorutils.CheckErrorf(
			"--run-native is not supported for 'pipenv' projects. " +
				"Run 'jf ca' without --run-native; the repository is resolved automatically from " +
				"'jf pipenv-config', ~/.pip/pip.conf, or the Artifactory [[source]] entry in your Pipfile.")
	}
	return errorutils.CheckErrorf(
		"--run-native is not supported for '%s' projects. "+
			"Run 'jf ca' without --run-native; configure the resolution repository using 'jf %s-config'.",
		tech.String(), tech.String())
}

// setRepoFromNpmrc builds PackageManagerConfig by reading the npm registry URL from the
// native npm configuration (respecting .npmrc and Volta), then parsing the Artifactory
// base URL and repository name from it.
// Authentication is taken from the jfrog-cli.conf server entry (via ca.ServerDetails()) —
// the same credentials the user configured with 'jf c'. Only the Artifactory URL and
// repository name are sourced from .npmrc, so 'jf npm-config' is not required.
func (ca *CurationAuditCommand) setRepoFromNpmrc() error {
	registryConfig, err := npmtech.GetNativeNpmRegistryConfig()
	if err != nil {
		return fmt.Errorf("--run-native: failed to read Artifactory details from .npmrc: %w", err)
	}

	// Use auth from the jfrog server config (jfrog-cli.conf) — it holds properly stored
	// credentials. Only override the ArtifactoryUrl with what .npmrc reports so the
	// Curation HEAD requests go to the right repository.
	serverDetails, err := ca.ServerDetails()
	if err != nil || serverDetails == nil {
		// No server configured — fall back to whatever auth .npmrc provides.
		serverDetails = &config.ServerDetails{
			ArtifactoryUrl: registryConfig.ArtifactoryUrl,
			AccessToken:    registryConfig.AuthToken,
		}
	} else {
		serverDetails.ArtifactoryUrl = registryConfig.ArtifactoryUrl
	}

	repoConfig := (&project.RepositoryConfig{}).
		SetTargetRepo(registryConfig.RepoName).
		SetServerDetails(serverDetails)
	ca.setPackageManagerConfig(repoConfig)
	log.Info(fmt.Sprintf("--run-native: using Artifactory URL %q and repository %q from .npmrc", registryConfig.ArtifactoryUrl, registryConfig.RepoName))
	return nil
}

// setRepoFromNpmrcForPnpm reads Artifactory connection details from the project's .npmrc
// via the pnpm CLI. pnpm uses the same .npmrc format and registry protocol as npm, so the
// URL parsing logic is identical. This is always called for pnpm — there is no 'jf pnpm-config'.
//
// Auth priority:
//  1. Token from .npmrc — preferred, because it is scoped to the exact registry URL.
//  2. Token from 'jf c' server config — used as fallback when .npmrc carries no token
//     (e.g. user relies on a jf-managed credential store).
func (ca *CurationAuditCommand) setRepoFromNpmrcForPnpm() error {
	registryConfig, err := pnpmtech.GetNativePnpmRegistryConfig()
	if err != nil {
		log.Warn("Ensure the pnpm registry is configured in .npmrc (e.g. registry=https://<host>/artifactory/api/npm/<repo>/)")
		return fmt.Errorf("pnpm: failed to read Artifactory details from .npmrc: %w", err)
	}

	var serverDetails *config.ServerDetails
	if registryConfig.AuthToken != "" {
		// .npmrc has an auth token that matches the registry — use it directly.
		log.Debug("pnpm: using auth token from .npmrc")
		serverDetails = &config.ServerDetails{
			ArtifactoryUrl: registryConfig.ArtifactoryUrl,
			AccessToken:    registryConfig.AuthToken,
		}
	} else {
		// No token in .npmrc — fall back to whatever 'jf c' has stored, overriding
		// only the Artifactory URL so requests go to the correct registry.
		log.Debug("pnpm: no token in .npmrc — using 'jf c' server credentials")
		serverDetails, err = ca.ServerDetails()
		if err != nil || serverDetails == nil {
			return fmt.Errorf("pnpm: no auth token found in .npmrc and no 'jf c' server configured: %w", err)
		}
		serverDetails.ArtifactoryUrl = registryConfig.ArtifactoryUrl
	}

	repoConfig := (&project.RepositoryConfig{}).
		SetTargetRepo(registryConfig.RepoName).
		SetServerDetails(serverDetails)
	ca.setPackageManagerConfig(repoConfig)
	log.Info(fmt.Sprintf("pnpm: using Artifactory URL %q and repository %q from .npmrc", registryConfig.ArtifactoryUrl, registryConfig.RepoName))
	return nil
}

// setRepoFromYarnrcForYarnV4 reads Artifactory connection details from the
// project's .yarnrc.yml via the Yarn CLI. Yarn V4 uses native mode — no
// jf yarn-config step is required; the registry URL and auth token live in
// .yarnrc.yml already. This is always called for Yarn V4 curation.
//
// Auth priority:
//  1. Token from .yarnrc.yml — preferred, scoped to the exact registry URL.
//  2. Token from 'jf c' server config — fallback when .yarnrc.yml carries no token.
func (ca *CurationAuditCommand) setRepoFromYarnrcForYarnV4(yarnExecPath, workingDir string) error {
	registryConfig, err := yarntech.GetNativeYarnV4RegistryConfig(yarnExecPath, workingDir)
	if err != nil {
		log.Warn("Ensure npmRegistryServer is configured in .yarnrc.yml (e.g. npmRegistryServer: \"https://<host>/artifactory/api/npm/<repo>/\")")
		return fmt.Errorf("yarn V4: failed to read Artifactory details from .yarnrc.yml: %w", err)
	}

	var serverDetails *config.ServerDetails
	if registryConfig.AuthToken != "" {
		log.Debug("yarn V4: using auth token from .yarnrc.yml")
		serverDetails = &config.ServerDetails{
			ArtifactoryUrl: registryConfig.ArtifactoryUrl,
			AccessToken:    registryConfig.AuthToken,
		}
	} else {
		log.Debug("yarn V4: no token in .yarnrc.yml — using 'jf c' server credentials")
		base, sdErr := ca.ServerDetails()
		if sdErr != nil || base == nil {
			return fmt.Errorf("yarn V4: no auth token found in .yarnrc.yml and no 'jf c' server configured: %w", sdErr)
		}
		// Copy before mutating: ca.ServerDetails() returns the shared struct, and
		// overwriting its URL would leak to other techs in a multi-tech audit.
		copied := *base
		copied.ArtifactoryUrl = registryConfig.ArtifactoryUrl
		serverDetails = &copied
	}

	repoConfig := (&project.RepositoryConfig{}).
		SetTargetRepo(registryConfig.RepoName).
		SetServerDetails(serverDetails)
	ca.setPackageManagerConfig(repoConfig)
	// Populate depsRepo on the audit-params interface so getBuildInfoParamsByTech
	// returns the correct repository name. For V4 native mode the user never passes
	// --deps-repo, so ca.DepsRepo() would otherwise be "". The repo name is consumed
	// downstream by the curation error messages and probeBlockedDirectDeps HEAD checks
	// (V4 does not route installs through the curation endpoint).
	ca.SetDepsRepo(registryConfig.RepoName)
	log.Info(fmt.Sprintf("yarn V4: using Artifactory URL %q and repository %q from .yarnrc.yml", registryConfig.ArtifactoryUrl, registryConfig.RepoName))
	return nil
}

// setRepoFromUvToml resolves the Artifactory URL and repo name via GetNativeUvRegistryConfig
// (~/.config/uv/uv.toml first, then pyproject.toml [[tool.uv.index]] as a fallback) and
// configures the command.
func (ca *CurationAuditCommand) setRepoFromUvToml() error {
	registryConfig, err := uvtech.GetNativeUvRegistryConfig()
	if err != nil {
		log.Warn("Ensure an [[index]] entry with an Artifactory PyPI URL is set in ~/.config/uv/uv.toml")
		return fmt.Errorf("uv: failed to read Artifactory details from uv.toml: %w", err)
	}

	base, sdErr := ca.ServerDetails()
	if sdErr != nil {
		return fmt.Errorf("uv: failed to read 'jf c' server configuration: %w", sdErr)
	}
	if base == nil {
		return errorutils.CheckErrorf("uv: no 'jf c' server configured")
	}
	if !sameArtifactoryHost(base.ArtifactoryUrl, registryConfig.ArtifactoryUrl) {
		return errorutils.CheckErrorf(
			"uv: the Artifactory URL declared in pyproject.toml/uv.toml (%s) does not match the "+
				"configured 'jf c' server (%s) — refusing to send its credentials to a different host. "+
				"Align the two, or select the matching server with --server-id.",
			registryConfig.ArtifactoryUrl, base.ArtifactoryUrl)
	}
	copied := *base
	copied.ArtifactoryUrl = registryConfig.ArtifactoryUrl

	repoConfig := (&project.RepositoryConfig{}).
		SetTargetRepo(registryConfig.RepoName).
		SetServerDetails(&copied)
	ca.setPackageManagerConfig(repoConfig)
	ca.SetDepsRepo(registryConfig.RepoName)
	log.Info(fmt.Sprintf("uv: using Artifactory URL %q and repository %q from uv.toml", registryConfig.ArtifactoryUrl, registryConfig.RepoName))
	return nil
}

// sameArtifactoryHost reports whether configuredUrl and discoveredUrl share the same
// scheme and host[:port], ignoring path and trailing slashes.
func sameArtifactoryHost(configuredUrl, discoveredUrl string) bool {
	configured, err := url.Parse(configuredUrl)
	if err != nil || configured.Host == "" {
		return false
	}
	discovered, err := url.Parse(discoveredUrl)
	if err != nil || discovered.Host == "" {
		return false
	}
	return strings.EqualFold(configured.Host, discovered.Host) &&
		strings.EqualFold(configured.Scheme, discovered.Scheme)
}

func (ca *CurationAuditCommand) getRepoParams(projectType project.ProjectType) (*project.RepositoryConfig, error) {
	configFilePath, exists, err := project.GetProjectConfFilePath(projectType)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errorutils.CheckErrorf("no config file was found! Before running the %s command on a "+
			"project for the first time, the project should be configured using the 'jf %s c' command", projectType.String(), projectType.String())
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
			if nc.cancelled.Load() {
				break
			}
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
	// Auth errors are stored silently (not via errorsQueue) to avoid double-printing.
	// Surface them here so they propagate as a single error to the caller.
	if authErr, ok := nc.authErr.Load().(error); ok {
		multiErrors = errors.Join(authErr, multiErrors)
	}
	return multiErrors
}

func (nc *treeAnalyzer) fetchNodeStatus(node xrayUtils.GraphNode, p *sync.Map) error {
	packageUrls, name, scope, version := getUrlNameAndVersionByTech(nc.tech, &node, nc.downloadUrls, nc.url, nc.repo)
	if len(packageUrls) == 0 {
		// For an explicit --hugging-face-model spot-check, nc.url/nc.repo are always
		// resolved by this point, so a non-empty name with no download URL means
		// getHuggingFaceNameAndVersion rejected a '.'/'..' path segment in the repo id —
		// surface that clearly instead of silently reporting "0 blocked packages".
		if nc.tech == techutils.HuggingFaceML && nc.hfExplicitModel && name != "" {
			return errorutils.CheckErrorf("Hugging Face: repo id %q is invalid — path segments must not be '.' or '..'", name)
		}
		return nil
	}
	if scope != "" {
		name = scope + "/" + name
	}
	for _, packageUrl := range packageUrls {
		if nc.cancelled.Load() {
			return nil
		}
		requestDetails := nc.httpClientDetails.Clone()
		var resp *http.Response
		var err error
		if nc.tech == techutils.Pip || nc.tech == techutils.Poetry || nc.tech == techutils.Pipenv {
			resp, _, err = nc.sendBoundedRequest(http.MethodHead, packageUrl, requestDetails)
		} else {
			resp, _, err = nc.rtManager.Client().SendHead(packageUrl, requestDetails)
		}
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			// Store the error silently (not returned) so errorsQueue.AddError is never
			// called and the message is not logged here. fetchNodesStatus picks it up
			// after the runner finishes and returns it once to the caller.
			if nc.cancelled.CompareAndSwap(false, true) {
				nc.authErr.Store(fmt.Errorf("authentication failed (401 Unauthorized) for Curation request to %s (package %s:%s).\n"+
					"The credentials configured via 'jf c' are not valid for the Artifactory instance at that URL.\n"+
					"Run 'jf c' to update your server configuration, or verify that the correct server-id is configured", packageUrl, name, version))
			}
			return nil
		}
		// HF 404: hard error for an explicit spot-check, warning for auto-discovery.
		if resp != nil && resp.StatusCode == http.StatusNotFound && nc.tech == techutils.HuggingFaceML {
			if nc.hfExplicitModel {
				return errorutils.CheckErrorf("Hugging Face: %s:%s could not be resolved at %s (HTTP 404) — verify the repo id and revision are correct", name, version, packageUrl)
			}
			log.Debug(fmt.Sprintf("Hugging Face: %s:%s not resolvable at %s (HTTP 404) — recording as unaudited", name, version, packageUrl))
			nc.hfUnresolvedMu.Lock()
			nc.hfUnresolvedNodes = append(nc.hfUnresolvedNodes, fmt.Sprintf("%s:%s", name, version))
			nc.hfUnresolvedMu.Unlock()
			continue
		}
		if err != nil {
			if resp != nil && resp.StatusCode >= 400 {
				return errorutils.CheckErrorf(errorTemplateHeadRequest, packageUrl, name, version, resp.StatusCode, err)
			}
			if resp == nil || resp.StatusCode != http.StatusForbidden {
				return err
			}
		}
		// Due to CreateAlternativeVersionForms, it's expected that for NuGet some of the URLs will be missing
		if resp.StatusCode == http.StatusNotFound && nc.tech == techutils.Nuget {
			continue
		}
		if resp != nil && resp.StatusCode >= 400 && resp.StatusCode != http.StatusForbidden {
			return errorutils.CheckErrorf(errorTemplateHeadRequest, packageUrl, name, version, resp.StatusCode, err)
		}
		if resp.StatusCode == http.StatusForbidden || (nc.includeCachedPackages && resp.StatusCode == http.StatusOK) {
			pkStatus, err := nc.getBlockedPackageDetails(packageUrl, name, version)
			if err != nil {
				return err
			}
			if pkStatus != nil {
				p.Store(pkStatus.BlockedPackageUrl, pkStatus)
			}
		}
		if nc.tech == techutils.Nuget {
			// DotNet can have multiple URLs only due to CreateAlternativeVersionForms.
			// Once the matching version was found, we can stop iterating.
			// See CreateAlternativeVersionForms for more details.
			return nil
		}
	}
	return nil
}

func (nc *treeAnalyzer) sendBoundedRequest(method, requestURL string, details *httputils.HttpClientDetails) (*http.Response, []byte, error) {
	repositoryURL := fmt.Sprintf("%s/api/pypi/%s/", strings.TrimSuffix(nc.url, "/"), nc.repo)
	boundary, err := redirect.NewEndpointBoundary(repositoryURL)
	if err != nil {
		return nil, nil, err
	}
	return redirect.SendWithBoundedRedirects(nc.rtManager.Client(), method, requestURL, details,
		boundary, redirect.MaxAuthenticatedRedirects)
}

// runCvsFallback is called when pip, poetry, or uv resolution failed because CVS
// stripped a pinned version from the simple index (CvsBlockedError). It uses
// the PyPI metadata API to recover each blocker's real download URL, probes
// the normal (non-audit) download path, and renders the policy in a partial
// curation table.
func (ca *CurationAuditCommand) runCvsFallback(cvsErr *python.CvsBlockedError, tech techutils.Technology, results map[string]*CurationReport) error {
	rtManager, serverDetails, err := ca.getRtManagerAndAuth(tech)
	if err != nil {
		return fmt.Errorf("curation-blocked resolution fallback: failed to get Artifactory manager (%w); %s error: %w", err, tech, cvsErr)
	}
	if tech == techutils.Pip || tech == techutils.Poetry || tech == techutils.Pipenv {
		rtManager, err = boundedRedirectManager(serverDetails)
		if err != nil {
			return fmt.Errorf("curation-blocked resolution fallback: failed to create bounded HTTP manager: %w", err)
		}
	}
	rtAuth, err := serverDetails.CreateArtAuthConfig()
	if err != nil {
		return fmt.Errorf("curation-blocked resolution fallback: failed to create auth config (%w); %s error: %w", err, tech, cvsErr)
	}
	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: ca.extractPoliciesRegex,
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 ca.PackageManagerConfig.TargetRepo(),
		tech:                 tech,
	}
	packagesStatus := analyzer.fetchCvsBlockedStatus(cvsErr.Packages)
	if len(packagesStatus) == 0 {
		// No policy match found for the stripped version(s) — surface the
		// generic curation-block guidance instead of the bare error.
		if msgToUser := technologies.GetMsgToUserForCurationBlock(true, tech, cvsErr.Cause.Error()); msgToUser != "" {
			return errors.Join(cvsErr.Cause, errors.New(msgToUser))
		}
		return cvsErr
	}
	workPath, wdErr := osGetwd()
	if wdErr != nil {
		log.Warn(fmt.Sprintf("curation-blocked resolution fallback: could not determine working directory (%v) — reporting under fallback key", wdErr))
		workPath = "unknown-project"
	}
	results[uniqueReportKey(results, filepath.Base(workPath), tech)] = &CurationReport{
		packagesStatus:        packagesStatus,
		totalNumberOfPackages: len(packagesStatus),
		isPartial:             true,
	}
	return nil
}

// cleanupForcedNpmDebugLog removes the log our forced --logs-max override caused npm to write,
// when logs-max=0. Success-path counterpart to runNpmLogFallback's cleanup; baselineKey (see
// npmDebugLogNewestKey) ensures a stale pre-existing log is never removed by mistake.
func cleanupForcedNpmDebugLog(logsDir string, logsMaxWasZero bool, baselineKey int64) {
	if !logsMaxWasZero {
		return
	}
	logFilePaths, err := findNewestNpmDebugLogChunksAfter(logsDir, baselineKey)
	if err != nil {
		return
	}
	for _, logFilePath := range logFilePaths {
		if rmErr := os.Remove(logFilePath); rmErr != nil {
			log.Debug(fmt.Sprintf("npm curation: failed to remove forced debug log %q: %v", logFilePath, rmErr))
		}
	}
}

// runNpmLogFallback reconstructs a partial curation report from npm's debug log (under
// logsDir — npm's "logs-dir" config) when the npm tree-build install crashes, since buildDeps
// completes before reify can fail. Falls back to originalErr unchanged if nothing is recoverable.
//
// baselineKey (see npmDebugLogNewestKey) is the newest log's identity captured just before this
// invocation ran — only a log newer than that is read, so a stale log from an earlier run
// sharing the same logs-dir (e.g. a shared CI cache) is never mistaken for this crash's own.
//
// logsMaxWasZero means our forced --logs-max override is the only reason a debug log exists
// for this run, so the log files read here are removed afterward; otherwise npm's own
// rotation manages them like any other run.
func (ca *CurationAuditCommand) runNpmLogFallback(logsDir string, tech techutils.Technology, results map[string]*CurationReport, originalErr error, logsMaxWasZero bool, baselineKey int64) error {
	entries, blockedPackages, logFilePaths, parseErr := parseNpmDebugLog(logsDir, baselineKey)
	if logsMaxWasZero {
		defer func() {
			for _, logFilePath := range logFilePaths {
				_ = os.Remove(logFilePath)
			}
		}()
	}
	if parseErr != nil {
		log.Debug(fmt.Sprintf("npm curation debug-log fallback: failed to parse debug log (%v); original error: %s", parseErr, originalErr.Error()))
		return originalErr
	}
	if len(entries) == 0 {
		// Nothing recoverable — install likely failed before buildDeps ever started.
		return originalErr
	}

	rtManager, serverDetails, err := ca.getRtManagerAndAuth(tech)
	if err != nil {
		return fmt.Errorf("npm curation debug-log fallback: failed to get Artifactory manager (%w); %s error: %w", err, tech, originalErr)
	}
	rtAuth, err := serverDetails.CreateArtAuthConfig()
	if err != nil {
		return fmt.Errorf("npm curation debug-log fallback: failed to create auth config (%w); %s error: %w", err, tech, originalErr)
	}

	workPath, wdErr := osGetwd()
	if wdErr != nil {
		log.Warn(fmt.Sprintf("npm curation debug-log fallback: could not determine working directory (%v) — reporting under fallback key", wdErr))
		workPath = "unknown-project"
	}
	rootName, rootVersion, pkgErr := readNpmProjectNameVersion(workPath)
	if pkgErr != nil {
		// The graph walk only reaches anything if rootName/rootVersion match the log's real root.
		if logRootName, logRootVersion, ok := rootIdentityFromLogEntries(entries); ok {
			rootName, rootVersion = logRootName, logRootVersion
		} else {
			// Same convention auditTree itself uses when a project doesn't declare a name.
			rootName = filepath.Base(workPath)
		}
	}

	analyzer := treeAnalyzer{
		rtManager:            rtManager,
		extractPoliciesRegex: ca.extractPoliciesRegex,
		rtAuth:               rtAuth,
		httpClientDetails:    rtAuth.CreateHttpClientDetails(),
		url:                  rtAuth.GetUrl(),
		repo:                 ca.PackageManagerConfig.TargetRepo(),
		tech:                 tech,
	}

	preProcessMap := &sync.Map{}
	var advisoryWarnings []string
	seenKeys := map[string]bool{}
	seenRangeWarnings := map[string]bool{}
	for _, entry := range sortedNpmLogEntries(entries) {
		category := classifyBlankVersionEntry(entry, blockedPackages)

		if category == npmEntryUnresolvableRange {
			// Dedupe on (Name, Specifier) — never preempts a same-name entry in a probeable category.
			rangeKey := entry.Name + "@" + entry.Specifier
			if seenRangeWarnings[rangeKey] {
				continue
			}
			seenRangeWarnings[rangeKey] = true
			advisoryWarnings = append(advisoryWarnings, fmt.Sprintf(
				"Package '%s' (requested as '%s') could not be resolved to a specific version, so its curation status could not be checked. This is not necessarily a curation block — verify the dependency resolves correctly.",
				entry.Name, entry.Specifier))
			continue
		}

		// effectiveGraphVersion avoids collapsing distinct ETARGET/non-registry specifiers onto one key.
		effectiveVersion := effectiveGraphVersion(entry, blockedPackages)
		key, keyErr := npmPackageKey(tech, analyzer.url, analyzer.repo, entry.Name, effectiveVersion)
		if keyErr != nil {
			advisoryWarnings = append(advisoryWarnings, fmt.Sprintf(
				"Package '%s@%s' could not be checked against the curation policy (%v) — its status is unknown, not confirmed clean.",
				entry.Name, effectiveVersion, keyErr))
			continue
		}
		if seenKeys[key] {
			continue
		}
		seenKeys[key] = true

		switch category {
		case npmEntryResolved:
			pkgStatus, probeErr := analyzer.getBlockedPackageDetails(key, entry.Name, entry.Version)
			if probeErr != nil {
				advisoryWarnings = append(advisoryWarnings, fmt.Sprintf(
					"Package '%s@%s' could not be checked against the curation policy (%v) — its status is unknown, not confirmed clean.",
					entry.Name, entry.Version, probeErr))
				continue
			}
			if pkgStatus == nil {
				continue // genuinely clean — no row needed
			}
			preProcessMap.Store(key, pkgStatus)
		case npmEntryWholePackageBlocked:
			preProcessMap.Store(key, wholePackageBlockedStatus(entry, blockedPackages[entry.Name], tech))
		case npmEntryNonRegistrySpecifier:
			// Advisory only, not a table/JSON row — same treatment as the other
			// "curation never applied" categories, so it can't be mistaken for a real block.
			advisoryWarnings = append(advisoryWarnings, fmt.Sprintf(
				"Package '%s' (%s): Not evaluated: This dependency was not evaluated because it is resolved from a source "+
					"other than an npm registry (such as a Git URL, local path, or npm alias), bypassing Artifactory. "+
					"As a result, curation policies do not apply.",
				entry.Name, entry.Specifier))
		case npmEntryETARGET:
			pkgStatus, probeErr := analyzer.getBlockedPackageDetails(key, entry.Name, entry.Specifier)
			if probeErr != nil {
				advisoryWarnings = append(advisoryWarnings, fmt.Sprintf(
					"Package '%s@%s' could not be checked against the curation policy (%v) — its status is unknown, not confirmed clean.",
					entry.Name, entry.Specifier, probeErr))
				continue
			}
			if pkgStatus == nil {
				// Plain 404, no curation signal — not curation-relevant, advisory only.
				advisoryWarnings = append(advisoryWarnings, fmt.Sprintf(
					"Package '%s@%s' could not be resolved (no matching version found in the registry) — this is not a curation policy block. Verify the version in package.json.",
					entry.Name, entry.Specifier))
				continue
			}
			preProcessMap.Store(key, pkgStatus)
		}
	}

	graph := buildGraphFromLogEntries(entries, rootName, rootVersion, blockedPackages)
	var packagesStatus []*PackageStatus
	analyzer.GraphsRelations([]*xrayUtils.GraphNode{graph}, preProcessMap, &packagesStatus)

	// DepRelation is set per-edge by GraphsRelations, so this is correct even when the same
	// package name occurs as both a direct and a transitive dependency.
	for _, ps := range packagesStatus {
		if ps.PackageVersion == allVersionsBlockedText {
			applyTransitiveAwareRecommendation(ps, ps.DepRelation == directRelation)
		}
	}

	if len(packagesStatus) == 0 && len(advisoryWarnings) == 0 {
		return originalErr
	}

	results[uniqueReportKey(results, filepath.Base(workPath), tech)] = &CurationReport{
		packagesStatus:        packagesStatus,
		totalNumberOfPackages: len(packagesStatus),
		isPartial:             true,
		npmLogPartial:         true,
		npmLogOriginalErr:     originalErr.Error(),
		warnings:              advisoryWarnings,
	}
	return nil
}

// allVersionsBlockedText also doubles as the marker applyTransitiveAwareRecommendation uses
// to identify whole-package-blocked rows after the graph walk.
const allVersionsBlockedText = "All versions blocked"

// wholePackageBlockedStatus synthesizes a *PackageStatus straight from the log's notice+403
// evidence — no HEAD-check needed. Recommendation is filled in later by
// applyTransitiveAwareRecommendation, once the graph walk knows the parent.
func wholePackageBlockedStatus(entry npmLogEntry, info npmBlockedInfo, tech techutils.Technology) *PackageStatus {
	return &PackageStatus{
		PackageName:    entry.Name,
		PackageVersion: allVersionsBlockedText,
		Action:         blocked,
		BlockingReason: BlockingReasonPolicy,
		PkgType:        string(tech),
		Policy: []Policy{{
			Policy:      info.Policy,
			Condition:   info.Condition,
			Explanation: allVersionsBlockedText,
			// Recommendation is filled in by applyTransitiveAwareRecommendation.
		}},
	}
}

// applyTransitiveAwareRecommendation: "remove and replace" is only actionable when the
// blocked package is itself a direct dependency; otherwise name the real direct dependency.
// ps.Policy is reassigned, not mutated in place — fillGraphRelations clones *PackageStatus
// per edge via a shallow copy, so edges sharing a preProcessMap entry share the same array.
func applyTransitiveAwareRecommendation(ps *PackageStatus, isDirectDependency bool) {
	policies := make([]Policy, len(ps.Policy))
	copy(policies, ps.Policy)
	for i := range policies {
		if isDirectDependency {
			policies[i].Recommendation = "Remove this package from your project and replace with an alternate package"
		} else {
			policies[i].Recommendation = fmt.Sprintf(
				"%s is a transitive dependency of %s and cannot be removed directly. Apply a waiver if acceptable, or replace %s with an alternative that doesn't depend on %s.",
				ps.PackageName, ps.ParentName, ps.ParentName, ps.PackageName)
		}
	}
	ps.Policy = policies
}

// lookupPypiAllVersions calls the Artifactory PyPI metadata API for a package
// name (no version — returns all releases) and returns all available version
// strings. This endpoint is NOT filtered by CVS, so it includes versions that
// have been stripped from the simple index.
func (nc *treeAnalyzer) lookupPypiAllVersions(name string) ([]string, error) {
	metadataURL := fmt.Sprintf("%s/api/pypi/%s/pypi/%s/json",
		strings.TrimSuffix(nc.url, "/"), nc.repo, name)

	requestDetails := nc.httpClientDetails.Clone()
	var resp *http.Response
	var body []byte
	var err error
	if nc.tech == techutils.Pip || nc.tech == techutils.Poetry || nc.tech == techutils.Pipenv {
		resp, body, err = nc.sendBoundedRequest(http.MethodGet, metadataURL, requestDetails)
	} else {
		resp, body, _, err = nc.rtManager.Client().SendGet(metadataURL, true, requestDetails)
	}
	if err != nil {
		return nil, fmt.Errorf("all-versions metadata API request failed for %s: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("all-versions metadata API returned HTTP %d for %s", resp.StatusCode, name)
	}

	var meta struct {
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse all-versions metadata for %s: %w", name, err)
	}

	versions := make([]string, 0, len(meta.Releases))
	for v := range meta.Releases {
		versions = append(versions, v)
	}
	return versions, nil
}

// lookupPypiNormalDownloadURL calls the Artifactory PyPI metadata API for
// name@version (which CVS does NOT filter) and returns the first available
// download URL as a normal Artifactory path (no api/curation/audit/ prefix).
// The url field in the metadata JSON is a relative path such as
// "../../packages/packages/<hash>/<file>" — the stable anchor is "packages/"
// so we slice from there and prepend the Artifactory base + repo.
func (nc *treeAnalyzer) lookupPypiNormalDownloadURL(name, ver string) (string, error) {
	metadataURL := fmt.Sprintf("%s/api/pypi/%s/pypi/%s/%s/json",
		strings.TrimSuffix(nc.url, "/"), nc.repo, name, ver)

	requestDetails := nc.httpClientDetails.Clone()
	var resp *http.Response
	var body []byte
	var err error
	if nc.tech == techutils.Pip || nc.tech == techutils.Poetry || nc.tech == techutils.Pipenv {
		resp, body, err = nc.sendBoundedRequest(http.MethodGet, metadataURL, requestDetails)
	} else {
		resp, body, _, err = nc.rtManager.Client().SendGet(metadataURL, true, requestDetails)
	}
	if err != nil {
		return "", fmt.Errorf("metadata API request failed for %s==%s: %w", name, ver, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata API returned HTTP %d for %s==%s", resp.StatusCode, name, ver)
	}

	var meta struct {
		Urls []struct {
			PackageType string `json:"packagetype"`
			URL         string `json:"url"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("failed to parse metadata for %s==%s: %w", name, ver, err)
	}

	// Prefer wheel over source dist — probe whichever we find first.
	for _, preferred := range []string{"bdist_wheel", "sdist"} {
		for _, u := range meta.Urls {
			if u.PackageType != preferred {
				continue
			}
			// Strip the leading relative components; the stable part is "packages/...".
			idx := strings.Index(u.URL, "packages/")
			if idx < 0 {
				continue
			}
			return fmt.Sprintf("%s/api/pypi/%s/%s",
				strings.TrimSuffix(nc.url, "/"), nc.repo, u.URL[idx:]), nil
		}
	}
	return "", fmt.Errorf("no download URL found in metadata for %s==%s", name, ver)
}

// fetchCvsBlockedStatus recovers the curation policy for each CVS-blocked package:
//
//  1. For range-based blockers (PinnedRequirement.VersionRange set): resolve the
//     newest version satisfying the range via the unfiltered all-versions metadata API.
//  2. Call the version-specific metadata API to get the normal download URL.
//  3. Probe the normal (non-audit) download URL via getBlockedPackageDetails.
//
// A blocker that cannot be confirmed as curation-blocked (its version is absent
// from the metadata API — e.g. removed from the index, or a typo/nonexistent
// version) is NOT rendered as a row; with no recoverable blockers the command
// falls back to the graceful PR #761 message listing affected package(s), so a
// version that is not in the metadata API is never shown as a fake "blocked" row.
//
// HTTP calls are sequential per pin. This path is an error-recovery path that
// typically processes 1-3 packages, so parallelism is not worth the complexity.
func (nc *treeAnalyzer) fetchCvsBlockedStatus(pins []python.PinnedRequirement) []*PackageStatus {
	var statuses []*PackageStatus
	for _, pin := range pins {
		// ── Step 1: resolve range / no-version → exact version ───────────────
		resolvedVersion := pin.Version
		if pin.VersionRange != "" || resolvedVersion == "" {
			// Either a range spec or a ResolutionImpossible entry with no version.
			// Use the unfiltered all-versions metadata API to find the newest match.
			allVersions, err := nc.lookupPypiAllVersions(pin.Name)
			if err != nil {
				log.Debug(fmt.Sprintf("curation-blocked resolution fallback: all-versions lookup failed for %s%s: %v",
					pin.Name, pin.VersionRange, err))
				continue
			}
			if pin.VersionRange != "" {
				resolvedVersion = python.ResolveVersionRange(pin.VersionRange, allVersions)
			} else {
				// No range — pick the newest available version.
				resolvedVersion = python.ResolveVersionRange(">=0", allVersions)
			}
			if resolvedVersion == "" {
				log.Debug(fmt.Sprintf("curation-blocked resolution fallback: no version found for %s%s",
					pin.Name, pin.VersionRange))
				continue
			}
			log.Debug(fmt.Sprintf("curation-blocked resolution fallback: resolved %s%s → %s",
				pin.Name, pin.VersionRange, resolvedVersion))
		}

		// ── Step 2: metadata API → normal download URL ────────────────────────
		dlURL, err := nc.lookupPypiNormalDownloadURL(pin.Name, resolvedVersion)
		if err != nil {
			// Version is absent from the metadata API (removed from the index, or
			// a typo/nonexistent version). There is no recoverable policy to show,
			// so skip it: with no recoverable blockers the command falls back to
			// the graceful "Affected package(s)" message (PR #761 behaviour),
			// rather than rendering a misleading empty table row.
			log.Debug(fmt.Sprintf("curation-blocked resolution fallback: metadata lookup failed for %s==%s: %v — treating as unresolved",
				pin.Name, resolvedVersion, err))
			continue
		}

		// ── Step 3a: HEAD probe — detect whether the version is download-blocked
		headDetails := nc.httpClientDetails.Clone()
		var headResp *http.Response
		var headErr error
		if nc.tech == techutils.Pip || nc.tech == techutils.Poetry || nc.tech == techutils.Pipenv {
			headResp, _, headErr = nc.sendBoundedRequest(http.MethodHead, dlURL, headDetails)
		} else {
			headResp, _, headErr = nc.rtManager.Client().SendHead(dlURL, headDetails)
		}
		if headErr != nil && (headResp == nil || headResp.StatusCode != http.StatusForbidden) {
			log.Debug(fmt.Sprintf("curation-blocked resolution fallback: HEAD probe failed for %s==%s: %v",
				pin.Name, resolvedVersion, headErr))
			continue
		}
		// Package is accessible — CVS cache may be stale; not currently blocked.
		if headErr == nil && headResp != nil && headResp.StatusCode != http.StatusForbidden {
			log.Debug(fmt.Sprintf("curation-blocked resolution fallback: HEAD probe returned %d for %s==%s — not CVS-blocked, skipping",
				headResp.StatusCode, pin.Name, resolvedVersion))
			continue
		}

		// ── Step 3b: 403 from HEAD → recover policy details via GET with waiver
		var pkStatus *PackageStatus
		if headResp != nil && headResp.StatusCode == http.StatusForbidden {
			var getErr error
			pkStatus, getErr = nc.getBlockedPackageDetails(dlURL, pin.Name, resolvedVersion)
			if getErr != nil {
				log.Debug(fmt.Sprintf("curation-blocked resolution fallback: GET probe failed for %s==%s: %v",
					pin.Name, resolvedVersion, getErr))
			}
		}
		depRelation := directRelation
		if effectiveParent(pin) != pin.Name {
			depRelation = indirectRelation
		} else if pin.Version == "" && pin.VersionRange == "" {
			// Name-only entry from ResolutionImpossible — parent attribution is
			// unknown but these are always transitive deps by definition.
			depRelation = indirectRelation
		}
		if pkStatus == nil {
			// HEAD returned 403 but GET probe errored — CVS stripped the version
			// from the index but policy details aren't available via this path;
			// record with unknown reason so the package is never silently dropped.
			statuses = append(statuses, &PackageStatus{
				PackageName:       pin.Name,
				PackageVersion:    resolvedVersion,
				ParentName:        effectiveParent(pin),
				ParentVersion:     effectiveParentVersion(pin),
				DepRelation:       depRelation,
				BlockedPackageUrl: dlURL,
				Action:            blocked,
				BlockingReason:    BlockingReasonUnknown,
				PkgType:           string(nc.tech),
			})
			continue
		}

		// Policy recovered — set parent attribution from the parsed blocker.
		pkStatus.PackageName = pin.Name
		pkStatus.PackageVersion = resolvedVersion
		pkStatus.ParentName = effectiveParent(pin)
		pkStatus.ParentVersion = effectiveParentVersion(pin)
		pkStatus.DepRelation = depRelation
		statuses = append(statuses, pkStatus)
	}
	return statuses
}

// effectiveParent returns the parent name to populate in the curation table row.
// For direct exact pins, ParentName equals Name (set by parseCvsFailedPackages);
// for transitive range blockers it is the requiring package. When not yet set,
// fall back to the package itself.
func effectiveParent(pin python.PinnedRequirement) string {
	if pin.ParentName != "" && pin.ParentName != pin.Name {
		return pin.ParentName
	}
	return pin.Name
}

// effectiveParentVersion returns the version to show in the "Direct Dependency
// Version" column. For exact pins it is the pinned version.
//
// For a ranged DIRECT dependency (parent == package, e.g. requirements.txt has
// "langchain-core>=1.4.0") the range spec itself is shown so the column is not
// blank. For a TRANSITIVE blocker (parent differs from the package) the range
// describes the blocked package, not the parent — so it must not be shown in
// the parent column; we leave it blank when the parent version is unknown.
func effectiveParentVersion(pin python.PinnedRequirement) string {
	if pin.ParentVersion != "" {
		return pin.ParentVersion
	}
	if pin.VersionRange != "" && (pin.ParentName == "" || pin.ParentName == pin.Name) {
		return pin.VersionRange
	}
	return pin.Version
}

// We try to collect curation details from GET response after HEAD request got forbidden status code.
func (nc *treeAnalyzer) getBlockedPackageDetails(packageUrl string, name string, version string) (*PackageStatus, error) {
	requestDetails := nc.httpClientDetails.Clone()
	requestDetails.Headers["X-Artifactory-Curation-Request-Waiver"] = "syn"
	var getResp *http.Response
	var respBody []byte
	var err error
	if nc.tech == techutils.Pip || nc.tech == techutils.Poetry || nc.tech == techutils.Pipenv {
		getResp, respBody, err = nc.sendBoundedRequest(http.MethodGet, packageUrl, requestDetails)
	} else {
		getResp, respBody, _, err = nc.rtManager.Client().SendGet(packageUrl, true, requestDetails)
	}
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
			// Body is not valid JSON (e.g. Artifactory returned an HTML error page).
			// The 403 itself is authoritative — record the package as blocked with
			// unknown policy rather than dropping it from results.
			log.Debug(fmt.Sprintf("curation: could not parse 403 body for %s@%s as JSON (%s) — recording as blocked with unknown policy", name, version, err.Error()))
			return &PackageStatus{
				PackageName:       name,
				PackageVersion:    version,
				BlockedPackageUrl: packageUrl,
				Action:            blocked,
				BlockingReason:    BlockingReasonUnknown,
				PkgType:           string(nc.tech),
			}, nil
		}
		if len(respError.Errors) == 0 {
			log.Debug(fmt.Sprintf("curation: received 403 with empty error list for %s@%s — recording as blocked with unknown policy", name, version))
			return &PackageStatus{
				PackageName:       name,
				PackageVersion:    version,
				BlockedPackageUrl: packageUrl,
				Action:            blocked,
				BlockingReason:    BlockingReasonUnknown,
				PkgType:           string(nc.tech),
			}, nil
		}
		// if the error message contains the curation string key, then we can be sure it got blocked by Curation service.
		if strings.Contains(strings.ToLower(respError.Errors[0].Message), BlockMessageKey) {
			blockingReason := BlockingReasonPolicy
			if strings.Contains(strings.ToLower(respError.Errors[0].Message), NotBeingFoundKey) {
				blockingReason = BlockingReasonNotFound
			} else if strings.Contains(strings.ToLower(respError.Errors[0].Message), IsOnDemand) {
				blockingReason = BlockingReasonOnDemand
			}
			policies := nc.extractPoliciesFromMsg(respError)
			// extractPoliciesFromMsg may return empty when BlockMessageKey is present
			// but no {policy,...} groups were found in the message.  In that case
			// keep the 403 signal but be honest: use BlockingReasonUnknown rather
			// than "Policy violations" with every detail column blank.
			if blockingReason == BlockingReasonPolicy && len(policies) == 0 {
				blockingReason = BlockingReasonUnknown
			}
			return &PackageStatus{
				PackageName:       name,
				PackageVersion:    version,
				BlockedPackageUrl: packageUrl,
				Action:            blocked,
				Policy:            policies,
				BlockingReason:    blockingReason,
				WaiverAllowed:     strings.Contains(respError.Errors[0].Message, "[waivers allowed]"),
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
	lowerMsg := strings.ToLower(msg)
	switch {
	case strings.Contains(lowerMsg, IsOnDemand):
		policies = []Policy{{Explanation: BlockingReasonOnDemand}}
	case strings.Contains(lowerMsg, NotBeingFoundKey):
		policies = []Policy{{Explanation: BlockingReasonNotFound}}
	default:
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
	case techutils.Npm, techutils.Yarn, techutils.Pnpm:
		// Yarn and pnpm both use npm:// node IDs and the same Artifactory /api/npm/ endpoint as npm.
		return getNpmNameScopeAndVersion(node.Id, artiUrl, repo, techutils.Npm.String())
	case techutils.Maven:
		return getMavenNameScopeAndVersion(node.Id, artiUrl, repo, node)
	case techutils.Gradle:
		return getGradleNameScopeAndVersion(node.Id, artiUrl, repo, node)
	case techutils.Gem:
		return getGemNameScopeAndVersion(node.Id, artiUrl, repo)
	case techutils.Pip, techutils.Poetry, techutils.Uv, techutils.Pipenv:
		downloadUrls, name, version = getPythonNameVersion(node.Id, downloadUrlsMap)
		return
	case techutils.Go:
		return getGoNameScopeAndVersion(node.Id, artiUrl, repo)
	case techutils.Nuget:
		downloadUrls, name, version = getNugetNameScopeAndVersion(node.Id, artiUrl, repo)
		return
	case techutils.Docker:
		downloadUrls, name, version = getDockerNameAndVersion(node.Id, artiUrl, repo)
		return
	case techutils.HuggingFaceML:
		downloadUrls, name, version = getHuggingFaceNameAndVersion(node.Id, artiUrl, repo)
		return
	}
	return
}

func getPythonNameVersion(id string, downloadUrlsMap map[string]string) (downloadUrls []string, name, version string) {
	idWithoutPrefix := strings.TrimPrefix(id, python.PythonPackageTypeIdentifier)
	parts := strings.Split(idWithoutPrefix, ":")
	if len(parts) < 2 {
		log.Debug(fmt.Sprintf("Package %s has unexpected format", id))
		return
	}

	name, version = parts[0], parts[1]

	if downloadUrlsMap == nil {
		return
	}
	if dl, ok := downloadUrlsMap[id]; ok {
		downloadUrls = []string{dl}
		return
	}

	// Python package names are case-insensitive and treat hyphens/underscores as equivalentl.
	// The download URLs map uses normalized names, so we normalize the id to find a match.
	normalizedName := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(parts[0])), "-", "_")
	normalizedId := python.PythonPackageTypeIdentifier + normalizedName + ":" + strings.TrimSpace(parts[1])
	if dl, ok := downloadUrlsMap[normalizedId]; ok {
		downloadUrls = []string{dl}
	} else {
		log.Warn(fmt.Sprintf("Couldn't find download URL for node ID %s", id))
	}
	return
}

func toNugetDownloadUrl(artifactoryUrl, repo, compName, compVersion string) string {
	return fmt.Sprintf("%s/api/nuget/v3/%s/registration-semver2/Download/%s/%s",
		strings.TrimSuffix(artifactoryUrl, "/"),
		repo,
		strings.ToLower(compName),
		compVersion,
	)
}

// input- id: gav://org.apache.tomcat.embed:tomcat-embed-jasper:8.0.33
// input - repo: libs-release
// output - downloadUrl: <arti-url>/libs-release/org/apache/tomcat/embed/tomcat-embed-jasper/8.0.33/tomcat-embed-jasper-8.0.33.jar
func getNugetNameScopeAndVersion(id, artiUrl, repo string) (downloadUrls []string, name, version string) {
	name, version, _ = techutils.SplitComponentIdRaw(id)

	downloadUrls = append(downloadUrls, toNugetDownloadUrl(artiUrl, repo, name, version))
	for _, versionVariant := range dependencies.CreateAlternativeVersionForms(version) {
		downloadUrls = append(downloadUrls, toNugetDownloadUrl(artiUrl, repo, name, versionVariant))
	}

	return downloadUrls, name, version
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

// https://hts1.jfrog.io/artifactory/api/gems/test-gems-remote/gems/devise-4.7.1.gem -O -L
func getGemNameScopeAndVersion(id, artiUrl, repo string) (downloadUrls []string, name, scope, version string) {
	// For Ruby technology, always return Ruby-Project as the project name
	// This matches the original getStaticProjectName behavior and unit test expectations
	if artiUrl == "" && repo == "" {
		// This is a project name extraction call (not a dependency processing call)
		log.Debug("Ruby project name extraction - returning Ruby-Project")
		return nil, "Ruby-Project", "", ""
	}
	id = strings.TrimPrefix(id, "rubygems://")
	allParts := strings.Split(id, ":")
	if len(allParts) != 2 {
		return nil, "", "", ""
	}
	nameVersion := allParts[0] + "-" + allParts[1]
	packagePath := "/" + nameVersion
	downloadUrls = append(downloadUrls, strings.TrimSuffix(artiUrl, "/")+"/api/gems/"+repo+"/gems"+packagePath+".gem")
	return downloadUrls, strings.Join(allParts[:1], ":"), "", allParts[1]
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

// Given an input containing a classifier, e.g., id: gav://org.apache.tomcat.embed:tomcat-embed-jasper:8.0.33-jdk15,
// we parse it to extract the package name and version, then use that information to build the corresponding Artifactory download URL.
func getGradleNameScopeAndVersion(id, artiUrl, repo string, node *xrayUtils.GraphNode) (downloadUrls []string, name, scope, version string) {
	id = strings.TrimPrefix(id, "gav://")
	parts := strings.Split(id, ":")
	if len(parts) < 3 {
		return
	}

	groupID, artifactID, version := parts[0], parts[1], parts[2]
	nameVersion := artifactID + "-" + version
	versionDir := version

	if node != nil && node.Classifier != nil && *node.Classifier != "" {
		classifierSuffix := "-" + *node.Classifier
		versionDir = strings.TrimSuffix(version, classifierSuffix)
	}

	groupPath := strings.ReplaceAll(groupID, ".", "/")
	packagePath := fmt.Sprintf("%s/%s/%s/%s", groupPath, artifactID, versionDir, nameVersion)
	if node != nil && node.Types != nil {
		for _, fileType := range *node.Types {
			if fileType == "jar" {
				jarURL := fmt.Sprintf("%s/%s/%s.jar", strings.TrimSuffix(artiUrl, "/"), repo, packagePath)
				downloadUrls = append(downloadUrls, jarURL)
				break
			}
		}
	} else {
		//  .jar type file by default
		jarURL := fmt.Sprintf("%s/%s/%s.jar", strings.TrimSuffix(artiUrl, "/"), repo, packagePath)
		downloadUrls = append(downloadUrls, jarURL)
	}

	return downloadUrls, strings.Join(parts[:2], ":"), "", parts[2]
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
	// Skip local workspace members — they have no remote artifact.
	// Yarn V1: version ends in "-use.local". Yarn V2+: name ends with a
	// 6-char hex hash and version is "0.0.0" (e.g. "admin-ui-428bae:0.0.0").
	if strings.HasSuffix(version, "-use.local") || isYarnBerryWorkspaceMember(name, version) {
		return nil, name, "", version
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

// isYarnBerryWorkspaceMember reports whether a graph node is a Yarn V2/V3
// workspace member. Yarn Berry appends a 6-char lowercase hex hash to the
// package name (e.g. "admin-ui-428bae") and sets their version to "0.0.0".
func isYarnBerryWorkspaceMember(name, version string) bool {
	if version != "0.0.0" {
		return false
	}
	if len(name) < 8 {
		return false
	}
	suffix := name[len(name)-7:]
	if suffix[0] != '-' {
		return false
	}
	for _, c := range suffix[1:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func getDockerNameAndVersion(id, artiUrl, repo string) (downloadUrls []string, name, version string) {
	if id == "" {
		return
	}

	id = strings.TrimPrefix(id, "docker://")

	sha256Idx := strings.Index(id, ":sha256:")
	tagIdx := strings.LastIndex(id, ":")

	switch {
	// Example: docker://nginx:sha256:abc123def456
	case sha256Idx > 0:
		name = id[:sha256Idx]
		version = id[sha256Idx+1:]
	// Example: docker://nginx:1.21
	case tagIdx > 0:
		name = id[:tagIdx]
		version = id[tagIdx+1:]
	// Example: docker://nginx (no tag specified, defaults to "latest")
	default:
		name = id
		version = "latest"
	}

	if artiUrl != "" && repo != "" {
		downloadUrls = []string{fmt.Sprintf("%s/api/docker/%s/v2/%s/manifests/%s",
			strings.TrimSuffix(artiUrl, "/"), repo, name, version)}
	}

	return
}

// getHuggingFaceNameAndVersion extracts the model id and revision from a node id of the
// form "huggingfaceml://<repo_id>:<revision>" and builds the model-info probe URL.
//
// The probe targets the model metadata endpoint, which the curation service blocks
// (HEAD returns 403) for a malicious revision — independent of any specific file:
//
//	{artiUrl}/api/huggingfaceml/{repo}/api/models/{repo_id}/revision/{revision}
func getHuggingFaceNameAndVersion(id, artiUrl, repo string) (downloadUrls []string, name, version string) {
	if id == "" {
		return
	}
	id = strings.TrimPrefix(id, huggingface.HuggingFacePackagePrefix)

	// Shared with ParseModelReference (flag parsing) — see SplitRepoIDAndRevision's
	// doc comment for why this must not be guarded on the revision being slash-free
	// (e.g. "refs/pr/3", a PR ref). The revision is path-escaped below since it may
	// contain '/'. A leading colon (e.g. ":main") yields name == ""; the early-return
	// below fires (defensive — ParseModelReference already rejects this at the
	// flag-parsing stage).
	name, version = huggingface.SplitRepoIDAndRevision(id)
	if version == "" {
		version = huggingface.DefaultRevision
	}

	if name == "" {
		return nil, "", ""
	}

	if artiUrl != "" && repo != "" {
		// name (repo_id) is namespace/repo — escape each segment individually so a
		// literal '/' still splits into two URL path segments, but any other special
		// character (?, #, space) within a segment can't inject the request. '.'/'..'
		// segments are rejected outright: url.PathEscape leaves them unescaped (they're
		// unreserved per RFC 3986), so a repo id like "../../api/system/ping" would
		// otherwise still traverse the request path after escaping.
		// version may contain '/' (e.g. "refs/pr/3"); path-escape it so it lands in the
		// URL as a single path segment instead of introducing extra, unintended ones.
		nameParts := strings.Split(name, "/")
		for i, part := range nameParts {
			if part == "." || part == ".." {
				return nil, name, version
			}
			nameParts[i] = url.PathEscape(part)
		}
		downloadUrls = []string{fmt.Sprintf("%s/api/huggingfaceml/%s/api/models/%s/revision/%s",
			strings.TrimSuffix(artiUrl, "/"), repo, strings.Join(nameParts, "/"), url.PathEscape(version))}
	}
	return
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
			err = errorutils.CheckErrorf("only the following output formats are supported: %s", coreutils.ListToText(CurationOutputFormats))
		}
	}
	return
}

func IsEntitledForCuration(xrayManager *xrayClient.XrayServicesManager) (entitled bool, err error) {
	xrayVersion, err := xrayManager.GetVersion()
	if err != nil {
		return
	}
	return xray.IsEntitled(xrayManager, xrayVersion, "curation")
}
