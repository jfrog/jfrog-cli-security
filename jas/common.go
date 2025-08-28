package jas

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/jfrog/gofrog/datastructures"
	clientservices "github.com/jfrog/jfrog-client-go/xsc/services"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	goclientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

const (
	NoServerUrlWarn      = "To incorporate the ‘Advanced Security’ scans into the audit output make sure platform url is provided and valid (run 'jf c add' prior to 'jf audit' via CLI, or provide JF_URL via Frogbot)"
	NoServerDetailsError = "jfrog Server details are missing"
)

type JasScanner struct {
	TempDir               string
	AnalyzerManager       AnalyzerManager
	ServerDetails         *config.ServerDetails
	ScannerDirCleanupFunc func() error
	EnvVars               map[string]string
	DiffMode              bool
	ResultsToCompare      *results.SecurityCommandResults
	Exclusions            []string
	// This field contains scanner specific exclude patterns from Config Profile
	ScannersExclusions SpecificScannersExcludePatterns
	MinSeverity        severityutils.Severity
}

type SpecificScannersExcludePatterns struct {
	ContextualAnalysisExcludePatterns []string
	SastExcludePatterns               []string
	SecretsExcludePatterns            []string
	IacExcludePatterns                []string
}

type JasScannerOption func(f *JasScanner) error

func NewJasScanner(serverDetails *config.ServerDetails, options ...JasScannerOption) (scanner *JasScanner, err error) {
	// Validate
	if serverDetails == nil {
		err = errors.New(NoServerDetailsError)
		return
	}
	if len(serverDetails.Url) == 0 {
		if len(serverDetails.XrayUrl) != 0 {
			log.Debug("Xray URL provided without platform URL")
		} else {
			if len(serverDetails.ArtifactoryUrl) != 0 {
				log.Debug("Artifactory URL provided without platform URL")
			}
			log.Warn(NoServerUrlWarn)
			return
		}
	}
	// Create temp dir for scanner
	var tempDir string
	if tempDir, err = fileutils.CreateTempDir(); err != nil {
		return
	}
	// Create scanner
	scanner = &JasScanner{
		ServerDetails: serverDetails,
		TempDir:       tempDir,
		ScannerDirCleanupFunc: func() error {
			return fileutils.RemoveTempDir(tempDir)
		},
	}
	// Apply options
	for _, option := range options {
		err = errors.Join(err, option(scanner))
	}
	return
}

func WithEnvVars(validateSecrets bool, diffMode JasDiffScanEnvValue, envVars map[string]string) JasScannerOption {
	return func(scanner *JasScanner) (err error) {
		scanner.EnvVars, err = getJasEnvVars(scanner.ServerDetails, validateSecrets, diffMode, envVars)
		return
	}
}

func WithResultsToCompare(resultsToCompare *results.SecurityCommandResults) JasScannerOption {
	return func(scanner *JasScanner) (err error) {
		scanner.ResultsToCompare = resultsToCompare
		return
	}
}

func WithExclusions(exclusions ...string) JasScannerOption {
	return func(scanner *JasScanner) (err error) {
		scanner.Exclusions = exclusions
		return
	}
}

func WithMinSeverity(minSeverity severityutils.Severity) JasScannerOption {
	return func(scanner *JasScanner) (err error) {
		scanner.MinSeverity = minSeverity
		return
	}
}

func getJasEnvVars(serverDetails *config.ServerDetails, validateSecrets bool, diffMode JasDiffScanEnvValue, vars map[string]string) (map[string]string, error) {
	amBasicVars, err := GetAnalyzerManagerEnvVariables(serverDetails)
	if err != nil {
		return nil, err
	}
	amBasicVars[JfSecretValidationEnvVariable] = strconv.FormatBool(validateSecrets)
	if diffMode != NotDiffScanEnvValue {
		amBasicVars[DiffScanEnvVariable] = string(diffMode)
	}
	return utils.MergeMaps(utils.ToEnvVarsMap(os.Environ()), amBasicVars, vars), nil
}

func (js *JasScanner) GetResultsToCompareByRelativePath(relativeTarget string) (resultsToCompare *results.TargetResults) {
	return results.SearchTargetResultsByRelativePath(relativeTarget, js.ResultsToCompare)
}

func CreateJFrogAppsConfig(workingDirs []string) (*jfrogappsconfig.JFrogAppsConfig, error) {
	if jfrogAppsConfig, err := jfrogappsconfig.LoadConfigIfExist(); err != nil {
		log.Warn("Please note the 'jfrog-apps-config.yml' is soon to be deprecated. Please consider using flags, environment variables, or centrally via the JFrog platform.")
		return nil, errorutils.CheckError(err)
	} else if jfrogAppsConfig != nil {
		// jfrog-apps-config.yml exist in the workspace
		for i := range jfrogAppsConfig.Modules {
			// converting to absolute path before starting the scan flow
			jfrogAppsConfig.Modules[i].SourceRoot, err = filepath.Abs(jfrogAppsConfig.Modules[i].SourceRoot)
			if err != nil {
				return nil, errorutils.CheckError(err)
			}
		}
		return jfrogAppsConfig, nil
	}

	// jfrog-apps-config.yml does not exist in the workspace
	fullPathsWorkingDirs, err := coreutils.GetFullPathsWorkingDirs(workingDirs)
	if err != nil {
		return nil, err
	}
	jfrogAppsConfig := new(jfrogappsconfig.JFrogAppsConfig)
	for _, workingDir := range fullPathsWorkingDirs {
		jfrogAppsConfig.Modules = append(jfrogAppsConfig.Modules, jfrogappsconfig.Module{SourceRoot: workingDir})
	}
	return jfrogAppsConfig, nil
}

type ScannerCmd interface {
	Run(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error)
}

func (a *JasScanner) Run(scannerCmd ScannerCmd, module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	func() {
		if vulnerabilitiesSarifRuns, violationsSarifRuns, err = scannerCmd.Run(module); err != nil {
			return
		}
	}()
	return
}

func ReadJasScanRunsFromFile(fileName, wd, informationUrlSuffix string, minSeverity severityutils.Severity) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	violationFileName := fmt.Sprintf("%s_violations.sarif", strings.TrimSuffix(fileName, ".sarif"))
	vulnFileExist, violationsFileExist, err := checkJasResultsFilesExist(fileName, violationFileName)
	if err != nil {
		return
	}
	if !vulnFileExist && !violationsFileExist {
		err = fmt.Errorf("Analyzer-Manager did not generate results files at: %s", filepath.Base(fileName))
		return
	}
	if vulnFileExist {
		vulnerabilitiesSarifRuns, err = readJasScanRunsFromFile(fileName, wd, informationUrlSuffix, minSeverity)
		if err != nil {
			return
		}
	}
	if violationsFileExist {
		violationsSarifRuns, err = readJasScanRunsFromFile(violationFileName, wd, informationUrlSuffix, minSeverity)
	}
	return
}

func checkJasResultsFilesExist(vulnFileName, violationsFileName string) (vulnFileExist, violationsFileExist bool, err error) {
	if vulnFileExist, err = fileutils.IsFileExists(vulnFileName, false); err != nil {
		return
	}
	if violationsFileExist, err = fileutils.IsFileExists(violationsFileName, false); err != nil {
		return
	}
	return
}

func readJasScanRunsFromFile(fileName, wd, informationUrlSuffix string, minSeverity severityutils.Severity) (sarifRuns []*sarif.Run, err error) {
	if sarifRuns, err = sarifutils.ReadScanRunsFromFile(fileName); err != nil {
		return
	}
	processSarifRuns(sarifRuns, wd, informationUrlSuffix, minSeverity)
	return
}

// This function processes the Sarif runs results: update invocations, fill missing information, exclude results and adding scores to rules
func processSarifRuns(sarifRuns []*sarif.Run, wd string, informationUrlSuffix string, minSeverity severityutils.Severity) {
	for _, sarifRun := range sarifRuns {
		fillMissingRequiredInvocationInformation(wd, sarifRun)
		fillMissingRequiredDriverInformation(utils.BaseDocumentationURL+informationUrlSuffix, GetAnalyzerManagerVersion(), sarifRun)
		addScoreToRunRules(sarifRun)
		// Process results
		sarifRun.Results = excludeSuppressResults(sarifRun.Results)
		sarifRun.Results = excludeMinSeverityResults(sarifRun.Results, minSeverity)
	}
}

func fillMissingRequiredDriverInformation(defaultJasInformationUri, defaultVersion string, run *sarif.Run) {
	driver := run.Tool.Driver
	if driver.InformationURI == nil {
		driver.InformationURI = &defaultJasInformationUri
	}
	if driver.Version == nil || !isValidVersion(*driver.Version) {
		driver.Version = &defaultVersion
	}
}

func isValidVersion(version string) bool {
	if len(version) == 0 {
		return false
	}
	firstChar := rune(version[0])
	return unicode.IsDigit(firstChar)
}

func fillMissingRequiredInvocationInformation(wd string, run *sarif.Run) {
	// If no invocations are present, add an empty invocation with an empty working directory
	if len(run.Invocations) == 0 {
		run.Invocations = append(run.Invocations, sarif.NewInvocation().WithWorkingDirectory(sarif.NewArtifactLocation()))
	}
	for _, invocation := range run.Invocations {
		// Set the actual working directory to the invocation, not the analyzerManager directory
		// Also used to calculate relative paths if needed with it
		invocation.WorkingDirectory.WithURI(utils.ToURI(wd))
		// Make sure the invocation not omitted attributes are set (the lib reports them as required but spec says they are optional)
		if len(invocation.NotificationConfigurationOverrides) == 0 {
			invocation.NotificationConfigurationOverrides = make([]*sarif.ConfigurationOverride, 0)
		}
		if len(invocation.RuleConfigurationOverrides) == 0 {
			invocation.RuleConfigurationOverrides = make([]*sarif.ConfigurationOverride, 0)
		}
		if len(invocation.ToolConfigurationNotifications) == 0 {
			invocation.ToolConfigurationNotifications = make([]*sarif.Notification, 0)
		}
		if len(invocation.ToolExecutionNotifications) == 0 {
			invocation.ToolExecutionNotifications = make([]*sarif.Notification, 0)
		}
	}
}

func excludeSuppressResults(sarifResults []*sarif.Result) []*sarif.Result {
	results := []*sarif.Result{}
	for _, sarifResult := range sarifResults {
		if len(sarifResult.Suppressions) > 0 {
			// Describes a request to “suppress” a result (to exclude it from result lists)
			continue
		}
		results = append(results, sarifResult)
	}
	return results
}

func excludeMinSeverityResults(sarifResults []*sarif.Result, minSeverity severityutils.Severity) []*sarif.Result {
	if minSeverity == "" {
		// No minimum severity to exclude
		return sarifResults
	}
	results := []*sarif.Result{}
	for _, sarifResult := range sarifResults {
		resultSeverity, err := severityutils.ParseSeverity(sarifResult.Level, true)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to parse Sarif level %s: %s", sarifResult.Level, err.Error()))
			resultSeverity = severityutils.Unknown
		}
		// Exclude results with severity lower than the minimum severity
		if severityutils.GetSeverityPriority(resultSeverity, jasutils.ApplicabilityUndetermined) >= severityutils.GetSeverityPriority(minSeverity, jasutils.ApplicabilityUndetermined) {
			results = append(results, sarifResult)
		}
	}
	return results
}

func addScoreToRunRules(sarifRun *sarif.Run) {
	for _, sarifResult := range sarifRun.Results {
		if rule := sarifutils.GetRuleById(sarifRun, sarifutils.GetResultRuleId(sarifResult)); rule != nil {
			// Add to the rule security-severity score based on results severity
			severity, err := severityutils.ParseSeverity(sarifResult.Level, true)
			if err != nil {
				log.Warn(fmt.Sprintf("Failed to parse Sarif level %s: %s", sarifResult.Level, err.Error()))
				severity = severityutils.Unknown
			}
			score := severityutils.GetSeverityScore(severity, jasutils.Applicable)
			if rule.Properties == nil {
				rule.WithProperties(sarif.NewPropertyBag())
			}
			// Add the score to the rule properties
			rule.Properties.Add(severityutils.SarifSeverityRuleProperty, fmt.Sprintf("%.1f", score))
		}
	}
}

func SaveScanResultsToCompareAsReport(fileName string, runs ...*sarif.Run) error {
	report := sarif.NewReport()
	report.Runs = runs
	sarifData, err := utils.GetAsJsonBytes(report, false, false)
	if err != nil {
		return err
	}
	return errorutils.CheckError(os.WriteFile(fileName, sarifData, 0644))
}

func CreateScannersConfigFile(fileName string, fileContent interface{}, scanType jasutils.JasScanType) error {
	yamlData, err := yaml.Marshal(&fileContent)
	if errorutils.CheckError(err) != nil {
		return err
	}
	log.Debug(scanType.String() + " scanner input YAML:\n" + string(yamlData))
	return errorutils.CheckError(os.WriteFile(fileName, yamlData, 0644))
}

var FakeServerDetails = config.ServerDetails{
	Url:      "platformUrl",
	Password: "password",
	User:     "user",
}

var FakeBasicXrayResults = []services.ScanResponse{
	{
		ScanId: "scanId_1",
		Vulnerabilities: []services.Vulnerability{
			{IssueId: "issueId_1", Technology: techutils.Pipenv.String(),
				Cves:       []services.Cve{{Id: "testCve1"}, {Id: "testCve2"}, {Id: "testCve3"}},
				Components: map[string]services.Component{"issueId_1_direct_dependency": {}, "issueId_3_direct_dependency": {}}},
		},
		Violations: []services.Violation{
			{IssueId: "issueId_2", Technology: techutils.Pipenv.String(),
				Cves:       []services.Cve{{Id: "testCve4"}, {Id: "testCve5"}},
				Components: map[string]services.Component{"issueId_2_direct_dependency": {}, "issueId_4_direct_dependency": {}}},
		},
	},
}

func InitJasTest(t *testing.T) (*JasScanner, func()) {
	assert.NoError(t, DownloadAnalyzerManagerIfNeeded(0))
	scanner, err := NewJasScanner(&FakeServerDetails)
	assert.NoError(t, err)
	return scanner, func() {
		assert.NoError(t, scanner.ScannerDirCleanupFunc())
	}
}

func GetTestDataPath() string {
	return filepath.Join("..", "..", "tests", "testdata", "other")
}

func GetModule(root string, appConfig *jfrogappsconfig.JFrogAppsConfig) *jfrogappsconfig.Module {
	for _, module := range appConfig.Modules {
		if module.SourceRoot == root {
			return &module
		}
	}
	return nil
}

func ShouldSkipScanner(module jfrogappsconfig.Module, scanType jasutils.JasScanType) bool {
	lowerScanType := strings.ToLower(string(scanType))
	if slices.Contains(module.ExcludeScanners, lowerScanType) {
		log.Info(fmt.Sprintf("Skipping %s scanning", scanType))
		return true
	}
	return false
}

func GetSourceRoots(module jfrogappsconfig.Module, scanner *jfrogappsconfig.Scanner) ([]string, error) {
	root, err := filepath.Abs(module.SourceRoot)
	if err != nil {
		return []string{}, errorutils.CheckError(err)
	}
	if scanner == nil || len(scanner.WorkingDirs) == 0 {
		return []string{root}, errorutils.CheckError(err)
	}
	var roots []string
	for _, workingDir := range scanner.WorkingDirs {
		roots = append(roots, filepath.Join(root, workingDir))
	}
	return roots, nil
}

func GetExcludePatterns(module jfrogappsconfig.Module, scanner *jfrogappsconfig.Scanner, exclusions ...string) []string {
	if len(exclusions) > 0 {
		return filterUniqueAndConvertToFilesExcludePatterns(exclusions)
	}

	// Adding exclusions from jfrog-apps-config IF no exclusions provided from other source (flags, env vars, config profile)
	excludePatterns := module.ExcludePatterns
	if scanner != nil {
		excludePatterns = append(excludePatterns, scanner.ExcludePatterns...)
	}
	if len(excludePatterns) == 0 {
		return utils.DefaultJasExcludePatterns
	}
	return excludePatterns
}

// This function convert every exclude pattern to a file exclude pattern form.
// Checks are being made since some of the exclude patters we get here might already be in a file exclude pattern
// Additionally, we keep patterns without duplications
func filterUniqueAndConvertToFilesExcludePatterns(excludePatterns []string) []string {
	uniqueExcludePatterns := datastructures.MakeSet[string]()
	for _, excludePattern := range excludePatterns {
		if !strings.HasPrefix(excludePattern, "**/") {
			excludePattern = "**/" + excludePattern
		}
		if !strings.HasSuffix(excludePattern, "/**") {
			excludePattern += "/**"
		}
		uniqueExcludePatterns.Add(excludePattern)
	}
	return uniqueExcludePatterns.ToSlice()
}

func CheckForSecretValidation(xrayManager *xray.XrayServicesManager, xrayVersion string, validateSecrets bool) bool {
	dynamicTokenVersionMismatchErr := goclientutils.ValidateMinimumVersion(goclientutils.Xray, xrayVersion, jasutils.DynamicTokenValidationMinXrayVersion)
	if dynamicTokenVersionMismatchErr != nil {
		if validateSecrets {
			log.Info(fmt.Sprintf("Token validation (--validate-secrets flag) is not supported in your xray version, your xray version is %s and the minimum is %s", xrayVersion, jasutils.DynamicTokenValidationMinXrayVersion))
		}
		return false
	}
	// Ordered By importance
	// first check for flag and second check for env var
	if validateSecrets || strings.ToLower(os.Getenv(JfSecretValidationEnvVariable)) == "true" {
		return true
	}
	// third check for platform api
	isEnabled, err := xrayManager.IsTokenValidationEnabled()
	return err == nil && isEnabled
}

func GetAnalyzerManagerXscEnvVars(msi string, gitRepoUrl, projectKey string, watches []string, technologies ...techutils.Technology) map[string]string {
	envVars := map[string]string{utils.JfMsiEnvVariable: msi}
	if gitRepoUrl != "" {
		envVars[gitRepoEnvVariable] = gitRepoUrl
	}
	if projectKey != "" {
		envVars[projectEnvVariable] = projectKey
	}
	if len(watches) > 0 {
		envVars[watchesEnvVariable] = strings.Join(watches, ",")
	}
	if len(technologies) != 1 {
		return envVars
	}
	technology := technologies[0]
	envVars[JfPackageManagerEnvVariable] = technology.String()
	envVars[JfLanguageEnvVariable] = string(techutils.TechnologyToLanguage(technology))
	return envVars

}

func IsEntitledForJas(xrayManager *xray.XrayServicesManager, xrayVersion string) (entitled bool, err error) {
	if e := goclientutils.ValidateMinimumVersion(goclientutils.Xray, xrayVersion, utils.EntitlementsMinVersion); e != nil {
		log.Debug(e)
		return
	}
	entitled, err = xrayManager.IsEntitled(ApplicabilityFeatureId)
	return
}

func CreateScannerTempDirectory(scanner *JasScanner, scanType string, threadId int) (string, error) {
	if scanner.TempDir == "" {
		return "", errors.New("scanner temp dir cannot be created in an empty base dir")
	}
	scannerTempDir := filepath.Join(scanner.TempDir, fmt.Sprintf("%s_%d_%d", scanType, time.Now().Unix(), threadId))
	err := os.MkdirAll(scannerTempDir, 0777)
	if err != nil {
		return "", err
	}
	return scannerTempDir, nil
}

func UpdateJasScannerWithExcludePatternsFromProfile(scanner *JasScanner, profile *clientservices.ConfigProfile) {
	if profile == nil {
		return
	}
	scanner.ScannersExclusions.ContextualAnalysisExcludePatterns = profile.Modules[0].ScanConfig.ContextualAnalysisScannerConfig.ExcludePatterns
	scanner.ScannersExclusions.SastExcludePatterns = profile.Modules[0].ScanConfig.SastScannerConfig.ExcludePatterns
	scanner.ScannersExclusions.SecretsExcludePatterns = profile.Modules[0].ScanConfig.SecretsScannerConfig.ExcludePatterns
	scanner.ScannersExclusions.IacExcludePatterns = profile.Modules[0].ScanConfig.IacScannerConfig.ExcludePatterns
}
