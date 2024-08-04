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

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	goclientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

type JasScanner struct {
	TempDir               string
	AnalyzerManager       AnalyzerManager
	ServerDetails         *config.ServerDetails
	JFrogAppsConfig       *jfrogappsconfig.JFrogAppsConfig
	ScannerDirCleanupFunc func() error
	EnvVars               map[string]string
	Exclusions            []string
}

func CreateJasScanner(scanner *JasScanner, jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig, serverDetails *config.ServerDetails, envVars map[string]string, exclusions ...string) (*JasScanner, error) {
	var err error
	if scanner.AnalyzerManager.AnalyzerManagerFullPath, err = GetAnalyzerManagerExecutable(); err != nil {
		return scanner, err
	}
	if scanner.EnvVars, err = getJasEnvVars(serverDetails, envVars); err != nil {
		return scanner, err
	}
	var tempDir string
	if tempDir, err = fileutils.CreateTempDir(); err != nil {
		return scanner, err
	}
	scanner.TempDir = tempDir
	scanner.ScannerDirCleanupFunc = func() error {
		return fileutils.RemoveTempDir(tempDir)
	}
	scanner.ServerDetails = serverDetails
	scanner.JFrogAppsConfig = jfrogAppsConfig
	scanner.Exclusions = exclusions
	return scanner, err
}

func getJasEnvVars(serverDetails *config.ServerDetails, vars map[string]string) (map[string]string, error) {
	amBasicVars, err := GetAnalyzerManagerEnvVariables(serverDetails)
	if err != nil {
		return nil, err
	}
	return utils.MergeMaps(utils.ToEnvVarsMap(os.Environ()), amBasicVars, vars), nil
}

func CreateJFrogAppsConfig(workingDirs []string) (*jfrogappsconfig.JFrogAppsConfig, error) {
	if jfrogAppsConfig, err := jfrogappsconfig.LoadConfigIfExist(); err != nil {
		return nil, errorutils.CheckError(err)
	} else if jfrogAppsConfig != nil {
		// jfrog-apps-config.yml exist in the workspace
		for _, module := range jfrogAppsConfig.Modules {
			// converting to absolute path before starting the scan flow
			module.SourceRoot, err = filepath.Abs(module.SourceRoot)
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
	Run(module jfrogappsconfig.Module) (err error)
}

func (a *JasScanner) Run(scannerCmd ScannerCmd, module jfrogappsconfig.Module) (err error) {
	func() {
		if err = scannerCmd.Run(module); err != nil {
			return
		}
	}()
	return
}

func ReadJasScanRunsFromFile(fileName, wd, informationUrlSuffix string) (sarifRuns []*sarif.Run, err error) {
	if sarifRuns, err = sarifutils.ReadScanRunsFromFile(fileName); err != nil {
		return
	}
	for _, sarifRun := range sarifRuns {
		// Jas reports has only one invocation
		// Set the actual working directory to the invocation, not the analyzerManager directory
		// Also used to calculate relative paths if needed with it
		sarifRun.Invocations[0].WorkingDirectory.WithUri(wd)
		// Process runs values
		fillMissingRequiredDriverInformation(utils.BaseDocumentationURL+informationUrlSuffix, GetAnalyzerManagerVersion(), sarifRun)
		sarifRun.Results = excludeSuppressResults(sarifRun.Results)
		addScoreToRunRules(sarifRun)
	}
	return
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

func addScoreToRunRules(sarifRun *sarif.Run) {
	for _, sarifResult := range sarifRun.Results {
		if rule, err := sarifRun.GetRuleById(*sarifResult.RuleID); err == nil {
			// Add to the rule security-severity score based on results severity
			severity, err := severityutils.ParseSeverity(sarifutils.GetResultLevel(sarifResult), true)
			if err != nil {
				log.Warn(fmt.Sprintf("Failed to parse Sarif level %s: %s", sarifutils.GetResultLevel(sarifResult), err.Error()))
				severity = severityutils.Unknown
			}
			score := severityutils.GetSeverityScore(severity, jasutils.Applicable)
			if rule.Properties == nil {
				rule.WithProperties(sarif.NewPropertyBag().Properties)
			}
			rule.Properties[severityutils.SarifSeverityRuleProperty] = fmt.Sprintf("%f", score)
		}
	}
}

func CreateScannersConfigFile(fileName string, fileContent interface{}, scanType jasutils.JasScanType) error {
	yamlData, err := yaml.Marshal(&fileContent)
	if errorutils.CheckError(err) != nil {
		return err
	}
	log.Debug(scanType.String() + " scanner input YAML:\n" + string(yamlData))
	err = os.WriteFile(fileName, yamlData, 0644)
	return errorutils.CheckError(err)
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

func InitJasTest(t *testing.T, workingDirs ...string) (*JasScanner, func()) {
	assert.NoError(t, DownloadAnalyzerManagerIfNeeded(0))
	jfrogAppsConfigForTest, err := CreateJFrogAppsConfig(workingDirs)
	assert.NoError(t, err)
	scanner := &JasScanner{}
	scanner, err = CreateJasScanner(scanner, jfrogAppsConfigForTest, &FakeServerDetails, GetAnalyzerManagerXscEnvVars(""))
	assert.NoError(t, err)
	return scanner, func() {
		assert.NoError(t, scanner.ScannerDirCleanupFunc())
	}
}

func GetTestDataPath() string {
	return filepath.Join("..", "..", "tests", "testdata", "other")
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
		return convertToFilesExcludePatterns(exclusions)
	}
	excludePatterns := module.ExcludePatterns
	if scanner != nil {
		excludePatterns = append(excludePatterns, scanner.ExcludePatterns...)
	}
	if len(excludePatterns) == 0 {
		return utils.DefaultJasExcludePatterns
	}
	return excludePatterns
}

func convertToFilesExcludePatterns(excludePatterns []string) []string {
	patterns := []string{}
	for _, excludePattern := range excludePatterns {
		patterns = append(patterns, "**/"+excludePattern+"/**")
	}
	return patterns
}

func GetAnalyzerManagerXscEnvVars(msi string, technologies ...techutils.Technology) map[string]string {
	envVars := map[string]string{utils.JfMsiEnvVariable: msi}
	if len(technologies) != 1 {
		return envVars
	}
	technology := technologies[0]
	envVars[JfPackageManagerEnvVariable] = technology.String()
	envVars[JfLanguageEnvVariable] = string(techutils.TechnologyToLanguage(technology))
	return envVars

}

func IsEntitledForJas(xrayManager *xray.XrayServicesManager, xrayVersion string) (entitled bool, err error) {
	if e := goclientutils.ValidateMinimumVersion(goclientutils.Xray, xrayVersion, EntitlementsMinVersion); e != nil {
		log.Debug(e)
		return
	}
	entitled, err = xrayManager.IsEntitled(ApplicabilityFeatureId)
	return
}

func CreateScannerTempDirectory(scanner *JasScanner, scanType string) (string, error) {
	if scanner.TempDir == "" {
		return "", errors.New("scanner temp dir cannot be created in an empty base dir")
	}
	scannerTempDir := scanner.TempDir + "/" + scanType + "_" + strconv.FormatInt(time.Now().Unix(), 10)
	err := os.MkdirAll(scannerTempDir, 0777)
	if err != nil {
		return "", err
	}
	return scannerTempDir, nil
}
