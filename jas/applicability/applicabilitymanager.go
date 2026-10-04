package applicability

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	catalogServices "github.com/jfrog/jfrog-client-go/catalog/services"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"golang.org/x/exp/slices"
)

const (
	applicabilityScanCommand   = "ca"
	applicabilityDocsUrlSuffix = "contextual-analysis-of-cves-1"

	ApplicabilityScannerType         ApplicabilityScanType = "analyze-applicability"
	ApplicabilityDockerScanScanType  ApplicabilityScanType = "analyze-applicability-docker-scan"
	ApplicabilityGenericScanScanType ApplicabilityScanType = "analyze-applicability-generic-scan"
)

type ApplicabilityScanType string

type ApplicabilityScanManager struct {
	directDependenciesCves   []string
	indirectDependenciesCves []string
	indirectCvePaths         map[string]catalogServices.IndirectContextualResponse
	scanner                  *jas.JasScanner
	thirdPartyScan           bool
	commandType              string
	configFileName           string
	resultsFileName          string
}

type ContextualAnalysisScanParams struct {
	DirectDependenciesCves       []string
	IndirectDependenciesCves     []string
	IndirectCvePaths             map[string]catalogServices.IndirectContextualResponse
	ScanType                     ApplicabilityScanType
	ThirdPartyContextualAnalysis bool
	ThreadId                     int
	TargetCount                  int
	Target                       results.ScanTarget
}

// The getApplicabilityScanResults function runs the applicability scan flow, which includes the following steps:
// Creating an ApplicabilityScanManager object.
// Checking if the scanned project is eligible for applicability scan.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
func RunApplicabilityScan(params ContextualAnalysisScanParams, scanner *jas.JasScanner) (results []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Applicability.String(), params.ThreadId); err != nil {
		return
	}
	applicabilityScanManager := newApplicabilityScanManager(params.DirectDependenciesCves, params.IndirectDependenciesCves, params.IndirectCvePaths, scanner, params.ThirdPartyContextualAnalysis, params.ScanType, scannerTempDir)
	if !applicabilityScanManager.cvesExists() {
		log.Debug(clientutils.GetLogMsgPrefix(params.ThreadId, false) + "We couldn't find any vulnerable dependencies. Skipping Contextual Analysis scan....")
		return
	}
	startTime := time.Now()
	log.Info(jas.GetStartJasScanLog(utils.ContextualAnalysisScan, params.ThreadId, params.Target.DeprecatedAppsConfigModule, params.TargetCount))
	if results, err = applicabilityScanManager.runApplicabilityScan(params); err != nil {
		return
	}
	applicableCveCount := sarifutils.GetRulesPropertyCount("applicability", "applicable", results...)
	if applicableCveCount > 0 {
		log.Info(clientutils.GetLogMsgPrefix(params.ThreadId, false)+"Found", applicableCveCount, "applicable cves", fmt.Sprintf("(duration %s)", time.Since(startTime)))
	}
	return
}

func (applicabilityScanManager *ApplicabilityScanManager) runApplicabilityScan(params ContextualAnalysisScanParams) (vulnerabilitiesSarifRuns []*sarif.Run, err error) {
	if params.Target.DeprecatedAppsConfigModule == nil {
		// Applicability scan does not produce violations.
		vulnerabilitiesSarifRuns, _, err = applicabilityScanManager.scanner.Run(applicabilityScanManager, params.Target)
		return
	}
	// Applicability scan does not produce violations.
	vulnerabilitiesSarifRuns, _, err = applicabilityScanManager.scanner.DeprecatedRun(applicabilityScanManager, *params.Target.DeprecatedAppsConfigModule, params.Target.GetCentralConfigExclusions(utils.ContextualAnalysisScan))
	return
}

func newApplicabilityScanManager(directDependenciesCves, indirectDependenciesCves []string, indirectCvePaths map[string]catalogServices.IndirectContextualResponse, scanner *jas.JasScanner, thirdPartyScan bool, scanType ApplicabilityScanType, scannerTempDir string) (manager *ApplicabilityScanManager) {
	return &ApplicabilityScanManager{
		directDependenciesCves:   directDependenciesCves,
		indirectDependenciesCves: indirectDependenciesCves,
		indirectCvePaths:         indirectCvePaths,
		scanner:                  scanner,
		thirdPartyScan:           thirdPartyScan,
		commandType:              string(scanType),
		configFileName:           filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName:          filepath.Join(scannerTempDir, "results.sarif"),
	}
}

func (asm *ApplicabilityScanManager) DeprecatedRun(module jfrogappsconfig.Module, centralConfigExclusions []string) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = asm.deprecatedCreateConfigFile(module, centralConfigExclusions, asm.scanner.Exclusions...); err != nil {
		return
	}
	if err = asm.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(asm.resultsFileName, applicabilityDocsUrlSuffix, asm.scanner.MinSeverity, module.SourceRoot)
}

func (asm *ApplicabilityScanManager) Run(target results.ScanTarget) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = asm.createConfigFileForTarget(target); err != nil {
		return
	}
	if err = asm.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(asm.resultsFileName, applicabilityDocsUrlSuffix, asm.scanner.MinSeverity, target.Target, target.Include...)
}

func (asm *ApplicabilityScanManager) cvesExists() bool {
	return len(asm.indirectDependenciesCves) > 0 || len(asm.directDependenciesCves) > 0
}

type applicabilityScanConfig struct {
	Scans []scanConfiguration `yaml:"scans"`
}

type scanConfiguration struct {
	Roots                []string          `yaml:"roots"`
	Output               string            `yaml:"output"`
	Type                 string            `yaml:"type"`
	GrepDisable          bool              `yaml:"grep-disable"`
	CveWhitelist         []string          `yaml:"cve-whitelist"`
	IndirectCveWhitelist []string          `yaml:"indirect-cve-whitelist"`
	TransitivePaths      map[string]string `yaml:"transitive_paths,omitempty"`
	SkippedDirs          []string          `yaml:"skipped-folders"`
	ScanType             string            `yaml:"scantype"`
}

// toTransitivePathsConfig marshals each Catalog indirect-CVE contextual response into an opaque JSON string.
// Downstream (AM / jas-shift-left / gadgets) parses this JSON directly as Catalog's own PathsResponse shape
// (PathsResponse(**json.loads(...))), so it must be the full Catalog struct, not a YAML-mirrored one.
func toTransitivePathsConfig(paths map[string]catalogServices.IndirectContextualResponse) map[string]string {
	if len(paths) == 0 {
		return nil
	}
	config := make(map[string]string, len(paths))
	for cve, response := range paths {
		if response.Name == "" && len(response.Functions) == 0 {
			// No package identity and no functions: nothing useful for Analyzer Manager to act on.
			// A response with functions/package identity but no paths is still valuable and kept.
			log.Warn(fmt.Sprintf("skipping indirect CVE contextual response for %s: no package identity or functions", cve))
			continue
		}
		marshaled, err := json.Marshal(response)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to marshal indirect CVE contextual paths for %s, skipping: %s", cve, err.Error()))
			continue
		}
		config[cve] = string(marshaled)
	}
	if len(config) == 0 {
		return nil
	}
	return config
}

func (asm *ApplicabilityScanManager) createConfigFileForTarget(target results.ScanTarget) error {
	excludePatterns := jas.GetJasExcludePatternsForTarget(target, target.GetCentralConfigExclusions(utils.ContextualAnalysisScan))
	if asm.thirdPartyScan {
		log.Info("Including node modules folder in applicability scan")
		excludePatterns = removeElementFromSlice(excludePatterns, utils.NodeModulesPattern)
	}
	configFileContent := applicabilityScanConfig{
		Scans: []scanConfiguration{
			{
				Roots:                jas.GetRootsFromTarget(target),
				Output:               asm.resultsFileName,
				Type:                 asm.commandType,
				GrepDisable:          false,
				CveWhitelist:         asm.directDependenciesCves,
				IndirectCveWhitelist: asm.indirectDependenciesCves,
				TransitivePaths:      toTransitivePathsConfig(asm.indirectCvePaths),
				SkippedDirs:          excludePatterns,
			},
		},
	}
	return jas.CreateScannersConfigFile(asm.configFileName, configFileContent, jasutils.Applicability)
}

func (asm *ApplicabilityScanManager) deprecatedCreateConfigFile(module jfrogappsconfig.Module, centralConfigExclusions []string, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, nil)
	if err != nil {
		return err
	}
	excludePatterns := jas.GetJasExcludePatterns(module, nil, centralConfigExclusions, exclusions...)
	if asm.thirdPartyScan {
		log.Info("Including node modules folder in applicability scan")
		excludePatterns = removeElementFromSlice(excludePatterns, utils.NodeModulesPattern)
	}
	configFileContent := applicabilityScanConfig{
		Scans: []scanConfiguration{
			{
				Roots:                roots,
				Output:               asm.resultsFileName,
				Type:                 asm.commandType,
				GrepDisable:          false,
				CveWhitelist:         asm.directDependenciesCves,
				IndirectCveWhitelist: asm.indirectDependenciesCves,
				SkippedDirs:          excludePatterns,
			},
		},
	}
	return jas.CreateScannersConfigFile(asm.configFileName, configFileContent, jasutils.Applicability)
}

// Runs the analyzerManager app and returns a boolean to indicate whether the user is entitled for
// advance security feature
func (asm *ApplicabilityScanManager) runAnalyzerManager() error {
	return asm.scanner.AnalyzerManager.Exec(asm.configFileName, applicabilityScanCommand, filepath.Dir(asm.scanner.AnalyzerManager.AnalyzerManagerFullPath), asm.scanner.ServerDetails, asm.scanner.EnvVars)
}

func removeElementFromSlice(skipDirs []string, element string) []string {
	deleteIndex := slices.Index(skipDirs, element)
	if deleteIndex == -1 {
		return skipDirs
	}
	return slices.Delete(skipDirs, deleteIndex, deleteIndex+1)
}
