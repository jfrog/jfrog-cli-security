package applicability

import (
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
	Roots                []string                      `yaml:"roots"`
	Output               string                        `yaml:"output"`
	Type                 string                        `yaml:"type"`
	GrepDisable          bool                          `yaml:"grep-disable"`
	CveWhitelist         []string                      `yaml:"cve-whitelist"`
	IndirectCveWhitelist []string                      `yaml:"indirect-cve-whitelist"`
	IndirectCvePaths     map[string]indirectCveContext `yaml:"indirect-cve-paths,omitempty"`
	SkippedDirs          []string                      `yaml:"skipped-folders"`
	ScanType             string                        `yaml:"scantype"`
}

// indirectCvePathNode is a single node (package + implicated function) in a dependency path leading to an indirect CVE's vulnerable package.
type indirectCvePathNode struct {
	Type      string `yaml:"type"`
	Namespace string `yaml:"namespace,omitempty"`
	Name      string `yaml:"name"`
	Version   string `yaml:"version"`
	Function  string `yaml:"function"`
}

// indirectCveContext is the per-indirect-CVE contextual analysis data obtained from Catalog: the vulnerable
// package, the function(s) involved, and the dependency path(s) reaching it.
type indirectCveContext struct {
	Type      string                  `yaml:"type"`
	Namespace string                  `yaml:"namespace,omitempty"`
	Name      string                  `yaml:"name"`
	Version   string                  `yaml:"version"`
	Functions []string                `yaml:"functions,omitempty"`
	Paths     [][]indirectCvePathNode `yaml:"paths,omitempty"`
}

func toIndirectCveContextConfig(paths map[string]catalogServices.IndirectContextualResponse) map[string]indirectCveContext {
	if len(paths) == 0 {
		return nil
	}
	config := make(map[string]indirectCveContext, len(paths))
	for cve, response := range paths {
		context := indirectCveContext{
			Type:      response.Type,
			Namespace: response.Namespace,
			Name:      response.Name,
			Version:   response.Version,
			Functions: response.Functions,
		}
		for _, path := range response.Paths {
			var pathNodes []indirectCvePathNode
			for _, node := range path {
				pathNodes = append(pathNodes, indirectCvePathNode{
					Type:      node.Type,
					Namespace: node.Namespace,
					Name:      node.Name,
					Version:   node.Version,
					Function:  node.Function,
				})
			}
			context.Paths = append(context.Paths, pathNodes)
		}
		config[cve] = context
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
				IndirectCvePaths:     toIndirectCveContextConfig(asm.indirectCvePaths),
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
