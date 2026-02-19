package iac

import (
	"path/filepath"
	"time"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	iacScannerType   = "iac-scan-modules"
	iacScanCommand   = "iac"
	iacDocsUrlSuffix = "advanced-security/features-and-capabilities/misconfigurations-scans"
)

type IacScanManager struct {
	scanner *jas.JasScanner

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

type IacScanParams struct {
	ThreadId         int
	TargetCount      int
	ResultsToCompare []*sarif.Run
	Module           *jfrogappsconfig.Module
	Target           results.ScanTarget
}

// The getIacScanResults function runs the iac scan flow, which includes the following steps:
// Creating an IacScanManager object.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
func RunIacScan(scanner *jas.JasScanner, params IacScanParams) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.IaC.String(), params.ThreadId); err != nil {
		return
	}
	iacScanManager, err := newIacScanManager(scanner, scannerTempDir, params.ResultsToCompare...)
	if err != nil {
		return
	}
	startTime := time.Now()
	log.Info(jas.GetStartJasScanLog(utils.IacScan, params.ThreadId, params.Module, params.TargetCount))
	if vulnerabilitiesResults, violationsResults, err = runIacScan(iacScanManager, params); err != nil {
		return
	}
	log.Info(utils.GetScanFindingsLog(utils.IacScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), startTime, params.ThreadId))
	return
}

func runIacScan(iacScanManager *IacScanManager, params IacScanParams) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	if params.Module == nil {
		return iacScanManager.scanner.Run(iacScanManager, params.Target)
	}
	return iacScanManager.scanner.DeprecatedRun(iacScanManager, *params.Module)
}

func newIacScanManager(scanner *jas.JasScanner, scannerTempDir string, resultsToCompare ...*sarif.Run) (manager *IacScanManager, err error) {
	manager = &IacScanManager{
		scanner:         scanner,
		configFileName:  filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName: filepath.Join(scannerTempDir, "results.sarif"),
	}
	if len(resultsToCompare) == 0 {
		// No scan results to compare
		return
	}
	log.Debug("Diff mode - IaC results to compare provided")
	manager.resultsToCompareFileName = filepath.Join(scannerTempDir, "target.sarif")
	// Save the iac results to compare as a report
	if err = jas.SaveScanResultsToCompareAsReport(manager.resultsToCompareFileName, resultsToCompare...); err != nil {
		return
	}
	return
}

func (iac *IacScanManager) DeprecatedRun(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = iac.deprecatedCreateConfigFile(module, iac.scanner.ScannersExclusions.IacExcludePatterns, iac.scanner.Exclusions...); err != nil {
		return
	}
	if err = iac.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(iac.resultsFileName, iacDocsUrlSuffix, iac.scanner.MinSeverity, module.SourceRoot)
}

func (iac *IacScanManager) Run(target results.ScanTarget) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = iac.createConfigFileForTarget(target, iac.scanner.ScannersExclusions.IacExcludePatterns); err != nil {
		return
	}
	if err = iac.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(iac.resultsFileName, iacDocsUrlSuffix, iac.scanner.MinSeverity, jas.GetWorkingDirsFromTarget(target)...)
}

type iacScanConfig struct {
	Scans []iacScanConfiguration `yaml:"scans"`
}

type iacScanConfiguration struct {
	Roots                  []string `yaml:"roots"`
	Output                 string   `yaml:"output"`
	PathToResultsToCompare string   `yaml:"target-result-file,omitempty"`
	Type                   string   `yaml:"type"`
	SkippedDirs            []string `yaml:"skipped-folders"`
}

func (iac *IacScanManager) deprecatedCreateConfigFile(module jfrogappsconfig.Module, centralConfigExclusions []string, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, module.Scanners.Iac)
	if err != nil {
		return err
	}
	configFileContent := iacScanConfig{
		Scans: []iacScanConfiguration{
			{
				Roots:                  roots,
				Output:                 iac.resultsFileName,
				PathToResultsToCompare: iac.resultsToCompareFileName,
				Type:                   iacScannerType,
				SkippedDirs:            jas.GetExcludePatterns(module, module.Scanners.Iac, centralConfigExclusions, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(iac.configFileName, configFileContent, jasutils.IaC)
}

func (iac *IacScanManager) createConfigFileForTarget(target results.ScanTarget, centralConfigExclusions []string) error {
	configFileContent := iacScanConfig{
		Scans: []iacScanConfiguration{
			{
				Roots:                  jas.GetRootsFromTarget(target),
				Output:                 iac.resultsFileName,
				PathToResultsToCompare: iac.resultsToCompareFileName,
				Type:                   iacScannerType,
				SkippedDirs:            jas.GetExcludePatternsForTarget(target, centralConfigExclusions),
			},
		},
	}
	return jas.CreateScannersConfigFile(iac.configFileName, configFileContent, jasutils.IaC)
}

func (iac *IacScanManager) runAnalyzerManager() error {
	return iac.scanner.AnalyzerManager.Exec(iac.configFileName, iacScanCommand, filepath.Dir(iac.scanner.AnalyzerManager.AnalyzerManagerFullPath), iac.scanner.ServerDetails, iac.scanner.EnvVars)
}
