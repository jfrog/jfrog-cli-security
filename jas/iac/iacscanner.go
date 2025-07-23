package iac

import (
	"fmt"
	"path/filepath"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	iacScannerType   = "iac-scan-modules"
	iacScanCommand   = "iac"
	iacDocsUrlSuffix = "infrastructure-as-code-iac"
)

type IacScanManager struct {
	scanner *jas.JasScanner

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

// The getIacScanResults function runs the iac scan flow, which includes the following steps:
// Creating an IacScanManager object.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
func RunIacScan(scanner *jas.JasScanner, module jfrogappsconfig.Module, threadId int, resultsToCompare ...*sarif.Run) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.IaC.String()); err != nil {
		return
	}
	iacScanManager, err := newIacScanManager(scanner, scannerTempDir, resultsToCompare...)
	if err != nil {
		return
	}
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + fmt.Sprintf("Running %s scan on target...", utils.IacScan.ToTextString()))
	if vulnerabilitiesResults, violationsResults, err = iacScanManager.scanner.Run(iacScanManager, module); err != nil {
		return
	}
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + utils.GetScanFindingsLog(utils.IacScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), sarifutils.GetResultsLocationCount(violationsResults...)))
	return
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

func (iac *IacScanManager) Run(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = iac.createConfigFile(module, append(iac.scanner.Exclusions, iac.scanner.ScannersExclusions.IacExcludePatterns...)...); err != nil {
		return
	}
	if err = iac.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(iac.resultsFileName, module.SourceRoot, iacDocsUrlSuffix, iac.scanner.MinSeverity)
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

func (iac *IacScanManager) createConfigFile(module jfrogappsconfig.Module, exclusions ...string) error {
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
				SkippedDirs:            jas.GetExcludePatterns(module, module.Scanners.Iac, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(iac.configFileName, configFileContent, jasutils.IaC)
}

func (iac *IacScanManager) runAnalyzerManager() error {
	return iac.scanner.AnalyzerManager.Exec(iac.configFileName, iacScanCommand, filepath.Dir(iac.scanner.AnalyzerManager.AnalyzerManagerFullPath), iac.scanner.ServerDetails, iac.scanner.EnvVars)
}
