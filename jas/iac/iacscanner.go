package iac

import (
	"path/filepath"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	iacScannerType   = "iac-scan-modules"
	iacScanCommand   = "iac"
	iacDocsUrlSuffix = "infrastructure-as-code-iac"
)

type IacScanManager struct {
	iacScannerResults []*sarif.Run
	scanner           *jas.JasScanner
	configFileName    string
	resultsFileName   string
}

// The getIacScanResults function runs the iac scan flow, which includes the following steps:
// Creating an IacScanManager object.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
// Return values:
// []utils.SourceCodeScanResult: a list of the iac violations that were found.
// bool: true if the user is entitled to iac scan, false otherwise.
// error: An error object (if any).
func RunIacScan(scanner *jas.JasScanner, module jfrogappsconfig.Module, threadId int) (results []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.IaC.String()); err != nil {
		return
	}
	iacScanManager := newIacScanManager(scanner, scannerTempDir)
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + "Running IaC scan...")
	if err = iacScanManager.scanner.Run(iacScanManager, module); err != nil {
		err = jas.ParseAnalyzerManagerError(jasutils.IaC, err)
		return
	}
	results = iacScanManager.iacScannerResults
	if len(results) > 0 {
		log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Found", sarifutils.GetResultsLocationCount(iacScanManager.iacScannerResults...), "IaC vulnerabilities")
	}
	return
}

func newIacScanManager(scanner *jas.JasScanner, scannerTempDir string) (manager *IacScanManager) {
	return &IacScanManager{
		iacScannerResults: []*sarif.Run{},
		scanner:           scanner,
		configFileName:    filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName:   filepath.Join(scannerTempDir, "results.sarif")}
}

func (iac *IacScanManager) Run(module jfrogappsconfig.Module) (err error) {
	if err = iac.createConfigFile(module, iac.scanner.Exclusions...); err != nil {
		return
	}
	if err = iac.runAnalyzerManager(); err != nil {
		return
	}
	workingDirResults, err := jas.ReadJasScanRunsFromFile(iac.resultsFileName, module.SourceRoot, iacDocsUrlSuffix, iac.scanner.MinSeverity)
	if err != nil {
		return
	}
	iac.iacScannerResults = append(iac.iacScannerResults, workingDirResults...)
	return
}

type iacScanConfig struct {
	Scans []iacScanConfiguration `yaml:"scans"`
}

type iacScanConfiguration struct {
	Roots       []string `yaml:"roots"`
	Output      string   `yaml:"output"`
	Type        string   `yaml:"type"`
	SkippedDirs []string `yaml:"skipped-folders"`
}

func (iac *IacScanManager) createConfigFile(module jfrogappsconfig.Module, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, module.Scanners.Iac)
	if err != nil {
		return err
	}
	configFileContent := iacScanConfig{
		Scans: []iacScanConfiguration{
			{
				Roots:       roots,
				Output:      iac.resultsFileName,
				Type:        iacScannerType,
				SkippedDirs: jas.GetExcludePatterns(module, module.Scanners.Iac, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(iac.configFileName, configFileContent, jasutils.IaC)
}

func (iac *IacScanManager) runAnalyzerManager() error {
	return iac.scanner.AnalyzerManager.Exec(iac.configFileName, iacScanCommand, filepath.Dir(iac.scanner.AnalyzerManager.AnalyzerManagerFullPath), iac.scanner.ServerDetails, iac.scanner.EnvVars)
}
