package iac

import (
	"path/filepath"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
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
	scanner         *jas.JasScanner
	configFileName  string
	resultsFileName string
}

// The getIacScanResults function runs the iac scan flow, which includes the following steps:
// Creating an IacScanManager object.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
func RunIacScan(scanner *jas.JasScanner, module jfrogappsconfig.Module, threadId int) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.IaC.String()); err != nil {
		return
	}
	iacScanManager := newIacScanManager(scanner, scannerTempDir)
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + "Running IaC scan...")
	if vulnerabilitiesResults, violationsResults, err = iacScanManager.scanner.Run(iacScanManager, module); err != nil {
		err = jas.ParseAnalyzerManagerError(jasutils.IaC, err)
		return
	}
	log.Info(utils.GetScanFindingsLog(utils.IacScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), sarifutils.GetResultsLocationCount(violationsResults...), threadId))
	return
}

func newIacScanManager(scanner *jas.JasScanner, scannerTempDir string) (manager *IacScanManager) {
	return &IacScanManager{
		scanner:         scanner,
		configFileName:  filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName: filepath.Join(scannerTempDir, "results.sarif")}
}

func (iac *IacScanManager) Run(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = iac.createConfigFile(module, iac.scanner.Exclusions...); err != nil {
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
