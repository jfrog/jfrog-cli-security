package maliciouscode

import (
	"path/filepath"
	"time"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	MaliciousScannerType   MaliciousScanType = "malicious-scan" // #nosec
	maliciousScanCommand                     = "mal"
	maliciousDocsUrlSuffix                   = "advanced-security/features-and-capabilities/malicious-code-scans"
)

type MaliciousScanType string

type MaliciousScanManager struct {
	scanner  *jas.JasScanner
	scanType MaliciousScanType

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

func RunMaliciousScan(scanner *jas.JasScanner, scanType MaliciousScanType, module jfrogappsconfig.Module, targetCount, threadId int, resultsToCompare ...*sarif.Run) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.MaliciousCode.String(), threadId); err != nil {
		return
	}
	maliciousScanManager, err := newMaliciousScanManager(scanner, scanType, scannerTempDir, resultsToCompare...)
	if err != nil {
		return
	}
	startTime := time.Now()
	log.Info(jas.GetStartJasScanLog(utils.MaliciousCodeScan, threadId, module, targetCount))
	if vulnerabilitiesResults, violationsResults, err = maliciousScanManager.scanner.Run(maliciousScanManager, module); err != nil {
		return
	}
	log.Info(utils.GetScanFindingsLog(utils.MaliciousCodeScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), startTime, threadId))
	return
}

func newMaliciousScanManager(scanner *jas.JasScanner, scanType MaliciousScanType, scannerTempDir string, resultsToCompare ...*sarif.Run) (manager *MaliciousScanManager, err error) {
	manager = &MaliciousScanManager{
		scanner:         scanner,
		scanType:        scanType,
		configFileName:  filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName: filepath.Join(scannerTempDir, "results.sarif"),
	}
	if len(resultsToCompare) == 0 {
		return
	}
	log.Debug("Diff mode - Malicious code results to compare provided")
	manager.resultsToCompareFileName = filepath.Join(scannerTempDir, "target.sarif")
	if err = jas.SaveScanResultsToCompareAsReport(manager.resultsToCompareFileName, resultsToCompare...); err != nil {
		return
	}
	return
}

func (mal *MaliciousScanManager) Run(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = mal.createConfigFile(module, append(mal.scanner.Exclusions, mal.scanner.ScannersExclusions.MaliciousCodeExcludePatterns...)...); err != nil {
		return
	}
	if err = mal.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(mal.resultsFileName, module.SourceRoot, maliciousDocsUrlSuffix, mal.scanner.MinSeverity)
}

type maliciousScanConfig struct {
	Scans []maliciousScanConfiguration `yaml:"scans"`
}

type maliciousScanConfiguration struct {
	Roots                  []string `yaml:"roots"`
	Output                 string   `yaml:"output"`
	PathToResultsToCompare string   `yaml:"target-result-file,omitempty"`
	Type                   string   `yaml:"type"`
	SkippedDirs            []string `yaml:"skipped-folders"`
}

func (mal *MaliciousScanManager) createConfigFile(module jfrogappsconfig.Module, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, module.Scanners.MaliciousCode)
	if err != nil {
		return err
	}
	configFileContent := maliciousScanConfig{
		Scans: []maliciousScanConfiguration{
			{
				Roots:                  roots,
				Output:                 mal.resultsFileName,
				PathToResultsToCompare: mal.resultsToCompareFileName,
				Type:                   string(mal.scanType),
				SkippedDirs:            jas.GetExcludePatterns(module, module.Scanners.MaliciousCode, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(mal.configFileName, configFileContent, jasutils.MaliciousCode)
}

func (mal *MaliciousScanManager) runAnalyzerManager() error {
	return mal.scanner.AnalyzerManager.Exec(mal.configFileName, maliciousScanCommand, filepath.Dir(mal.scanner.AnalyzerManager.AnalyzerManagerFullPath), mal.scanner.ServerDetails, mal.scanner.EnvVars)
}
