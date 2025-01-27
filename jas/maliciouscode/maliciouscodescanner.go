package maliciouscode

import (
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"path/filepath"
	"time"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	maliciousScanCommand                         = "mal"
	maliciousDocsUrlSuffix                       = "malicious"
	MaliciousScannerType       MaliciousScanType = "malicious-scan"        // #nosec
	MaliciousDockerScannerType MaliciousScanType = "malicious-docker-scan" // #nosec
)

type MaliciousScanType string

type MaliciousScanManager struct {
	scanner  *jas.JasScanner
	scanType MaliciousScanType

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

// The getMaliciousScanResults function runs the malicious code scan flow, which includes the following steps:
// Creating an MaliciousSecretManager object.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
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
		// No scan results to compare
		return
	}
	log.Debug("Diff mode - Malicious code results to compare provided")
	manager.resultsToCompareFileName = filepath.Join(scannerTempDir, "target.sarif")
	// Save the malicious code results to compare as a report
	err = jas.SaveScanResultsToCompareAsReport(manager.resultsToCompareFileName, resultsToCompare...)
	return
}

func (msm *MaliciousScanManager) Run(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = msm.createConfigFile(module, msm.scanner.Exclusions...); err != nil {
		return
	}
	if err = msm.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(msm.resultsFileName, module.SourceRoot, maliciousDocsUrlSuffix, msm.scanner.MinSeverity)
}

type maliciousScanConfig struct {
	Scans []maliciousScanConfiguration `yaml:"scans"`
}

type maliciousScanConfiguration struct {
	Roots       []string `yaml:"roots"`
	Output      string   `yaml:"output"`
	Type        string   `yaml:"type"`
	SkippedDirs []string `yaml:"skipped-folders"`
}

func (m *MaliciousScanManager) createConfigFile(module jfrogappsconfig.Module, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, module.Scanners.MaliciousCode)
	if err != nil {
		return err
	}
	configFileContent := maliciousScanConfig{
		Scans: []maliciousScanConfiguration{
			{
				Roots:       roots,
				Output:      m.resultsFileName,
				Type:        string(m.scanType),
				SkippedDirs: jas.GetExcludePatterns(module, module.Scanners.MaliciousCode, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(m.configFileName, configFileContent, jasutils.MaliciousCode)
}

func (m *MaliciousScanManager) runAnalyzerManager() error {
	return m.scanner.AnalyzerManager.Exec(m.configFileName, maliciousScanCommand, filepath.Dir(m.scanner.AnalyzerManager.AnalyzerManagerFullPath), m.scanner.ServerDetails, m.scanner.EnvVars)
}
