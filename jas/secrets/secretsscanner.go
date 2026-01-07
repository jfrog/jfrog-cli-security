package secrets

import (
	"path/filepath"
	"strings"
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
	secretsScanCommand   = "sec"
	secretsDocsUrlSuffix = "advanced-security/features-and-capabilities/secrets-scans"

	SecretsScannerType            SecretsScanType = "secrets-scan"         // #nosec
	SecretsScannerDockerScanType  SecretsScanType = "secrets-docker-scan"  // #nosec
	SecretsScannerGenericScanType SecretsScanType = "secrets-generic-scan" // #nosec
)

type SecretsScanType string

type SecretScanManager struct {
	scanner  *jas.JasScanner
	scanType SecretsScanType

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

// The getSecretsScanResults function runs the secrets scan flow, which includes the following steps:
// Creating an SecretScanManager object.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
func RunSecretsScan(scanner *jas.JasScanner, scanType SecretsScanType, module jfrogappsconfig.Module, targetCount, threadId int, resultsToCompare ...*sarif.Run) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Secrets.String(), threadId); err != nil {
		return
	}
	secretScanManager, err := newSecretsScanManager(scanner, scanType, scannerTempDir, resultsToCompare...)
	if err != nil {
		return
	}
	startTime := time.Now()
	log.Info(jas.GetStartJasScanLog(utils.SecretsScan, threadId, module, targetCount))
	if vulnerabilitiesResults, violationsResults, err = secretScanManager.scanner.Run(secretScanManager, module); err != nil {
		return
	}
	log.Info(utils.GetScanFindingsLog(utils.SecretsScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), startTime, threadId))
	return
}

func newSecretsScanManager(scanner *jas.JasScanner, scanType SecretsScanType, scannerTempDir string, resultsToCompare ...*sarif.Run) (manager *SecretScanManager, err error) {
	manager = &SecretScanManager{
		scanner:         scanner,
		scanType:        scanType,
		configFileName:  filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName: filepath.Join(scannerTempDir, "results.sarif"),
	}
	if len(resultsToCompare) == 0 {
		// No scan results to compare
		return
	}
	log.Debug("Diff mode - Secrets results to compare provided")
	manager.resultsToCompareFileName = filepath.Join(scannerTempDir, "target.sarif")
	// Save the secrets results to compare as a report
	err = jas.SaveScanResultsToCompareAsReport(manager.resultsToCompareFileName, resultsToCompare...)
	return
}

func (ssm *SecretScanManager) Run(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = ssm.createConfigFile(module, ssm.scanner.ScannersExclusions.SecretsExcludePatterns, ssm.scanner.Exclusions...); err != nil {
		return
	}
	if err = ssm.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(ssm.resultsFileName, module.SourceRoot, secretsDocsUrlSuffix, ssm.scanner.MinSeverity)
}

type secretsScanConfig struct {
	Scans []secretsScanConfiguration `yaml:"scans"`
}

type secretsScanConfiguration struct {
	Roots                  []string `yaml:"roots"`
	Output                 string   `yaml:"output"`
	PathToResultsToCompare string   `yaml:"target-result-file,omitempty"`
	Type                   string   `yaml:"type"`
	SkippedDirs            []string `yaml:"skipped-folders"`
}

func (s *SecretScanManager) createConfigFile(module jfrogappsconfig.Module, centralConfigExclusions []string, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, module.Scanners.Secrets)
	if err != nil {
		return err
	}
	configFileContent := secretsScanConfig{
		Scans: []secretsScanConfiguration{
			{
				Roots:                  roots,
				Output:                 s.resultsFileName,
				PathToResultsToCompare: s.resultsToCompareFileName,
				Type:                   string(s.scanType),
				SkippedDirs:            jas.GetExcludePatterns(module, module.Scanners.Secrets, centralConfigExclusions, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(s.configFileName, configFileContent, jasutils.Secrets)
}

func (s *SecretScanManager) runAnalyzerManager() error {
	return s.scanner.AnalyzerManager.Exec(s.configFileName, secretsScanCommand, filepath.Dir(s.scanner.AnalyzerManager.AnalyzerManagerFullPath), s.scanner.ServerDetails, s.scanner.EnvVars)
}

func maskSecret(secret string) string {
	if len(secret) <= 3 {
		return "***"
	}
	return secret[:3] + strings.Repeat("*", 12)
}

func processSecretScanRuns(sarifRuns []*sarif.Run) []*sarif.Run {
	for _, secretRun := range sarifRuns {
		// Hide discovered secrets value
		for _, secretResult := range secretRun.Results {
			for _, location := range secretResult.Locations {
				sarifutils.SetLocationSnippet(location, maskSecret(sarifutils.GetLocationSnippetText(location)))
			}
		}
	}
	return sarifRuns
}
