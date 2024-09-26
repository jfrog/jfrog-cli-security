package secrets

import (
	"path/filepath"
	"strings"

	clientutils "github.com/jfrog/jfrog-client-go/utils"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	secretsScanCommand   = "sec"
	secretsDocsUrlSuffix = "secrets"

	SecretsScannerType           SecretsScanType = "secrets-scan"        // #nosec
	SecretsScannerDockerScanType SecretsScanType = "secrets-docker-scan" // #nosec
)

type SecretsScanType string

type SecretScanManager struct {
	secretsScannerResults []*sarif.Run
	scanner               *jas.JasScanner
	scanType              SecretsScanType
	configFileName        string
	resultsFileName       string
}

// The getSecretsScanResults function runs the secrets scan flow, which includes the following steps:
// Creating an SecretScanManager object.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
// Return values:
// []utils.IacOrSecretResult: a list of the secrets that were found.
// error: An error object (if any).
func RunSecretsScan(scanner *jas.JasScanner, scanType SecretsScanType, module jfrogappsconfig.Module, threadId int) (results []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Secrets.String()); err != nil {
		return
	}
	secretScanManager := newSecretsScanManager(scanner, scanType, scannerTempDir)
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + "Running secrets scan...")
	if err = secretScanManager.scanner.Run(secretScanManager, module); err != nil {
		err = jas.ParseAnalyzerManagerError(jasutils.Secrets, err)
		return
	}
	results = secretScanManager.secretsScannerResults
	if len(results) > 0 {
		log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Found", sarifutils.GetResultsLocationCount(results...), "secrets vulnerabilities")
	}
	return
}

func newSecretsScanManager(scanner *jas.JasScanner, scanType SecretsScanType, scannerTempDir string) (manager *SecretScanManager) {
	return &SecretScanManager{
		secretsScannerResults: []*sarif.Run{},
		scanner:               scanner,
		scanType:              scanType,
		configFileName:        filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName:       filepath.Join(scannerTempDir, "results.sarif"),
	}
}

func (ssm *SecretScanManager) Run(module jfrogappsconfig.Module) (err error) {
	if err = ssm.createConfigFile(module, ssm.scanner.Exclusions...); err != nil {
		return
	}
	if err = ssm.runAnalyzerManager(); err != nil {
		return
	}
	workingDirRuns, err := jas.ReadJasScanRunsFromFile(ssm.resultsFileName, module.SourceRoot, secretsDocsUrlSuffix, ssm.scanner.MinSeverity)
	if err != nil {
		return
	}
	ssm.secretsScannerResults = append(ssm.secretsScannerResults, processSecretScanRuns(workingDirRuns)...)
	return
}

type secretsScanConfig struct {
	Scans []secretsScanConfiguration `yaml:"scans"`
}

type secretsScanConfiguration struct {
	Roots       []string `yaml:"roots"`
	Output      string   `yaml:"output"`
	Type        string   `yaml:"type"`
	SkippedDirs []string `yaml:"skipped-folders"`
}

func (s *SecretScanManager) createConfigFile(module jfrogappsconfig.Module, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, module.Scanners.Secrets)
	if err != nil {
		return err
	}
	configFileContent := secretsScanConfig{
		Scans: []secretsScanConfiguration{
			{
				Roots:       roots,
				Output:      s.resultsFileName,
				Type:        string(s.scanType),
				SkippedDirs: jas.GetExcludePatterns(module, module.Scanners.Secrets, exclusions...),
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
				sarifutils.SetLocationSnippet(location, maskSecret(sarifutils.GetLocationSnippet(location)))
			}
		}
	}
	return sarifRuns
}
