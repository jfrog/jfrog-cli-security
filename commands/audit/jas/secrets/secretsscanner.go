package secrets

import (
	"path/filepath"
	"strconv"
	"strings"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	secretsScanCommand   = "sec"
	secretsScannerType   = "secrets-scan"
	secretsDocsUrlSuffix = "secrets"
)

type SecretScanManager struct {
	secretsScannerResults []*sarif.Run
	scanner               *jas.JasScanner
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
func RunSecretsScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, extendedScanResults *utils.ExtendedScanResults,
	module jfrogappsconfig.Module, threadId int) (err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, string(utils.Secrets)); err != nil {
		return
	}
	secretScanManager := newSecretsScanManager(scanner, scannerTempDir)
	log.Info("[thread_id: " + strconv.Itoa(threadId) + "] Running secrets scanning...")
	if err = secretScanManager.scanner.Run(secretScanManager, module); err != nil {
		err = utils.ParseAnalyzerManagerError(utils.Secrets, err)
		return
	}
	results := secretScanManager.secretsScannerResults
	if len(results) > 0 {
		log.Info("[thread_id: "+strconv.Itoa(threadId)+"] Found", utils.GetResultsLocationCount(results...), "secrets")
	}
	auditParallelRunner.Mu.Lock()
	extendedScanResults.SecretsScanResults = append(extendedScanResults.SecretsScanResults, results...)
	auditParallelRunner.Mu.Unlock()
	return
}

func newSecretsScanManager(scanner *jas.JasScanner, scannerTempDir string) (manager *SecretScanManager) {
	return &SecretScanManager{
		secretsScannerResults: []*sarif.Run{},
		scanner:               scanner,
		configFileName:        filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName:       filepath.Join(scannerTempDir, "results.sarif"),
	}
}

func (ssm *SecretScanManager) Run(module jfrogappsconfig.Module) (err error) {
	if err = ssm.createConfigFile(module); err != nil {
		return
	}
	if err = ssm.runAnalyzerManager(); err != nil {
		return
	}
	workingDirRuns, err := jas.ReadJasScanRunsFromFile(ssm.resultsFileName, module.SourceRoot, secretsDocsUrlSuffix)
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

func (s *SecretScanManager) createConfigFile(module jfrogappsconfig.Module) error {
	roots, err := jas.GetSourceRoots(module, module.Scanners.Secrets)
	if err != nil {
		return err
	}
	configFileContent := secretsScanConfig{
		Scans: []secretsScanConfiguration{
			{
				Roots:       roots,
				Output:      s.resultsFileName,
				Type:        secretsScannerType,
				SkippedDirs: jas.GetExcludePatterns(module, module.Scanners.Secrets),
			},
		},
	}
	return jas.CreateScannersConfigFile(s.configFileName, configFileContent, utils.Secrets)
}

func (s *SecretScanManager) runAnalyzerManager() error {
	return s.scanner.AnalyzerManager.Exec(s.configFileName, secretsScanCommand, filepath.Dir(s.scanner.AnalyzerManager.AnalyzerManagerFullPath), s.scanner.ServerDetails)
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
				utils.SetLocationSnippet(location, maskSecret(utils.GetLocationSnippet(location)))
			}
		}
	}
	return sarifRuns
}
