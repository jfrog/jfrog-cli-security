package maliciouscode

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	maliciousScanCommand = "mal"
	malDocsUrlSuffix     = ""

	MaliciousScannerType MaliciousScanType = "malicious-scan" // #nosec
)

type MaliciousScanType string

type MaliciousScanManager struct {
	scanner  *jas.JasScanner
	scanType MaliciousScanType

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

func RunMaliciousScan(scanner *jas.JasScanner, scanType MaliciousScanType, sourceRoot string, targetCount, threadId int, resultsToCompare ...*sarif.Run) (vulnerabilitiesResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.MaliciousCode.String(), threadId); err != nil {
		return
	}
	maliciousScanManager, err := newMaliciousScanManager(scanner, scanType, scannerTempDir, resultsToCompare...)
	if err != nil {
		return
	}
	startTime := time.Now()
	logMsg := fmt.Sprintf("Running %s scan", utils.MaliciousCodeScan.ToTextString())
	if targetCount != 1 {
		logMsg += fmt.Sprintf(" on target '%s'...", sourceRoot)
	} else {
		logMsg += "..."
	}
	log.Info(logMsg)
	if vulnerabilitiesResults, err = maliciousScanManager.Run(sourceRoot); err != nil {
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

func (mal *MaliciousScanManager) Run(sourceRoot string) (vulnerabilitiesSarifRuns []*sarif.Run, err error) {
	if err = mal.createConfigFile(sourceRoot, append(mal.scanner.Exclusions, mal.scanner.ScannersExclusions.MaliciousCodeExcludePatterns...)...); err != nil {
		return
	}
	if err = mal.runAnalyzerManager(); err != nil {
		return
	}
	// Malicious code scans only return vulnerabilities, not violations
	vulnerabilitiesSarifRuns, _, err = jas.ReadJasScanRunsFromFile(mal.resultsFileName, sourceRoot, malDocsUrlSuffix, mal.scanner.MinSeverity)
	return
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

func (mal *MaliciousScanManager) createConfigFile(sourceRoot string, exclusions ...string) error {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return err
	}
	roots := []string{root}

	// Process exclusions - convert to file exclude patterns if needed
	excludePatterns := mal.getExcludePatterns(exclusions...)

	configFileContent := maliciousScanConfig{
		Scans: []maliciousScanConfiguration{
			{
				Roots:                  roots,
				Output:                 mal.resultsFileName,
				PathToResultsToCompare: mal.resultsToCompareFileName,
				Type:                   string(mal.scanType),
				SkippedDirs:            excludePatterns,
			},
		},
	}
	return jas.CreateScannersConfigFile(mal.configFileName, configFileContent, jasutils.MaliciousCode)
}

func (mal *MaliciousScanManager) getExcludePatterns(exclusions ...string) []string {
	if len(exclusions) == 0 {
		return utils.DefaultJasExcludePatterns
	}
	// Convert exclusions to file exclude patterns
	excludePatterns := make([]string, 0, len(exclusions))
	for _, exclusion := range exclusions {
		pattern := exclusion
		// Convert to file exclude pattern format if not already in that format
		if !filepath.IsAbs(pattern) {
			if !strings.HasPrefix(pattern, "**/") {
				pattern = "**/" + pattern
			}
			if !strings.HasSuffix(pattern, "/**") {
				pattern += "/**"
			}
		}
		excludePatterns = append(excludePatterns, pattern)
	}
	return excludePatterns
}

func (mal *MaliciousScanManager) runAnalyzerManager() error {
	return mal.scanner.AnalyzerManager.Exec(mal.configFileName, maliciousScanCommand, filepath.Dir(mal.scanner.AnalyzerManager.AnalyzerManagerFullPath), mal.scanner.ServerDetails, mal.scanner.EnvVars)
}
