package sast

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"golang.org/x/exp/maps"
)

const (
	sastScannerType   = "sast"
	sastScanCommand   = "zd"
	sastDocsUrlSuffix = "sast-1"

	sastChangedFilesModeEnvVar = "JAS_SAST_CHANGED_FILES_MODE"
)

// SastChangedFilesFromGitContext returns gitCtx.ChangedFiles when sastChangedFilesModeEnvVar is "true",
// gitCtx is non-nil, and ChangedFiles is non-empty; otherwise nil.
func SastChangedFilesFromGitContext(gitCtx *xscservices.XscGitInfoContext) []string {
	if gitCtx == nil || os.Getenv(sastChangedFilesModeEnvVar) != "true" {
		return nil
	}
	if len(gitCtx.ChangedFiles) == 0 {
		return nil
	}
	return gitCtx.ChangedFiles
}

type SastScanManager struct {
	scanner *jas.JasScanner

	sastChangedFiles   []string
	signedDescriptions bool
	sastRules          string

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

func RunSastScan(scanner *jas.JasScanner, module jfrogappsconfig.Module, signedDescriptions bool, sastRules string, sastChangedFiles []string, targetCount, threadId int, resultsToCompare ...*sarif.Run) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Sast.String(), threadId); err != nil {
		return
	}
	sastScanManager, err := newSastScanManager(scanner, scannerTempDir, signedDescriptions, sastRules, sastChangedFiles, resultsToCompare...)
	if err != nil {
		return
	}
	startTime := time.Now()
	log.Info(jas.GetStartJasScanLog(utils.SastScan, threadId, module, targetCount))
	if vulnerabilitiesResults, violationsResults, err = sastScanManager.scanner.Run(sastScanManager, module); err != nil {
		return
	}
	log.Info(utils.GetScanFindingsLog(utils.SastScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), startTime, threadId))
	return
}

func newSastScanManager(scanner *jas.JasScanner, scannerTempDir string, signedDescriptions bool, sastRules string, sastChangedFiles []string, resultsToCompare ...*sarif.Run) (manager *SastScanManager, err error) {
	manager = &SastScanManager{
		scanner:            scanner,
		signedDescriptions: signedDescriptions,
		sastRules:          sastRules,
		sastChangedFiles:   sastChangedFiles,
		configFileName:     filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName:    filepath.Join(scannerTempDir, "results.sarif"),
	}
	if len(resultsToCompare) == 0 {
		// No scan results to compare
		return
	}
	log.Debug("Diff mode - SAST results to compare provided")
	manager.resultsToCompareFileName = filepath.Join(scannerTempDir, "target.sarif")
	// Save the sast results to compare as a report
	err = jas.SaveScanResultsToCompareAsReport(manager.resultsToCompareFileName, resultsToCompare...)
	return
}

func (ssm *SastScanManager) Run(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = ssm.createConfigFile(module, ssm.signedDescriptions, ssm.sastChangedFiles, ssm.scanner.ScannersExclusions.SastExcludePatterns, ssm.scanner.Exclusions...); err != nil {
		return
	}
	if err = ssm.runAnalyzerManager(filepath.Dir(ssm.scanner.AnalyzerManager.AnalyzerManagerFullPath)); err != nil {
		return
	}
	vulnerabilitiesSarifRuns, violationsSarifRuns, err = jas.ReadJasScanRunsFromFile(ssm.resultsFileName, module.SourceRoot, sastDocsUrlSuffix, ssm.scanner.MinSeverity)
	if err != nil {
		return
	}
	groupResultsByLocation(vulnerabilitiesSarifRuns)
	groupResultsByLocation(violationsSarifRuns)
	return
}

type sastScanConfig struct {
	Scans []scanConfiguration `yaml:"scans,omitempty"`
}

type scanConfiguration struct {
	Roots                  []string       `yaml:"roots,omitempty"`
	Type                   string         `yaml:"type,omitempty"`
	Output                 string         `yaml:"output,omitempty"`
	PathToResultsToCompare string         `yaml:"target-result-file,omitempty"`
	Language               string         `yaml:"language,omitempty"`
	ExcludePatterns        []string       `yaml:"exclude_patterns,omitempty"`
	ExcludedRules          []string       `yaml:"excluded-rules,omitempty"`
	SastParameters         sastParameters `yaml:"sast_parameters,omitempty"`
	UserRules              string         `yaml:"user_rules,omitempty"`
}

type sastParameters struct {
	SignedDescriptions bool `yaml:"signed_descriptions,omitempty"`
}

func (ssm *SastScanManager) createConfigFile(module jfrogappsconfig.Module, signedDescriptions bool, sastChangedFiles []string, centralConfigExclusions []string, exclusions ...string) error {
	sastScanner := module.Scanners.Sast
	if sastScanner == nil {
		sastScanner = &jfrogappsconfig.SastScanner{}
	}
	roots, err := jas.GetSourceRoots(module, &sastScanner.Scanner)
	if err != nil {
		return err
	}
	if len(sastChangedFiles) > 0 {
		log.Debug(fmt.Sprintf("Using SAST Changed Files mode with %d changed files", len(sastChangedFiles)))
		roots = sastChangedFiles
	}
	configFileContent := sastScanConfig{
		Scans: []scanConfiguration{
			{
				Type:                   sastScannerType,
				Roots:                  roots,
				Output:                 ssm.resultsFileName,
				PathToResultsToCompare: ssm.resultsToCompareFileName,
				Language:               sastScanner.Language,
				ExcludedRules:          sastScanner.ExcludedRules,
				SastParameters: sastParameters{
					SignedDescriptions: signedDescriptions,
				},
				ExcludePatterns: jas.GetExcludePatterns(module, &sastScanner.Scanner, centralConfigExclusions, exclusions...),
				UserRules:       ssm.sastRules,
			},
		},
	}
	return jas.CreateScannersConfigFile(ssm.configFileName, configFileContent, jasutils.Sast)
}

func (ssm *SastScanManager) runAnalyzerManager(wd string) error {
	return ssm.scanner.AnalyzerManager.ExecWithOutputFile(ssm.configFileName, sastScanCommand, wd, ssm.resultsFileName, ssm.scanner.ServerDetails, ssm.scanner.EnvVars)
}

// In the Sast scanner, there can be multiple results with the same location.
// The only difference is that their CodeFlow values are different.
// We combine those under the same result location value
func groupResultsByLocation(sarifRuns []*sarif.Run) {
	for _, sastRun := range sarifRuns {
		locationToResult := map[string]*sarif.Result{}
		for _, sastResult := range sastRun.Results {
			resultID := getResultId(sastResult)
			if result, exists := locationToResult[resultID]; exists {
				result.CodeFlows = append(result.CodeFlows, sastResult.CodeFlows...)
			} else {
				locationToResult[resultID] = sastResult
			}
		}
		sastRun.Results = maps.Values(locationToResult)
	}
}

func getResultLocationStr(result *sarif.Result) string {
	if len(result.Locations) == 0 {
		return ""
	}
	location := result.Locations[0]
	return fmt.Sprintf("%s%d%d%d%d",
		sarifutils.GetLocationFileName(location),
		sarifutils.GetLocationStartLine(location),
		sarifutils.GetLocationStartColumn(location),
		sarifutils.GetLocationEndLine(location),
		sarifutils.GetLocationEndColumn(location))
}

func getResultId(result *sarif.Result) string {
	return sarifutils.GetResultRuleId(result) + result.Level + sarifutils.GetResultMsgText(result) + getResultLocationStr(result)
}
