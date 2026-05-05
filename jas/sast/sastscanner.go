package sast

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jfrog/gofrog/datastructures"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"golang.org/x/exp/maps"
)

const (
	sastScannerType   = "sast"
	sastScanCommand   = "zd"
	sastDocsUrlSuffix = "sast-1"
)

type SastScanManager struct {
	scanner *jas.JasScanner

	sastChangedFiles   []string
	signedDescriptions bool
	sastRules          string

	changedFilesMode bool

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

type SastScanParams struct {
	Module             jfrogappsconfig.Module
	SignedDescriptions bool
	SastRules          string
	TargetCount        int
	ThreadId           int
	SastChangedFiles   []string
	ChangedFilesMode   bool
	ResultsToCompare   []*sarif.Run
}

func RunSastScan(params SastScanParams, scanner *jas.JasScanner) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	if params.ChangedFilesMode && len(params.SastChangedFiles) == 0 {
		log.Info(clientutils.GetLogMsgPrefix(params.ThreadId, false) + "SAST changed files mode: no changed files in scope for this target, skipping SAST scan")
		return
	}
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Sast.String(), params.ThreadId); err != nil {
		return
	}
	sastScanManager, err := newSastScanManager(scanner, scannerTempDir, params.SignedDescriptions, params.ChangedFilesMode, params.SastRules, params.SastChangedFiles, params.ResultsToCompare...)
	if err != nil {
		return
	}
	startTime := time.Now()
	log.Info(jas.GetStartJasScanLog(utils.SastScan, params.ThreadId, params.Module, params.TargetCount))
	if vulnerabilitiesResults, violationsResults, err = sastScanManager.scanner.Run(sastScanManager, params.Module); err != nil {
		return
	}
	log.Info(utils.GetScanFindingsLog(utils.SastScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), startTime, params.ThreadId))
	return
}

func newSastScanManager(scanner *jas.JasScanner, scannerTempDir string, signedDescriptions, changedFilesMode bool, sastRules string, sastChangedFiles []string, resultsToCompare ...*sarif.Run) (manager *SastScanManager, err error) {
	manager = &SastScanManager{
		scanner:            scanner,
		signedDescriptions: signedDescriptions,
		sastRules:          sastRules,
		changedFilesMode:   changedFilesMode,
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
	if ssm.changedFilesMode {
		log.Debug(fmt.Sprintf("SAST changed files mode: using %d paths as scan roots", len(sastChangedFiles)))
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

// sastChangedFileDropStats counts reasons entries from git were not used as SAST roots.
type sastChangedFileDropStats struct {
	invalidPath   int
	outsideTarget int
	absError      int
	duplicate     int
}

func (s sastChangedFileDropStats) anyDrops() bool {
	return s.invalidPath+s.outsideTarget+s.absError+s.duplicate > 0
}

// collectSastChangedAbsPaths maps repo-relative (or absolute-under-repo) changed file paths to clean absolute
func collectSastChangedAbsPaths(commonAbs, targetRel string, changedFiles []string) (out []string, stats sastChangedFileDropStats) {
	seen := datastructures.MakeSet[string]()
	for _, cf := range changedFiles {
		if !changedFileBelongsToTarget(targetRel, cf) {
			log.Verbose(fmt.Sprintf("SAST changed files: outside target: %s", cf))
			stats.outsideTarget++
			continue
		}
		absPath, err := filepath.Abs(filepath.Clean(filepath.Join(commonAbs, filepath.FromSlash(cf))))
		if err != nil {
			log.Verbose(fmt.Sprintf("SAST changed files: absolute path error: %s", err.Error()))
			stats.absError++
			continue
		}
		if exists, err := fileutils.IsFileExists(absPath, false); err != nil || !exists {
			log.Verbose(fmt.Sprintf("SAST changed files: file does not exist: %s", absPath))
			stats.invalidPath++
			continue
		}
		if seen.Exists(absPath) {
			log.Verbose(fmt.Sprintf("SAST changed files: duplicate path: %s", absPath))
			stats.duplicate++
			continue
		}
		seen.Add(absPath)
		out = append(out, absPath)
	}
	return out, stats
}

// SastChangedFilesForTarget returns absolute paths of changed files under the root directory that belong to the target path.
func SastChangedFilesForTarget(gitCtx *xscservices.XscGitInfoContext, targetPath, rootDir string) []string {
	if gitCtx == nil {
		return nil
	}
	if len(gitCtx.ChangedFiles) == 0 {
		log.Debug("SAST changed files: git context has no changed files; skipping per-file roots")
		return nil
	}
	if strings.TrimSpace(rootDir) == "" || strings.TrimSpace(targetPath) == "" {
		log.Debug("SAST changed files: empty common parent or target path; skipping per-file roots")
		return nil
	}
	targetRel := filepath.ToSlash(utils.GetRelativePath(targetPath, rootDir))
	inputCount := len(gitCtx.ChangedFiles)
	out, stats := collectSastChangedAbsPaths(rootDir, targetRel, gitCtx.ChangedFiles)
	if stats.anyDrops() {
		log.Debug(fmt.Sprintf("SAST changed files: kept %d of %d changed-file entries (dropped: %d invalid/unsafe path, %d outside target, %d path resolution error, %d duplicate after normalization)",
			len(out), inputCount, stats.invalidPath, stats.outsideTarget, stats.absError, stats.duplicate))
	}
	slices.Sort(out)
	return out
}

func changedFileBelongsToTarget(targetRel, cfSlash string) bool {
	if targetRel == "" {
		return true
	}
	if cfSlash == targetRel {
		return true
	}
	return strings.HasPrefix(cfSlash, targetRel+"/")
}
