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
	"github.com/jfrog/jfrog-client-go/utils/log"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"golang.org/x/exp/maps"
)

const (
	sastScannerType   = "sast"
	sastScanCommand   = "zd"
	sastDocsUrlSuffix = "sast-1"

	// ChangedFilesModeEnvVar enables using GitContext changed files (scoped per target) as SAST scan roots.
	ChangedFilesModeEnvVar = "JAS_SAST_CHANGED_FILES_MODE"
)

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
	// In changed-files mode with nothing in scope, do not fall back to a full module scan. Diff mode (baseline compare) must still run.
	if utils.IsEnvVarTruthy(ChangedFilesModeEnvVar) && len(sastChangedFiles) == 0 && len(resultsToCompare) == 0 {
		log.Info(clientutils.GetLogMsgPrefix(threadId, false) + "SAST changed files mode: no changed files in scope for this target, skipping SAST scan")
		return
	}
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
	if utils.IsEnvVarTruthy(ChangedFilesModeEnvVar) {
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
// paths under commonAbs that belong to targetRel, deduplicating by absolute path.
func collectSastChangedAbsPaths(commonAbs, targetRel string, changedFiles []string) (out []string, stats sastChangedFileDropStats) {
	seen := datastructures.MakeSet[string]()
	for _, cf := range changedFiles {
		cfSlash, ok := normalizeRepoRelativeChangedPath(commonAbs, cf)
		if !ok {
			stats.invalidPath++
			continue
		}
		if !changedFileBelongsToTarget(targetRel, cfSlash) {
			stats.outsideTarget++
			continue
		}
		joined := filepath.Join(commonAbs, filepath.FromSlash(cfSlash))
		absPath, err := filepath.Abs(filepath.Clean(joined))
		if err != nil {
			stats.absError++
			continue
		}
		if seen.Exists(absPath) {
			stats.duplicate++
			continue
		}
		seen.Add(absPath)
		out = append(out, absPath)
	}
	return out, stats
}

// SastChangedFilesForTarget returns absolute paths of git changed files that belong to targetPath
// (relative to commonParent), when ChangedFilesModeEnvVar is truthy (see utils.IsEnvVarTruthy). Returns nil if nothing matches
// or if gitCtx, commonParent, or targetPath are unusable.
func SastChangedFilesForTarget(gitCtx *xscservices.XscGitInfoContext, targetPath, commonParent string) []string {
	if gitCtx == nil {
		return nil
	}
	if !utils.IsEnvVarTruthy(ChangedFilesModeEnvVar) {
		return nil
	}
	if len(gitCtx.ChangedFiles) == 0 {
		log.Debug("SAST changed files: git context has no changed files; skipping per-file roots")
		return nil
	}
	if strings.TrimSpace(commonParent) == "" || strings.TrimSpace(targetPath) == "" {
		log.Debug("SAST changed files: empty common parent or target path; skipping per-file roots")
		return nil
	}
	commonAbs, err := filepath.Abs(filepath.Clean(commonParent))
	if err != nil {
		log.Debug(fmt.Sprintf("SAST changed files: could not resolve common parent: %s", err.Error()))
		return nil
	}
	targetRel := filepath.ToSlash(utils.GetRelativePath(targetPath, commonParent))
	inputCount := len(gitCtx.ChangedFiles)
	out, stats := collectSastChangedAbsPaths(commonAbs, targetRel, gitCtx.ChangedFiles)
	if stats.anyDrops() {
		log.Debug(fmt.Sprintf("SAST changed files: kept %d of %d changed-file entries (dropped: %d invalid/unsafe path, %d outside target, %d path resolution error, %d duplicate after normalization)",
			len(out), inputCount, stats.invalidPath, stats.outsideTarget, stats.absError, stats.duplicate))
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return out
}

func normalizeRepoRelativeChangedPath(commonAbs, cf string) (slashPath string, ok bool) {
	cf = strings.TrimSpace(cf)
	if cf == "" {
		return "", false
	}
	if filepath.IsAbs(cf) {
		cleaned := filepath.Clean(cf)
		r, err := filepath.Rel(commonAbs, cleaned)
		if err != nil {
			return "", false
		}
		r = filepath.ToSlash(filepath.Clean(r))
		if r == ".." || strings.HasPrefix(r, "../") {
			return "", false
		}
		return r, true
	}
	return filepath.ToSlash(filepath.Clean(cf)), true
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
