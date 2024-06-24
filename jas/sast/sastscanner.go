package sast

import (
	"fmt"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"
	"path/filepath"
)

const (
	sastScannerType   = "sast"
	sastScanCommand   = "zd"
	sastDocsUrlSuffix = "sast"
)

type SastScanManager struct {
	sastScannerResults []*sarif.Run
	scanner            *jas.JasScanner
	configFileName     string
	resultsFileName    string
}

func RunSastScan(scanner *jas.JasScanner, module jfrogappsconfig.Module, threadId int) (results []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, string(utils.Sast)); err != nil {
		return
	}
	sastScanManager := newSastScanManager(scanner, scannerTempDir)
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + "Running SAST scan...")
	if err = sastScanManager.scanner.Run(sastScanManager, module); err != nil {
		err = utils.ParseAnalyzerManagerError(utils.Sast, err)
		return
	}
	results = sastScanManager.sastScannerResults
	if len(results) > 0 {
		log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Found", utils.GetResultsLocationCount(sastScanManager.sastScannerResults...), "SAST vulnerabilities")
	}
	return
}

func newSastScanManager(scanner *jas.JasScanner, scannerTempDir string) (manager *SastScanManager) {
	return &SastScanManager{
		sastScannerResults: []*sarif.Run{},
		scanner:            scanner,
		configFileName:     filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName:    filepath.Join(scannerTempDir, "results.sarif")}
}

func (ssm *SastScanManager) Run(module jfrogappsconfig.Module) (err error) {
	if err = ssm.createConfigFile(module, ssm.scanner.Exclusions...); err != nil {
		return
	}
	if err = ssm.runAnalyzerManager(filepath.Dir(ssm.scanner.AnalyzerManager.AnalyzerManagerFullPath)); err != nil {
		return
	}
	workingDirRuns, err := jas.ReadJasScanRunsFromFile(ssm.resultsFileName, module.SourceRoot, sastDocsUrlSuffix)
	if err != nil {
		return
	}
	groupResultsByLocation(workingDirRuns)
	ssm.sastScannerResults = append(ssm.sastScannerResults, workingDirRuns...)
	return
}

type sastScanConfig struct {
	Scans []scanConfiguration `yaml:"scans,omitempty"`
}

type scanConfiguration struct {
	Roots           []string `yaml:"roots,omitempty"`
	Type            string   `yaml:"type,omitempty"`
	Language        string   `yaml:"language,omitempty"`
	ExcludePatterns []string `yaml:"exclude_patterns,omitempty"`
	ExcludedRules   []string `yaml:"excluded-rules,omitempty"`
}

func (ssm *SastScanManager) createConfigFile(module jfrogappsconfig.Module, exclusions ...string) error {
	sastScanner := module.Scanners.Sast
	if sastScanner == nil {
		sastScanner = &jfrogappsconfig.SastScanner{}
	}
	roots, err := jas.GetSourceRoots(module, &sastScanner.Scanner)
	if err != nil {
		return err
	}
	configFileContent := sastScanConfig{
		Scans: []scanConfiguration{
			{
				Type:            sastScannerType,
				Roots:           roots,
				Language:        sastScanner.Language,
				ExcludedRules:   sastScanner.ExcludedRules,
				ExcludePatterns: jas.GetExcludePatterns(module, &sastScanner.Scanner, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(ssm.configFileName, configFileContent, utils.Sast)
}

func (ssm *SastScanManager) runAnalyzerManager(wd string) error {
	return ssm.scanner.AnalyzerManager.ExecWithOutputFile(ssm.configFileName, sastScanCommand, wd, ssm.resultsFileName, ssm.scanner.ServerDetails)
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
		utils.GetLocationFileName(location),
		utils.GetLocationStartLine(location),
		utils.GetLocationStartColumn(location),
		utils.GetLocationEndLine(location),
		utils.GetLocationEndColumn(location))
}

func getResultRuleId(result *sarif.Result) string {
	if result.RuleID == nil {
		return ""
	}
	return *result.RuleID
}

func getResultId(result *sarif.Result) string {
	return getResultRuleId(result) + utils.GetResultSeverity(result) + utils.GetResultMsgText(result) + getResultLocationStr(result)
}
