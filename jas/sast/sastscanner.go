package sast

import (
	"fmt"
	"path/filepath"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"
)

const (
	sastScannerType   = "sast"
	sastScanCommand   = "zd"
	sastDocsUrlSuffix = "sast"
)

type SastScanManager struct {
	sastScannerResults []*sarif.Run
	scanner            *jas.JasScanner
	signedDescriptions bool
	configFileName     string
	resultsFileName    string
}

func RunSastScan(scanner *jas.JasScanner, module jfrogappsconfig.Module, signedDescriptions bool, threadId int) (results []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Sast.String()); err != nil {
		return
	}
	sastScanManager := newSastScanManager(scanner, scannerTempDir, signedDescriptions)
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + "Running SAST scan...")
	if err = sastScanManager.scanner.Run(sastScanManager, module); err != nil {
		err = jas.ParseAnalyzerManagerError(jasutils.Sast, err)
		return
	}
	results = sastScanManager.sastScannerResults
	if len(results) > 0 {
		log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Found", sarifutils.GetResultsLocationCount(sastScanManager.sastScannerResults...), "SAST vulnerabilities")
	}
	return
}

func newSastScanManager(scanner *jas.JasScanner, scannerTempDir string, signedDescriptions bool) (manager *SastScanManager) {
	return &SastScanManager{
		sastScannerResults: []*sarif.Run{},
		scanner:            scanner,
		signedDescriptions: signedDescriptions,
		configFileName:     filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName:    filepath.Join(scannerTempDir, "results.sarif")}
}

func (ssm *SastScanManager) Run(module jfrogappsconfig.Module) (err error) {
	if err = ssm.createConfigFile(module, ssm.signedDescriptions, ssm.scanner.Exclusions...); err != nil {
		return
	}
	if err = ssm.runAnalyzerManager(filepath.Dir(ssm.scanner.AnalyzerManager.AnalyzerManagerFullPath)); err != nil {
		return
	}
	workingDirRuns, err := jas.ReadJasScanRunsFromFile(ssm.resultsFileName, module.SourceRoot, sastDocsUrlSuffix, ssm.scanner.MinSeverity)
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
	Roots           []string       `yaml:"roots,omitempty"`
	Type            string         `yaml:"type,omitempty"`
	Language        string         `yaml:"language,omitempty"`
	ExcludePatterns []string       `yaml:"exclude_patterns,omitempty"`
	ExcludedRules   []string       `yaml:"excluded-rules,omitempty"`
	SastParameters  sastParameters `yaml:"sast_parameters,omitempty"`
}

type sastParameters struct {
	SignedDescriptions bool `yaml:"signed_descriptions,omitempty"`
}

func (ssm *SastScanManager) createConfigFile(module jfrogappsconfig.Module, signedDescriptions bool, exclusions ...string) error {
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
				Type:          sastScannerType,
				Roots:         roots,
				Language:      sastScanner.Language,
				ExcludedRules: sastScanner.ExcludedRules,
				SastParameters: sastParameters{
					SignedDescriptions: signedDescriptions,
				},
				ExcludePatterns: jas.GetExcludePatterns(module, &sastScanner.Scanner, exclusions...),
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
	return sarifutils.GetResultRuleId(result) + sarifutils.GetResultLevel(result) + sarifutils.GetResultMsgText(result) + getResultLocationStr(result)
}
