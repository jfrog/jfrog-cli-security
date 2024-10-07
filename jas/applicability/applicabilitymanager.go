package applicability

import (
	"path/filepath"

	"github.com/jfrog/gofrog/datastructures"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

const (
	applicabilityScanCommand   = "ca"
	applicabilityDocsUrlSuffix = "contextual-analysis"

	ApplicabilityScannerType        ApplicabilityScanType = "analyze-applicability"
	ApplicabilityDockerScanScanType ApplicabilityScanType = "analyze-applicability-docker-scan"
)

type ApplicabilityScanType string

type ApplicabilityScanManager struct {
	applicabilityScanResults []*sarif.Run
	directDependenciesCves   []string
	indirectDependenciesCves []string
	xrayResults              []services.ScanResponse
	scanner                  *jas.JasScanner
	thirdPartyScan           bool
	commandType              string
	configFileName           string
	resultsFileName          string
}

// The getApplicabilityScanResults function runs the applicability scan flow, which includes the following steps:
// Creating an ApplicabilityScanManager object.
// Checking if the scanned project is eligible for applicability scan.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
// Return values:
// map[string]string: A map containing the applicability result of each XRAY CVE.
// bool: true if the user is entitled to the applicability scan, false otherwise.
// error: An error object (if any).
func RunApplicabilityScan(xrayResults []services.ScanResponse, directDependencies []string,
	scanner *jas.JasScanner, thirdPartyContextualAnalysis bool, scanType ApplicabilityScanType, module jfrogappsconfig.Module, threadId int) (results []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Applicability.String()); err != nil {
		return
	}
	applicabilityScanManager := newApplicabilityScanManager(xrayResults, directDependencies, scanner, thirdPartyContextualAnalysis, scanType, scannerTempDir)
	if !applicabilityScanManager.cvesExists() {
		log.Debug(clientutils.GetLogMsgPrefix(threadId, false), "We couldn't find any vulnerable dependencies. Skipping....")
		return
	}
	log.Info(clientutils.GetLogMsgPrefix(threadId, false) + "Running applicability scan...")
	if err = applicabilityScanManager.scanner.Run(applicabilityScanManager, module); err != nil {
		err = jas.ParseAnalyzerManagerError(jasutils.Applicability, err)
		return
	}
	results = applicabilityScanManager.applicabilityScanResults
	if len(results) > 0 {
		log.Info(clientutils.GetLogMsgPrefix(threadId, false)+"Found", sarifutils.GetRulesPropertyCount("applicability", "applicable", results...), "applicable cves")
	}
	return
}

func newApplicabilityScanManager(xrayScanResults []services.ScanResponse, directDependencies []string, scanner *jas.JasScanner, thirdPartyScan bool, scanType ApplicabilityScanType, scannerTempDir string) (manager *ApplicabilityScanManager) {
	directDependenciesCves, indirectDependenciesCves := extractDependenciesCvesFromScan(xrayScanResults, directDependencies)
	return &ApplicabilityScanManager{
		applicabilityScanResults: []*sarif.Run{},
		directDependenciesCves:   directDependenciesCves,
		indirectDependenciesCves: indirectDependenciesCves,
		xrayResults:              xrayScanResults,
		scanner:                  scanner,
		thirdPartyScan:           thirdPartyScan,
		commandType:              string(scanType),
		configFileName:           filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName:          filepath.Join(scannerTempDir, "results.sarif"),
	}
}

func addCvesToSet(cves []services.Cve, set *datastructures.Set[string]) {
	for _, cve := range cves {
		if cve.Id != "" {
			set.Add(cve.Id)
		}
	}
}

// This function gets a list of xray scan responses that contain direct and indirect vulnerabilities and returns separate
// lists of the direct and indirect CVEs
func extractDependenciesCvesFromScan(xrayScanResults []services.ScanResponse, directDependencies []string) (directCves []string, indirectCves []string) {
	directCvesSet := datastructures.MakeSet[string]()
	indirectCvesSet := datastructures.MakeSet[string]()
	for _, scanResult := range xrayScanResults {
		for _, vulnerability := range scanResult.Vulnerabilities {
			if isDirectComponents(maps.Keys(vulnerability.Components), directDependencies) {
				addCvesToSet(vulnerability.Cves, directCvesSet)
			} else {
				addCvesToSet(vulnerability.Cves, indirectCvesSet)
			}
		}
		for _, violation := range scanResult.Violations {
			if isDirectComponents(maps.Keys(violation.Components), directDependencies) {
				addCvesToSet(violation.Cves, directCvesSet)
			} else {
				addCvesToSet(violation.Cves, indirectCvesSet)
			}
		}
	}

	return directCvesSet.ToSlice(), indirectCvesSet.ToSlice()
}

func isDirectComponents(components []string, directDependencies []string) bool {
	for _, component := range components {
		if slices.Contains(directDependencies, component) {
			return true
		}
	}
	return false
}

func (asm *ApplicabilityScanManager) Run(module jfrogappsconfig.Module) (err error) {
	if err = asm.createConfigFile(module, asm.scanner.Exclusions...); err != nil {
		return
	}
	if err = asm.runAnalyzerManager(); err != nil {
		return
	}
	workingDirResults, err := jas.ReadJasScanRunsFromFile(asm.resultsFileName, module.SourceRoot, applicabilityDocsUrlSuffix, asm.scanner.MinSeverity)
	if err != nil {
		return
	}
	asm.applicabilityScanResults = append(asm.applicabilityScanResults, workingDirResults...)
	return
}

func (asm *ApplicabilityScanManager) cvesExists() bool {
	return len(asm.indirectDependenciesCves) > 0 || len(asm.directDependenciesCves) > 0
}

type applicabilityScanConfig struct {
	Scans []scanConfiguration `yaml:"scans"`
}

type scanConfiguration struct {
	Roots                []string `yaml:"roots"`
	Output               string   `yaml:"output"`
	Type                 string   `yaml:"type"`
	GrepDisable          bool     `yaml:"grep-disable"`
	CveWhitelist         []string `yaml:"cve-whitelist"`
	IndirectCveWhitelist []string `yaml:"indirect-cve-whitelist"`
	SkippedDirs          []string `yaml:"skipped-folders"`
	ScanType             string   `yaml:"scantype"`
}

func (asm *ApplicabilityScanManager) createConfigFile(module jfrogappsconfig.Module, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, nil)
	if err != nil {
		return err
	}
	excludePatterns := jas.GetExcludePatterns(module, nil, exclusions...)
	if asm.thirdPartyScan {
		log.Info("Including node modules folder in applicability scan")
		excludePatterns = removeElementFromSlice(excludePatterns, utils.NodeModulesPattern)
	}
	configFileContent := applicabilityScanConfig{
		Scans: []scanConfiguration{
			{
				Roots:                roots,
				Output:               asm.resultsFileName,
				Type:                 asm.commandType,
				GrepDisable:          false,
				CveWhitelist:         asm.directDependenciesCves,
				IndirectCveWhitelist: asm.indirectDependenciesCves,
				SkippedDirs:          excludePatterns,
			},
		},
	}
	return jas.CreateScannersConfigFile(asm.configFileName, configFileContent, jasutils.Applicability)
}

// Runs the analyzerManager app and returns a boolean to indicate whether the user is entitled for
// advance security feature
func (asm *ApplicabilityScanManager) runAnalyzerManager() error {
	return asm.scanner.AnalyzerManager.Exec(asm.configFileName, applicabilityScanCommand, filepath.Dir(asm.scanner.AnalyzerManager.AnalyzerManagerFullPath), asm.scanner.ServerDetails, asm.scanner.EnvVars)
}

func removeElementFromSlice(skipDirs []string, element string) []string {
	deleteIndex := slices.Index(skipDirs, element)
	if deleteIndex == -1 {
		return skipDirs
	}
	return slices.Delete(skipDirs, deleteIndex, deleteIndex+1)
}
