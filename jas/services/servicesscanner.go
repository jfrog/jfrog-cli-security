package services

import (
	"path/filepath"
	"time"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	servicesScannerType   = "services-scan"
	servicesScanCommand   = "svc"
	servicesDocsUrlSuffix = "misconfigurations-scans-1#services-scans---services-configuration-security"
)

type ServicesScanManager struct {
	scanner *jas.JasScanner

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

type ServicesScanParams struct {
	ThreadId         int
	TargetCount      int
	ResultsToCompare []*sarif.Run
	Target           results.ScanTarget
}

// The RunServicesScan function runs the services scan flow, which includes the following steps:
// Creating a ServicesScanManager object.
// Running the analyzer manager executable.
// Parsing the analyzer manager results.
func RunServicesScan(scanner *jas.JasScanner, params ServicesScanParams) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Services.String(), params.ThreadId); err != nil {
		return
	}
	servicesScanManager, err := newServicesScanManager(scanner, scannerTempDir, params.ResultsToCompare...)
	if err != nil {
		return
	}
	startTime := time.Now()
	log.Info(jas.GetStartJasScanLog(utils.ServicesScan, params.ThreadId, params.Target.DeprecatedAppsConfigModule, params.TargetCount))
	if vulnerabilitiesResults, violationsResults, err = servicesScanManager.runServicesScan(params); err != nil {
		return
	}
	log.Info(utils.GetScanFindingsLog(utils.ServicesScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), startTime, params.ThreadId))
	return
}

func (servicesScanManager *ServicesScanManager) runServicesScan(params ServicesScanParams) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	if params.Target.DeprecatedAppsConfigModule == nil {
		return servicesScanManager.scanner.Run(servicesScanManager, params.Target)
	}
	return servicesScanManager.scanner.DeprecatedRun(servicesScanManager, *params.Target.DeprecatedAppsConfigModule, params.Target.GetCentralConfigExclusions(utils.ServicesScan))
}

func newServicesScanManager(scanner *jas.JasScanner, scannerTempDir string, resultsToCompare ...*sarif.Run) (manager *ServicesScanManager, err error) {
	manager = &ServicesScanManager{
		scanner:         scanner,
		configFileName:  filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName: filepath.Join(scannerTempDir, "results.sarif"),
	}
	if len(resultsToCompare) == 0 {
		// No scan results to compare
		return
	}
	log.Debug("Diff mode - Services results to compare provided")
	manager.resultsToCompareFileName = filepath.Join(scannerTempDir, "target.sarif")
	// Save the iac results to compare as a report
	if err = jas.SaveScanResultsToCompareAsReport(manager.resultsToCompareFileName, resultsToCompare...); err != nil {
		return
	}
	return
}

func (servicesScanManager *ServicesScanManager) DeprecatedRun(module jfrogappsconfig.Module, centralConfigExclusions []string) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = servicesScanManager.deprecatedCreateConfigFile(module, centralConfigExclusions, servicesScanManager.scanner.Exclusions...); err != nil {
		return
	}
	if err = servicesScanManager.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(servicesScanManager.resultsFileName, servicesDocsUrlSuffix, servicesScanManager.scanner.MinSeverity, module.SourceRoot)
}

func (servicesScanManager *ServicesScanManager) Run(target results.ScanTarget) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = servicesScanManager.createConfigFileForTarget(target); err != nil {
		return
	}
	if err = servicesScanManager.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(servicesScanManager.resultsFileName, servicesDocsUrlSuffix, servicesScanManager.scanner.MinSeverity, target.Target, target.Include...)
}

type servicesScanConfig struct {
	Scans []servicesScanConfiguration `yaml:"scans"`
}

type servicesScanConfiguration struct {
	Roots                  []string `yaml:"roots"`
	Output                 string   `yaml:"output"`
	PathToResultsToCompare string   `yaml:"target-result-file,omitempty"`
	Type                   string   `yaml:"type"`
	SkippedDirs            []string `yaml:"skipped-folders"`
}

func (servicesScanManager *ServicesScanManager) deprecatedCreateConfigFile(module jfrogappsconfig.Module, centralConfigExclusions []string, exclusions ...string) error {
	// We are not planning on adding support in jfrogappsconfig for services scans since it is deprecated
	roots, err := jas.GetSourceRoots(module, nil)
	if err != nil {
		return err
	}
	configFileContent := servicesScanConfig{
		Scans: []servicesScanConfiguration{
			{
				Roots:                  roots,
				Output:                 servicesScanManager.resultsFileName,
				PathToResultsToCompare: servicesScanManager.resultsToCompareFileName,
				Type:                   servicesScannerType,
				SkippedDirs:            jas.GetJasExcludePatterns(module, module.Scanners.Iac, centralConfigExclusions, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(servicesScanManager.configFileName, configFileContent, jasutils.Services)
}

func (servicesScanManager *ServicesScanManager) createConfigFileForTarget(target results.ScanTarget) error {
	configFileContent := servicesScanConfig{
		Scans: []servicesScanConfiguration{
			{
				Roots:                  jas.GetRootsFromTarget(target),
				Output:                 servicesScanManager.resultsFileName,
				PathToResultsToCompare: servicesScanManager.resultsToCompareFileName,
				Type:                   servicesScannerType,
				SkippedDirs:            jas.GetJasExcludePatternsForTarget(target, target.GetCentralConfigExclusions(utils.IacScan)),
			},
		},
	}
	return jas.CreateScannersConfigFile(servicesScanManager.configFileName, configFileContent, jasutils.Services)
}

func (servicesScanManager *ServicesScanManager) runAnalyzerManager() error {
	return servicesScanManager.scanner.AnalyzerManager.Exec(servicesScanManager.configFileName, servicesScanCommand, filepath.Dir(servicesScanManager.scanner.AnalyzerManager.AnalyzerManagerFullPath), servicesScanManager.scanner.ServerDetails, servicesScanManager.scanner.EnvVars)
}
