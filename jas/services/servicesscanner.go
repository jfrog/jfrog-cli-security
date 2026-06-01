package services

import (
	"path/filepath"
	"time"

	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

const (
	servicesScannerType   = "services"
	servicesScanCommand   = "serve"
	servicesDocsUrlSuffix = "services-scans"
)

type ServicesScanManager struct {
	scanner *jas.JasScanner

	resultsToCompareFileName string
	configFileName           string
	resultsFileName          string
}

func RunServicesScan(scanner *jas.JasScanner, module jfrogappsconfig.Module, targetCount, threadId int, resultsToCompare ...*sarif.Run) (vulnerabilitiesResults []*sarif.Run, violationsResults []*sarif.Run, err error) {
	var scannerTempDir string
	if scannerTempDir, err = jas.CreateScannerTempDirectory(scanner, jasutils.Services.String(), threadId); err != nil {
		return
	}
	servicesScanManager, err := newServicesScanManager(scanner, scannerTempDir, resultsToCompare...)
	if err != nil {
		return
	}
	startTime := time.Now()
	log.Info(jas.GetStartJasScanLog(utils.ServicesScan, threadId, module, targetCount))
	if vulnerabilitiesResults, violationsResults, err = servicesScanManager.scanner.Run(servicesScanManager, module); err != nil {
		return
	}
	log.Info(utils.GetScanFindingsLog(utils.ServicesScan, sarifutils.GetResultsLocationCount(vulnerabilitiesResults...), startTime, threadId))
	return
}

func newServicesScanManager(scanner *jas.JasScanner, scannerTempDir string, resultsToCompare ...*sarif.Run) (manager *ServicesScanManager, err error) {
	manager = &ServicesScanManager{
		scanner:         scanner,
		configFileName:  filepath.Join(scannerTempDir, "config.yaml"),
		resultsFileName: filepath.Join(scannerTempDir, "results.sarif"),
	}
	if len(resultsToCompare) == 0 {
		return
	}
	log.Debug("Diff mode - Services results to compare provided")
	manager.resultsToCompareFileName = filepath.Join(scannerTempDir, "target.sarif")
	if err = jas.SaveScanResultsToCompareAsReport(manager.resultsToCompareFileName, resultsToCompare...); err != nil {
		return
	}
	return
}

func (ssm *ServicesScanManager) Run(module jfrogappsconfig.Module) (vulnerabilitiesSarifRuns []*sarif.Run, violationsSarifRuns []*sarif.Run, err error) {
	if err = ssm.createConfigFile(module, ssm.scanner.ScannersExclusions.ServicesExcludePatterns, ssm.scanner.Exclusions...); err != nil {
		return
	}
	if err = ssm.runAnalyzerManager(); err != nil {
		return
	}
	return jas.ReadJasScanRunsFromFile(ssm.resultsFileName, module.SourceRoot, servicesDocsUrlSuffix, ssm.scanner.MinSeverity)
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

func (ssm *ServicesScanManager) createConfigFile(module jfrogappsconfig.Module, centralConfigExclusions []string, exclusions ...string) error {
	roots, err := jas.GetSourceRoots(module, nil)
	if err != nil {
		return err
	}
	configFileContent := servicesScanConfig{
		Scans: []servicesScanConfiguration{
			{
				Roots:                  roots,
				Output:                 ssm.resultsFileName,
				PathToResultsToCompare: ssm.resultsToCompareFileName,
				Type:                   servicesScannerType,
				SkippedDirs:            jas.GetExcludePatterns(module, nil, centralConfigExclusions, exclusions...),
			},
		},
	}
	return jas.CreateScannersConfigFile(ssm.configFileName, configFileContent, jasutils.Services)
}

func (ssm *ServicesScanManager) runAnalyzerManager() error {
	return ssm.scanner.AnalyzerManager.Exec(ssm.configFileName, servicesScanCommand, filepath.Dir(ssm.scanner.AnalyzerManager.AnalyzerManagerFullPath), ssm.scanner.ServerDetails, ssm.scanner.EnvVars)
}
