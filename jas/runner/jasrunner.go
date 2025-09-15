package runner

import (
	"errors"
	"fmt"

	"github.com/jfrog/gofrog/parallel"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/iac"
	"github.com/jfrog/jfrog-cli-security/jas/sast"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"golang.org/x/exp/slices"
)

type JasRunnerParams struct {
	Runner        *utils.SecurityParallelRunner
	ServerDetails *config.ServerDetails
	Scanner       *jas.JasScanner
	// Module flags
	Module        jfrogappsconfig.Module
	ConfigProfile *services.ConfigProfile
	// Scan flags
	AllowPartialResults bool
	ScansToPerform      []utils.SubScanType
	// Diff mode flags
	SourceResultsToCompare *results.TargetResults
	DiffMode               bool
	// Secret scan flags
	SecretsScanType secrets.SecretsScanType
	// Contextual Analysis scan flags
	CvesProvider                CveProvider
	ApplicableScanType          applicability.ApplicabilityScanType
	ThirdPartyApplicabilityScan bool
	// SAST scan flags
	SignedDescriptions bool
	// Outputs
	ScanResults     *results.TargetResults
	TargetOutputDir string
}

// Cves are only available after the SCA scan is performed, so we need a provider to dynamically pass the discovered cves.
type CveProvider func() (directCves []string, indirectCves []string)

func AddJasScannersTasks(params JasRunnerParams) (generalError error) {
	// For docker scan we support only secrets and contextual scans.
	runAllScanners := false
	if params.ApplicableScanType == applicability.ApplicabilityScannerType || params.SecretsScanType == secrets.SecretsScannerType {
		runAllScanners = true
	}
	if generalError = addJasScanTaskForModuleIfNeeded(params, utils.ContextualAnalysisScan, runContextualScan(&params)); generalError != nil {
		return
	}
	if params.ThirdPartyApplicabilityScan {
		// Don't execute other scanners when scanning third party dependencies.
		return
	}
	if generalError = addJasScanTaskForModuleIfNeeded(params, utils.SecretsScan, runSecretsScan(&params)); generalError != nil {
		return
	}
	if !runAllScanners {
		// Binary scan only supports secrets and contextual scans.
		return
	}
	if generalError = addJasScanTaskForModuleIfNeeded(params, utils.IacScan, runIacScan(&params)); generalError != nil {
		return
	}
	return addJasScanTaskForModuleIfNeeded(params, utils.SastScan, runSastScan(&params))
}

func addJasScanTaskForModuleIfNeeded(params JasRunnerParams, subScan utils.SubScanType, task parallel.TaskFunc) (generalError error) {
	jasType := jasutils.SubScanTypeToJasScanType(subScan)
	if jasType == "" {
		return fmt.Errorf("failed to determine Jas scan type for %s", subScan)
	}
	if len(params.ScansToPerform) > 0 && !slices.Contains(params.ScansToPerform, subScan) {
		log.Debug(fmt.Sprintf("Skipping %s scan as requested by input...", subScan))
		return
	}
	if params.ConfigProfile != nil {
		// This code section is related to CentralizedConfig integration in CI Next.
		log.Debug(fmt.Sprintf("Using config profile '%s' to determine whether to run %s scan...", params.ConfigProfile.ProfileName, jasType))
		enabled := false
		switch jasType {
		case jasutils.Secrets:
			enabled = params.ConfigProfile.Modules[0].ScanConfig.SecretsScannerConfig.EnableSecretsScan
		case jasutils.Sast:
			enabled = params.ConfigProfile.Modules[0].ScanConfig.SastScannerConfig.EnableSastScan
		case jasutils.IaC:
			enabled = params.ConfigProfile.Modules[0].ScanConfig.IacScannerConfig.EnableIacScan
		case jasutils.Applicability:
			// In Applicability scanner we must check that Sca is also enabled, since we cannot run CA without Sca results
			enabled = params.ConfigProfile.Modules[0].ScanConfig.ContextualAnalysisScannerConfig.EnableCaScan && params.ConfigProfile.Modules[0].ScanConfig.ScaScannerConfig.EnableScaScan
		}
		if !enabled || jas.ShouldSkipScannerByRemoteConfig(params.ScanResults.Target, params.ConfigProfile.Modules[0], jasType) {
			log.Debug(fmt.Sprintf("Skipping %s scan as requested by '%s' config profile...", jasType, params.ConfigProfile.ProfileName))
		}
		return addModuleJasScanTask(jasType, params.Runner, task, params.ScanResults, params.AllowPartialResults)
	}
	if jas.ShouldSkipScanner(params.ScanResults.Target, params.Module, jasType) {
		log.Debug(fmt.Sprintf("Skipping %s scan as requested by local module config...", subScan))
		return
	}
	return addModuleJasScanTask(jasType, params.Runner, task, params.ScanResults, params.AllowPartialResults)
}

func addModuleJasScanTask(scanType jasutils.JasScanType, securityParallelRunner *utils.SecurityParallelRunner, task parallel.TaskFunc, scanResults *results.TargetResults, allowSkippingErrors bool) (generalError error) {
	securityParallelRunner.JasScannersWg.Add(1)
	if _, addTaskErr := securityParallelRunner.Runner.AddTaskWithError(task, func(err error) {
		_ = scanResults.AddTargetError(fmt.Errorf("failed to run %s scan: %s", scanType, err.Error()), allowSkippingErrors)
	}); addTaskErr != nil {
		generalError = scanResults.AddTargetError(fmt.Errorf("error occurred while adding '%s' scan to parallel runner: %s", scanType, addTaskErr.Error()), allowSkippingErrors)
	}
	return
}

func runSecretsScan(params *JasRunnerParams) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			params.Runner.JasScannersWg.Done()
		}()
		vulnerabilitiesResults, violationsResults, err := secrets.RunSecretsScan(params.Scanner, params.SecretsScanType, params.Module, threadId, getSourceRunsToCompare(params, jasutils.Secrets)...)
		params.Runner.ResultsMu.Lock()
		defer params.Runner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		params.ScanResults.JasResults.AddJasScanResults(jasutils.Secrets, vulnerabilitiesResults, violationsResults, jas.GetAnalyzerManagerExitCode(err))
		if err = jas.ParseAnalyzerManagerError(jasutils.Secrets, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(params.TargetOutputDir, jasutils.Secrets, threadId, vulnerabilitiesResults, violationsResults)
	}
}

func runIacScan(params *JasRunnerParams) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			params.Runner.JasScannersWg.Done()
		}()
		vulnerabilitiesResults, violationsResults, err := iac.RunIacScan(params.Scanner, params.Module, threadId, getSourceRunsToCompare(params, jasutils.IaC)...)
		params.Runner.ResultsMu.Lock()
		defer params.Runner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		params.ScanResults.JasResults.AddJasScanResults(jasutils.IaC, vulnerabilitiesResults, violationsResults, jas.GetAnalyzerManagerExitCode(err))
		if err = jas.ParseAnalyzerManagerError(jasutils.IaC, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(params.TargetOutputDir, jasutils.IaC, threadId, vulnerabilitiesResults, violationsResults)
	}
}

func runSastScan(params *JasRunnerParams) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			params.Runner.JasScannersWg.Done()
		}()
		vulnerabilitiesResults, violationsResults, err := sast.RunSastScan(params.Scanner, params.Module, params.SignedDescriptions, threadId, getSourceRunsToCompare(params, jasutils.Sast)...)
		params.Runner.ResultsMu.Lock()
		defer params.Runner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		params.ScanResults.JasResults.AddJasScanResults(jasutils.Sast, vulnerabilitiesResults, violationsResults, jas.GetAnalyzerManagerExitCode(err))
		if err = jas.ParseAnalyzerManagerError(jasutils.Sast, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(params.TargetOutputDir, jasutils.Sast, threadId, vulnerabilitiesResults, violationsResults)
	}
}

func runContextualScan(params *JasRunnerParams) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			params.Runner.JasScannersWg.Done()
		}()
		// Wait for sca scans to complete before running contextual scan
		params.Runner.ScaScansWg.Wait()
		// Get the direct and indirect cves from the sca scan.
		directCves, indirectCves := params.CvesProvider()
		// Run the applicability scan only if we have cves to scan.
		caScanResults, err := applicability.RunApplicabilityScan(
			applicability.ContextualAnalysisScanParams{
				DirectDependenciesCves:       directCves,
				IndirectDependenciesCves:     indirectCves,
				ScanType:                     params.ApplicableScanType,
				ThirdPartyContextualAnalysis: params.ThirdPartyApplicabilityScan,
				ThreadId:                     threadId,
				Module:                       params.Module,
			},
			params.Scanner,
		)
		params.Runner.ResultsMu.Lock()
		defer params.Runner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		params.ScanResults.JasResults.AddApplicabilityScanResults(jas.GetAnalyzerManagerExitCode(err), caScanResults...)
		if err = jas.ParseAnalyzerManagerError(jasutils.Applicability, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(params.TargetOutputDir, jasutils.Applicability, threadId, caScanResults)
	}
}

func getSourceRunsToCompare(params *JasRunnerParams, scanType jasutils.JasScanType) []*sarif.Run {
	if params.SourceResultsToCompare == nil {
		return nil
	}
	return params.SourceResultsToCompare.GetJasScansResults(scanType)
}

// If an output dir was provided through --output-dir flag, we create in the provided path new file containing the scan results
func dumpSarifRunToFileIfNeeded(scanResultsOutputDir string, scanType jasutils.JasScanType, threadId int, scanResults ...[]*sarif.Run) (err error) {
	if scanResultsOutputDir == "" || len(scanResults) == 0 {
		return
	}
	var fileContent []byte
	for _, resultsToDump := range scanResults {
		if len(resultsToDump) == 0 {
			continue
		}
		if fileContent, err = utils.GetAsJsonBytes(resultsToDump, true, true); err != nil {
			err = errors.Join(err, fmt.Errorf("failed to write %s scan results to file", scanType))
		} else {
			err = errors.Join(err, utils.DumpSarifContentToFile(fileContent, scanResultsOutputDir, scanType.String(), threadId))
		}
	}
	return
}
