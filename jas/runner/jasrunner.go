package runner

import (
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-security/jas/maliciouscode"

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
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/slices"
)

type JasRunnerParams struct {
	Runner        *utils.SecurityParallelRunner
	ServerDetails *config.ServerDetails
	Scanner       *jas.JasScanner

	Module              jfrogappsconfig.Module
	ConfigProfile       *services.ConfigProfile
	AllowPartialResults bool

	ScansToPerform []utils.SubScanType

	// Malicious code scan flags
	MaliciousScanType maliciouscode.MaliciousScanType
	// Secret scan flags
	SecretsScanType secrets.SecretsScanType
	// Contextual Analysis scan flags
	ApplicableScanType          applicability.ApplicabilityScanType
	DirectDependencies          *[]string
	ThirdPartyApplicabilityScan bool
	// SAST scan flags
	SignedDescriptions bool

	ScanResults     *results.TargetResults
	TargetOutputDir string
}

func AddJasScannersTasks(params JasRunnerParams) (generalError error) {
	// Set the analyzer manager executable path.
	if params.Scanner.AnalyzerManager.AnalyzerManagerFullPath, generalError = jas.GetAnalyzerManagerExecutable(); generalError != nil {
		return fmt.Errorf("failed to set analyzer manager executable path: %s", generalError.Error())
	}
	// For docker scan we support only secrets, malicious code, and contextual scans.
	runAllScanners := false
	if params.ApplicableScanType == applicability.ApplicabilityScannerType || params.SecretsScanType == secrets.SecretsScannerType {
		runAllScanners = true
	}
	if generalError = addJasScanTaskForModuleIfNeeded(params, utils.ContextualAnalysisScan, runContextualScan(params.Runner, params.Scanner, params.ScanResults, params.Module, params.DirectDependencies, params.ThirdPartyApplicabilityScan, params.ApplicableScanType, params.TargetOutputDir)); generalError != nil {
		return
	}
	if params.ThirdPartyApplicabilityScan {
		// Don't execute other scanners when scanning third party dependencies.
		return
	}
	if generalError = addJasScanTaskForModuleIfNeeded(params, utils.SecretsScan, runSecretsScan(params.Runner, params.Scanner, params.ScanResults.JasResults, params.Module, params.SecretsScanType, params.TargetOutputDir)); generalError != nil {
		return
	}
	if generalError = addJasScanTaskForModuleIfNeeded(params, utils.MaliciousCodeScan, runMaliciousScan(params.Runner, params.Scanner, params.ScanResults.JasResults, params.Module, params.MaliciousScanType, params.TargetOutputDir)); generalError != nil {
		return
	}
	if !runAllScanners {
		return
	}
	if generalError = addJasScanTaskForModuleIfNeeded(params, utils.IacScan, runIacScan(params.Runner, params.Scanner, params.ScanResults.JasResults, params.Module, params.TargetOutputDir)); generalError != nil {
		return
	}
	return addJasScanTaskForModuleIfNeeded(params, utils.SastScan, runSastScan(params.Runner, params.Scanner, params.ScanResults.JasResults, params.Module, params.TargetOutputDir, params.SignedDescriptions))
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
		if len(params.ConfigProfile.Modules) < 1 {
			// Verify Modules are not nil and contain at least one modules
			return fmt.Errorf("config profile %s has no modules. A config profile must contain at least one modules", params.ConfigProfile.ProfileName)
		}
		// Currently, if config profile exists, the only possible scanners to run are: Secrets, Sast
		enabled := false
		switch jasType {
		case jasutils.Secrets:
			enabled = params.ConfigProfile.Modules[0].ScanConfig.SecretsScannerConfig.EnableSecretsScan
		case jasutils.Sast:
			enabled = params.ConfigProfile.Modules[0].ScanConfig.SastScannerConfig.EnableSastScan
		case jasutils.IaC:
			enabled = params.ConfigProfile.Modules[0].ScanConfig.IacScannerConfig.EnableIacScan
		case jasutils.Applicability:
			enabled = params.ConfigProfile.Modules[0].ScanConfig.EnableContextualAnalysisScan
		case jasutils.MaliciousCode:
			enabled = params.ConfigProfile.Modules[0].ScanConfig.MaliciousScannerConfig.EnableMaliciousScan
		}
		if enabled {
			generalError = addModuleJasScanTask(jasType, params.Runner, task, params.ScanResults, params.AllowPartialResults)
		} else {
			log.Debug(fmt.Sprintf("Skipping %s scan as requested by '%s' config profile...", jasType, params.ConfigProfile.ProfileName))
		}
		return
	}
	if jas.ShouldSkipScanner(params.Module, jasType) {
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

func runSecretsScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *results.JasScansResults,
	module jfrogappsconfig.Module, secretsScanType secrets.SecretsScanType, scansOutputDir string) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		vulnerabilitiesResults, violationsResults, err := secrets.RunSecretsScan(scanner, secretsScanType, module, threadId)
		securityParallelRunner.ResultsMu.Lock()
		defer securityParallelRunner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		extendedScanResults.AddJasScanResults(jasutils.Secrets, vulnerabilitiesResults, violationsResults, jas.GetAnalyzerManagerExitCode(err))
		if err = jas.ParseAnalyzerManagerError(jasutils.Secrets, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(scansOutputDir, jasutils.Secrets, vulnerabilitiesResults, violationsResults)
	}
}

func runMaliciousScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *results.JasScansResults,
	module jfrogappsconfig.Module, maliciousScanType maliciouscode.MaliciousScanType, scansOutputDir string) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		vulnerabilitiesResults, violationsResults, err := maliciouscode.RunMaliciousScan(scanner, maliciousScanType, module, threadId)
		securityParallelRunner.ResultsMu.Lock()
		defer securityParallelRunner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		extendedScanResults.AddJasScanResults(jasutils.MaliciousCode, vulnerabilitiesResults, violationsResults, jas.GetAnalyzerManagerExitCode(err))
		if err = jas.ParseAnalyzerManagerError(jasutils.MaliciousCode, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(scansOutputDir, jasutils.MaliciousCode, vulnerabilitiesResults, violationsResults)
	}
}

func runIacScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *results.JasScansResults,
	module jfrogappsconfig.Module, scansOutputDir string) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		vulnerabilitiesResults, violationsResults, err := iac.RunIacScan(scanner, module, threadId)
		securityParallelRunner.ResultsMu.Lock()
		defer securityParallelRunner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		extendedScanResults.AddJasScanResults(jasutils.IaC, vulnerabilitiesResults, violationsResults, jas.GetAnalyzerManagerExitCode(err))
		if err = jas.ParseAnalyzerManagerError(jasutils.IaC, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(scansOutputDir, jasutils.IaC, vulnerabilitiesResults, violationsResults)
	}
}

func runSastScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *results.JasScansResults,
	module jfrogappsconfig.Module, scansOutputDir string, signedDescriptions bool) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		vulnerabilitiesResults, violationsResults, err := sast.RunSastScan(scanner, module, signedDescriptions, threadId)
		securityParallelRunner.ResultsMu.Lock()
		defer securityParallelRunner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		extendedScanResults.AddJasScanResults(jasutils.Sast, vulnerabilitiesResults, violationsResults, jas.GetAnalyzerManagerExitCode(err))
		if err = jas.ParseAnalyzerManagerError(jasutils.Sast, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(scansOutputDir, jasutils.Sast, vulnerabilitiesResults, violationsResults)
	}
}

func runContextualScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, scanResults *results.TargetResults,
	module jfrogappsconfig.Module, directDependencies *[]string, thirdPartyApplicabilityScan bool, scanType applicability.ApplicabilityScanType, scansOutputDir string) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		// Wait for sca scans to complete before running contextual scan
		securityParallelRunner.ScaScansWg.Wait()
		caScanResults, err := applicability.RunApplicabilityScan(scanResults.GetScaScansXrayResults(), *directDependencies, scanner, thirdPartyApplicabilityScan, scanType, module, threadId)
		securityParallelRunner.ResultsMu.Lock()
		defer securityParallelRunner.ResultsMu.Unlock()
		// We first add the scan results and only then check for errors, so we can store the exit code in order to report it in the end
		scanResults.JasResults.AddApplicabilityScanResults(jas.GetAnalyzerManagerExitCode(err), caScanResults...)
		if err = jas.ParseAnalyzerManagerError(jasutils.Applicability, err); err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		return dumpSarifRunToFileIfNeeded(scansOutputDir, jasutils.Applicability, caScanResults)
	}
}

// If an output dir was provided through --output-dir flag, we create in the provided path new file containing the scan results
func dumpSarifRunToFileIfNeeded(scanResultsOutputDir string, scanType jasutils.JasScanType, scanResults ...[]*sarif.Run) (err error) {
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
			err = errors.Join(err, utils.DumpContentToFile(fileContent, scanResultsOutputDir, scanType.String()))
		}
	}
	return
}
