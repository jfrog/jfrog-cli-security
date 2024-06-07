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
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func RunJasScannersAndSetResults(securityParallelRunner *utils.SecurityParallelRunner, scanResults *utils.Results, technologiesList []techutils.Technology, directDependencies []string,
	serverDetails *config.ServerDetails, workingDirs []string, thirdPartyApplicabilityScan bool, msi string, scanType applicability.ApplicabilityScanType, secretsScanType secrets.SecretsScanType, errHandlerFunc func(error)) (err error) {
	if serverDetails == nil || len(serverDetails.Url) == 0 {
		log.Warn("To include 'Advanced Security' scan as part of the audit output, please run the 'jf c add' command before running this command.")
		return
	}
	// For docker scan we support only secrets and contextual scans.
	runAllScanners := false
	if scanType == applicability.ApplicabilityScannerType || secretsScanType == secrets.SecretsScannerType {
		runAllScanners = true
	}
	scanner, err := jas.NewJasScanner(workingDirs, serverDetails)
	if err != nil {
		return
	}
	// Set environments variables for analytics in analyzers manager.
	callback := jas.SetAnalyticsMetricsDataForAnalyzerManager(msi, technologiesList)
	defer func() {
		securityParallelRunner.ScannersWg.Wait()
		callback()
		cleanup := scanner.ScannerDirCleanupFunc
		err = errors.Join(err, cleanup())
	}()

	// Don't execute other scanners when scanning third party dependencies.
	if !thirdPartyApplicabilityScan {
		for _, module := range scanner.JFrogAppsConfig.Modules {
			if err = addModuleJasScanTask(module, utils.Secrets, securityParallelRunner, runSecretsScan(securityParallelRunner, scanner, scanResults.ExtendedScanResults, module, secretsScanType), errHandlerFunc); err != nil {
				return
			}
			if runAllScanners {
				if err = addModuleJasScanTask(module, utils.IaC, securityParallelRunner, runIacScan(securityParallelRunner, scanner, scanResults.ExtendedScanResults, module), errHandlerFunc); err != nil {
					return
				}
				if err = addModuleJasScanTask(module, utils.Sast, securityParallelRunner, runSastScan(securityParallelRunner, scanner, scanResults.ExtendedScanResults, module), errHandlerFunc); err != nil {
					return
				}
			}
		}
	}

	// Wait for sca scan to complete
	securityParallelRunner.ScaScansWg.Wait()
	for _, module := range scanner.JFrogAppsConfig.Modules {
		if err = addModuleJasScanTask(module, utils.Applicability, securityParallelRunner, runContextualScan(securityParallelRunner, scanner, scanResults, module, directDependencies, thirdPartyApplicabilityScan, scanType), errHandlerFunc); err != nil {
			return
		}
	}
	return err
}

func addModuleJasScanTask(module jfrogappsconfig.Module, scanType utils.JasScanType, securityParallelRunner *utils.SecurityParallelRunner, task parallel.TaskFunc, errHandlerFunc func(error)) (err error) {
	if jas.ShouldSkipScanner(module, scanType) {
		return
	}
	securityParallelRunner.ScannersWg.Add(1)
	if _, err = securityParallelRunner.Runner.AddTaskWithError(task, errHandlerFunc); err != nil {
		err = fmt.Errorf("failed to create %s scan task: %s", scanType, err.Error())
	}
	return
}

func runSecretsScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *utils.ExtendedScanResults,
	module jfrogappsconfig.Module, secretsScanType secrets.SecretsScanType) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.ScannersWg.Done()
		}()
		results, err := secrets.RunSecretsScan(scanner, secretsScanType, module, threadId)
		if err != nil {
			return fmt.Errorf("error from thread_id %d: %s", threadId, err.Error())
		}
		securityParallelRunner.ResultsMu.Lock()
		extendedScanResults.SecretsScanResults = append(extendedScanResults.SecretsScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}

func runIacScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *utils.ExtendedScanResults,
	module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.ScannersWg.Done()
		}()
		results, err := iac.RunIacScan(scanner, module, threadId)
		if err != nil {
			return fmt.Errorf("error from thread_id %d: %s", threadId, err.Error())
		}
		securityParallelRunner.ResultsMu.Lock()
		extendedScanResults.IacScanResults = append(extendedScanResults.IacScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}

func runSastScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *utils.ExtendedScanResults,
	module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.ScannersWg.Done()
		}()
		results, err := sast.RunSastScan(scanner, module, threadId)
		if err != nil {
			return fmt.Errorf("error from thread_id %d: %s", threadId, err.Error())
		}
		securityParallelRunner.ResultsMu.Lock()
		extendedScanResults.SastScanResults = append(extendedScanResults.SastScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}

func runContextualScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, scanResults *utils.Results,
	module jfrogappsconfig.Module, directDependencies []string, thirdPartyApplicabilityScan bool, scanType applicability.ApplicabilityScanType) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.ScannersWg.Done()
		}()
		results, err := applicability.RunApplicabilityScan(scanResults.GetScaScansXrayResults(), directDependencies, scanner, thirdPartyApplicabilityScan, scanType, module, threadId)
		if err != nil {
			return fmt.Errorf("error from thread_id %d: %s", threadId, err.Error())
		}
		securityParallelRunner.ResultsMu.Lock()
		scanResults.ExtendedScanResults.ApplicabilityScanResults = append(scanResults.ExtendedScanResults.ApplicabilityScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}
