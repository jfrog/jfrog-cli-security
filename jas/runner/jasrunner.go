package runner

import (
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
	"golang.org/x/exp/slices"
)

func AddJasScannersTasks(securityParallelRunner *utils.SecurityParallelRunner, module jfrogappsconfig.Module, scanResults *results.TargetResults, directDependencies *[]string,
	serverDetails *config.ServerDetails, thirdPartyApplicabilityScan bool, scanner *jas.JasScanner, scanType applicability.ApplicabilityScanType, secretsScanType secrets.SecretsScanType, scansToPreform []utils.SubScanType) (err error) {
	if serverDetails == nil || len(serverDetails.Url) == 0 {
		log.Warn("To include 'Advanced Security' scan as part of the audit output, please run the 'jf c add' command before running this command.")
		return
	}
	// For docker scan we support only secrets and contextual scans.
	runAllScanners := false
	if scanType == applicability.ApplicabilityScannerType || secretsScanType == secrets.SecretsScannerType {
		runAllScanners = true
	}
	// Set environments variables for analytics in analyzers manager.
	if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.ContextualAnalysisScan) {
		log.Debug("Skipping contextual analysis scan as requested by input...")
		return err
	}
	if err = addModuleJasScanTask(module, jasutils.Applicability, securityParallelRunner, runContextualScan(securityParallelRunner, scanner, scanResults, module, directDependencies, thirdPartyApplicabilityScan, scanType), scanResults); err != nil {
		return
	}
	// Don't execute other scanners when scanning third party dependencies.
	if thirdPartyApplicabilityScan {
		return
	}
	if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.SecretsScan) {
		log.Debug("Skipping secrets scan as requested by input...")
	} else if err = addModuleJasScanTask(module, jasutils.Secrets, securityParallelRunner, runSecretsScan(securityParallelRunner, scanner, scanResults.JasResults, module, secretsScanType), scanResults); err != nil {
		return
	}
	if runAllScanners {
		if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.IacScan) {
			log.Debug("Skipping Iac scan as requested by input...")
		} else if err = addModuleJasScanTask(module, jasutils.IaC, securityParallelRunner, runIacScan(securityParallelRunner, scanner, scanResults.JasResults, module), scanResults); err != nil {
			return
		}
		if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.SastScan) {
			log.Debug("Skipping Sast scan as requested by input...")
		} else if err = addModuleJasScanTask(module, jasutils.Sast, securityParallelRunner, runSastScan(securityParallelRunner, scanner, scanResults.JasResults, module), scanResults); err != nil {
			return
		}
	}
	return err
}

func addModuleJasScanTask(module jfrogappsconfig.Module, scanType jasutils.JasScanType, securityParallelRunner *utils.SecurityParallelRunner, task parallel.TaskFunc, scanResults *results.TargetResults) (err error) {
	if jas.ShouldSkipScanner(module, scanType) {
		return
	}
	securityParallelRunner.JasScannersWg.Add(1)
	if _, err = securityParallelRunner.Runner.AddTaskWithError(task, func(err error) {
		scanResults.AddError(err)
	}); err != nil {
		err = fmt.Errorf("failed to create %s scan task: %s", scanType, err.Error())
	}
	return
}

func runSecretsScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *results.JasScansResults,
	module jfrogappsconfig.Module, secretsScanType secrets.SecretsScanType) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		results, err := secrets.RunSecretsScan(scanner, secretsScanType, module, threadId)
		if err != nil {
			return fmt.Errorf("%s%s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		securityParallelRunner.ResultsMu.Lock()
		extendedScanResults.SecretsScanResults = append(extendedScanResults.SecretsScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}

func runIacScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *results.JasScansResults,
	module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		results, err := iac.RunIacScan(scanner, module, threadId)
		if err != nil {
			return fmt.Errorf("%s %s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		securityParallelRunner.ResultsMu.Lock()
		extendedScanResults.IacScanResults = append(extendedScanResults.IacScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}

func runSastScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *results.JasScansResults,
	module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		results, err := sast.RunSastScan(scanner, module, threadId)
		if err != nil {
			return fmt.Errorf("%s %s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		securityParallelRunner.ResultsMu.Lock()
		extendedScanResults.SastScanResults = append(extendedScanResults.SastScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}

func runContextualScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, scanResults *results.TargetResults,
	module jfrogappsconfig.Module, directDependencies *[]string, thirdPartyApplicabilityScan bool, scanType applicability.ApplicabilityScanType) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			securityParallelRunner.JasScannersWg.Done()
		}()
		// Wait for sca scans to complete before running contextual scan
		securityParallelRunner.ScaScansWg.Wait()
		results, err := applicability.RunApplicabilityScan(scanResults.GetScaScansXrayResults(), *directDependencies, scanner, thirdPartyApplicabilityScan, scanType, module, threadId)
		if err != nil {
			return fmt.Errorf("%s %s", clientutils.GetLogMsgPrefix(threadId, false), err.Error())
		}
		securityParallelRunner.ResultsMu.Lock()
		scanResults.JasResults.ApplicabilityScanResults = append(scanResults.JasResults.ApplicabilityScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}
