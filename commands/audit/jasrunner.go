package audit

import (
	"errors"
	"fmt"
	"github.com/jfrog/gofrog/parallel"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/iac"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/sast"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func RunJasScannersAndSetResults(auditParallelRunner *utils.AuditParallelRunner, scanResults *utils.Results, serverDetails *config.ServerDetails,
	auditParams *AuditParams, jfrogAppsConfig *jfrogappsconfig.JFrogAppsConfig, msi string) (err error) {
	if serverDetails == nil || len(serverDetails.Url) == 0 {
		log.Warn("To include 'Advanced Security' scan as part of the audit output, please run the 'jf c add' command before running this command.")
		return
	}
	scanner, err := jas.NewJasScanner(serverDetails, jfrogAppsConfig)
	if err != nil {
		return
	}
	// Set environments variables for analytics in analyzers manager.
	callback := jas.SetAnalyticsMetricsDataForAnalyzerManager(msi, scanResults.GetScaScannedTechnologies())
	defer func() {
		auditParallelRunner.ScannersWg.Wait()
		callback()
		cleanup := scanner.ScannerDirCleanupFunc
		err = errors.Join(err, cleanup())
	}()

	// Don't execute other scanners when scanning third party dependencies.
	if !auditParams.thirdPartyApplicabilityScan {
		for _, module := range scanner.JFrogAppsConfig.Modules {
			if err = addModuleJasScanTask(module, utils.Secrets, auditParallelRunner, runSecretsScan(auditParallelRunner, scanner, scanResults, module)); err != nil {
				return
			}
			if err = addModuleJasScanTask(module, utils.IaC, auditParallelRunner, runIacScan(auditParallelRunner, scanner, scanResults, module)); err != nil {
				return
			}
			if err = addModuleJasScanTask(module, utils.Sast, auditParallelRunner, runSastScan(auditParallelRunner, scanner, scanResults, module)); err != nil {
				return
			}
		}
	}

	// Wait for sca scan to complete
	auditParallelRunner.ScaScansWg.Wait()
	for _, module := range scanner.JFrogAppsConfig.Modules {
		if err = addModuleJasScanTask(module, utils.Applicability, auditParallelRunner, runContextualScan(auditParallelRunner, scanner, scanResults, module, auditParams)); err != nil {
			return
		}
	}
	return err
}

func addModuleJasScanTask(module jfrogappsconfig.Module, scanType utils.JasScanType, auditParallelRunner *utils.AuditParallelRunner, task parallel.TaskFunc) (err error) {
	if jas.ShouldSkipScanner(module, scanType) {
		return
	}
	auditParallelRunner.ScannersWg.Add(1)
	if _, err = auditParallelRunner.Runner.AddTaskWithError(task, auditParallelRunner.AddErrorToChan); err != nil {
		err = fmt.Errorf("failed to create %s scan task: %s", scanType, err.Error())
	}
	return
}

func runSecretsScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, scanResults *utils.Results,
	module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			auditParallelRunner.ScannersWg.Done()
		}()
		err = secrets.RunSecretsScan(auditParallelRunner, scanner, scanResults.ExtendedScanResults, module, threadId)
		return
	}
}

func runIacScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, scanResults *utils.Results,
	module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			auditParallelRunner.ScannersWg.Done()
		}()
		err = iac.RunIacScan(auditParallelRunner, scanner, scanResults.ExtendedScanResults, module, threadId)
		return
	}
}

func runSastScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, scanResults *utils.Results,
	module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			auditParallelRunner.ScannersWg.Done()
		}()
		err = sast.RunSastScan(auditParallelRunner, scanner, scanResults.ExtendedScanResults, module, threadId)
		return
	}
}

func runContextualScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, scanResults *utils.Results,
	module jfrogappsconfig.Module, auditParams *AuditParams) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			auditParallelRunner.ScannersWg.Done()
		}()
		err = applicability.RunApplicabilityScan(auditParallelRunner, scanResults.GetScaScansXrayResults(), auditParams.DirectDependencies(), scanner, auditParams.thirdPartyApplicabilityScan, scanResults.ExtendedScanResults, module, threadId)
		return
	}
}
