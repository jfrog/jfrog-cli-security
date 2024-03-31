package audit

import (
	"errors"
	"github.com/jfrog/gofrog/parallel"
	jfrogappsconfig "github.com/jfrog/jfrog-apps-config/go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/iac"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/sast"
	"github.com/jfrog/jfrog-cli-security/commands/audit/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func RunJasScannersAndSetResults(auditParallelRunner *utils.AuditParallelRunner, scanResults *utils.Results, directDependencies []string,
	serverDetails *config.ServerDetails, workingDirs []string, progress io.ProgressMgr, thirdPartyApplicabilityScan bool, auditParams *AuditParams) (err error) {
	if serverDetails == nil || len(serverDetails.Url) == 0 {
		log.Warn("To include 'Advanced Security' scan as part of the audit output, please run the 'jf c add' command before running this command.")
		return
	}
	scanner, err := jas.NewJasScanner(workingDirs, serverDetails)
	if err != nil {
		return
	}
	defer func() {
		auditParallelRunner.ScannersWg.Wait()
		cleanup := scanner.ScannerDirCleanupFunc
		err = errors.Join(err, cleanup())
	}()

	// Don't execute other scanners when scanning third party dependencies.
	if !thirdPartyApplicabilityScan {
		for _, module := range scanner.JFrogAppsConfig.Modules {
			if !jas.ShouldSkipScanner(module, utils.Secrets) {
				auditParallelRunner.ScannersWg.Add(1)
				_, err = auditParallelRunner.Runner.AddTaskWithError(runSecretsScan(auditParallelRunner, scanner, progress, scanResults, module), auditParallelRunner.AddErrorToChan)
			}
			if !jas.ShouldSkipScanner(module, utils.IaC) {
				auditParallelRunner.ScannersWg.Add(1)
				_, err = auditParallelRunner.Runner.AddTaskWithError(runIacScan(auditParallelRunner, scanner, progress, scanResults, module), auditParallelRunner.AddErrorToChan)
			}
			if !jas.ShouldSkipScanner(module, utils.Sast) {
				auditParallelRunner.ScannersWg.Add(1)
				_, err = auditParallelRunner.Runner.AddTaskWithError(runSastScan(auditParallelRunner, scanner, progress, scanResults, module), auditParallelRunner.AddErrorToChan)
			}
		}
	}

	// Wait for sca scan to complete
	auditParallelRunner.ScaScansWg.Wait()
	for _, module := range scanner.JFrogAppsConfig.Modules {
		if !jas.ShouldSkipScanner(module, utils.Applicability) {
			auditParallelRunner.ScannersWg.Add(1)
			_, err = auditParallelRunner.Runner.AddTaskWithError(runContextualScan(auditParallelRunner, scanner, thirdPartyApplicabilityScan, progress, scanResults, module, auditParams), auditParallelRunner.AddErrorToChan)
		}
	}
	return err
}

func runSecretsScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, progress io.ProgressMgr, scanResults *utils.Results, module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			auditParallelRunner.ScannersWg.Done()
		}()
		if progress != nil {
			progress.SetHeadlineMsg("Running secrets scanning")
		}
		err = secrets.RunSecretsScan(auditParallelRunner, scanner, scanResults.ExtendedScanResults, module, threadId)
		return
	}
}

func runIacScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, progress io.ProgressMgr, scanResults *utils.Results, module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			auditParallelRunner.ScannersWg.Done()
		}()
		if progress != nil {
			progress.SetHeadlineMsg("Running IaC scanning")
		}
		err = iac.RunIacScan(auditParallelRunner, scanner, scanResults.ExtendedScanResults, module, threadId)
		return
	}
}

func runSastScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, progress io.ProgressMgr, scanResults *utils.Results, module jfrogappsconfig.Module) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			auditParallelRunner.ScannersWg.Done()
		}()
		if progress != nil {
			progress.SetHeadlineMsg("Running Sast scanning")
		}
		err = sast.RunSastScan(auditParallelRunner, scanner, scanResults.ExtendedScanResults, module, threadId)
		return
	}
}

func runContextualScan(auditParallelRunner *utils.AuditParallelRunner, scanner *jas.JasScanner, thirdPartyApplicabilityScan bool, progress io.ProgressMgr,
	scanResults *utils.Results, module jfrogappsconfig.Module, auditParams *AuditParams) parallel.TaskFunc {
	return func(threadId int) (err error) {
		defer func() {
			auditParallelRunner.ScannersWg.Done()
		}()
		if progress != nil {
			progress.SetHeadlineMsg("Running applicability scanning")
		}
		err = applicability.RunApplicabilityScan(auditParallelRunner, scanResults.GetScaScansXrayResults(), auditParams.DirectDependencies(), scanResults.GetScaScannedTechnologies(), scanner, thirdPartyApplicabilityScan, scanResults.ExtendedScanResults, module, threadId)
		return
	}
}
