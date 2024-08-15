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
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"golang.org/x/exp/slices"
)

func AddJasScannersTasks(securityParallelRunner *utils.SecurityParallelRunner, scanResults *utils.Results, directDependencies *[]string,
	serverDetails *config.ServerDetails, thirdPartyApplicabilityScan bool, scanner *jas.JasScanner, scanType applicability.ApplicabilityScanType,
	secretsScanType secrets.SecretsScanType, errHandlerFunc func(error), scansToPreform []utils.SubScanType, configProfile *services.ConfigProfile) (err error) {
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
	// Don't execute other scanners when scanning third party dependencies.
	// Currently, if config profile exists, the only possible scanners to run are: Secrets, Sast
	if !thirdPartyApplicabilityScan {
		for _, module := range scanner.JFrogAppsConfig.Modules {
			if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.SecretsScan) {
				log.Debug("Skipping secrets scan as requested by input...")
			} else if configProfile != nil {
				// This code section is related to CentralizedConfig integration in CI Next.
				log.Debug(fmt.Sprintf("Using config profile '%s' to determine whether to run secrets scan...", configProfile.ProfileName))
				if configProfile.Modules[0].ScanConfig.SecretsScannerConfig.EnableSecretsScan {
					err = addModuleJasScanTask(jfrogappsconfig.Module{}, jasutils.Secrets, securityParallelRunner, runSecretsScan(securityParallelRunner, scanner, scanResults.ExtendedScanResults, module, secretsScanType), errHandlerFunc)
				} else {
					log.Debug(fmt.Sprintf("Skipping secrets scan as requested by '%s' config profile...", configProfile.ProfileName))
				}
			} else if err = addModuleJasScanTask(module, jasutils.Secrets, securityParallelRunner, runSecretsScan(securityParallelRunner, scanner, scanResults.ExtendedScanResults, module, secretsScanType), errHandlerFunc); err != nil {
				return
			}
			if runAllScanners {
				if configProfile == nil {
					if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.IacScan) {
						log.Debug("Skipping Iac scan as requested by input...")
					} else if err = addModuleJasScanTask(module, jasutils.IaC, securityParallelRunner, runIacScan(securityParallelRunner, scanner, scanResults.ExtendedScanResults, module), errHandlerFunc); err != nil {
						return
					}
				}
				if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.SastScan) {
					log.Debug("Skipping Sast scan as requested by input...")
				} else if configProfile != nil {
					log.Debug(fmt.Sprintf("Using config profile '%s' to determine whether to run Sast scan...", configProfile.ProfileName))
					if configProfile.Modules[0].ScanConfig.SastScannerConfig.EnableSastScan {
						err = addModuleJasScanTask(jfrogappsconfig.Module{}, jasutils.Sast, securityParallelRunner, runSastScan(securityParallelRunner, scanner, scanResults.ExtendedScanResults, module), errHandlerFunc)
					} else {
						log.Debug(fmt.Sprintf("Skipping Sast scan as requested by '%s' config profile...", configProfile.ProfileName))
					}
				} else if err = addModuleJasScanTask(module, jasutils.Sast, securityParallelRunner, runSastScan(securityParallelRunner, scanner, scanResults.ExtendedScanResults, module), errHandlerFunc); err != nil {
					return
				}
			}
		}
	}
	if configProfile == nil {
		if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.ContextualAnalysisScan) {
			log.Debug("Skipping contextual analysis scan as requested by input...")
			return err
		}
		for _, module := range scanner.JFrogAppsConfig.Modules {
			if err = addModuleJasScanTask(module, jasutils.Applicability, securityParallelRunner, runContextualScan(securityParallelRunner, scanner, scanResults, module, directDependencies, thirdPartyApplicabilityScan, scanType), errHandlerFunc); err != nil {
				return
			}
		}
	}
	return err
}

func addModuleJasScanTask(module jfrogappsconfig.Module, scanType jasutils.JasScanType, securityParallelRunner *utils.SecurityParallelRunner, task parallel.TaskFunc, errHandlerFunc func(error)) (err error) {
	if jas.ShouldSkipScanner(module, scanType) {
		return
	}
	securityParallelRunner.JasScannersWg.Add(1)
	if _, err = securityParallelRunner.Runner.AddTaskWithError(task, errHandlerFunc); err != nil {
		err = fmt.Errorf("failed to create %s scan task: %s", scanType, err.Error())
	}
	return
}

func runSecretsScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *utils.ExtendedScanResults,
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

func runIacScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *utils.ExtendedScanResults,
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

func runSastScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, extendedScanResults *utils.ExtendedScanResults,
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

func runContextualScan(securityParallelRunner *utils.SecurityParallelRunner, scanner *jas.JasScanner, scanResults *utils.Results,
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
		scanResults.ExtendedScanResults.ApplicabilityScanResults = append(scanResults.ExtendedScanResults.ApplicabilityScanResults, results...)
		securityParallelRunner.ResultsMu.Unlock()
		return
	}
}
