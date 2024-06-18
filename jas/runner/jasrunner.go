package runner

import (
	"errors"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/jas"
	"github.com/jfrog/jfrog-cli-security/jas/applicability"
	"github.com/jfrog/jfrog-cli-security/jas/iac"
	"github.com/jfrog/jfrog-cli-security/jas/sast"
	"github.com/jfrog/jfrog-cli-security/jas/secrets"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"golang.org/x/exp/slices"
)

func RunJasScannersAndSetResults(extendedScanResults *utils.ExtendedScanResults, technologiesList []techutils.Technology, xrayScanResults []services.ScanResponse, directDependencies []string,
	serverDetails *config.ServerDetails, workingDirs []string, progress io.ProgressMgr, thirdPartyApplicabilityScan bool, msi string, scanType applicability.ApplicabilityScanType, secretsScanType secrets.SecretsScanType, scansToPreform []utils.SubScanType) (err error) {
	if serverDetails == nil || len(serverDetails.Url) == 0 {
		log.Warn("To include 'Advanced Security' scan as part of the audit output, please run the 'jf c add' command before running this command.")
		return
	}
	scanner, err := jas.NewJasScanner(workingDirs, serverDetails)
	if err != nil {
		return
	}
	defer func() {
		cleanup := scanner.ScannerDirCleanupFunc
		err = errors.Join(err, cleanup())
	}()
	if progress != nil {
		progress.SetHeadlineMsg("Running applicability scanning")
	}
	// Set environments variables for analytics in analyzers manager.
	callback := jas.SetAnalyticsMetricsDataForAnalyzerManager(msi, technologiesList)
	defer callback()

	extendedScanResults.ApplicabilityScanResults, err = applicability.RunApplicabilityScan(xrayScanResults, directDependencies, technologiesList, scanner, thirdPartyApplicabilityScan, scanType)
	if err != nil {
		return
	}
	// Don't execute other scanners when scanning third party dependencies.
	if thirdPartyApplicabilityScan {
		return
	}
	if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.SecretsScan) {
		log.Debug("Skipping Secrets scan...")
	} else {
		if progress != nil {
			progress.SetHeadlineMsg("Running secrets scanning")
		}
		extendedScanResults.SecretsScanResults, err = secrets.RunSecretsScan(scanner, secretsScanType)
		if err != nil {
			return
		}
	}

	if scanType == applicability.ApplicabilityScannerType || secretsScanType == secrets.SecretsScannerType {
		if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.IacScan) {
			log.Debug("Skipping Iac scan...")
		} else {
			if progress != nil {
				progress.SetHeadlineMsg("Running IaC scanning")
			}
			extendedScanResults.IacScanResults, err = iac.RunIacScan(scanner)
			if err != nil {
				return
			}
		}
		if len(scansToPreform) > 0 && !slices.Contains(scansToPreform, utils.SastScan) {
			log.Debug("Skipping Sast scan...")
		} else {
			if progress != nil {
				progress.SetHeadlineMsg("Running SAST scanning")
			}
			extendedScanResults.SastScanResults, err = sast.RunSastScan(scanner)
		}
	}
	return
}
